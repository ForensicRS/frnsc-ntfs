//! Directory indexes (`$I30`): `INDX` records of `$INDEX_ALLOCATION`, and `$INDEX_ROOT`.
//!
//! Each index entry's key is a copy of the child's `$FILE_NAME`. When a file is deleted its entry
//! is removed by shifting the following entries down, so its bytes often survive in the node's
//! slack (between the used and allocated length). [`IndexNode::carve_slack`] recovers those
//! entries through the strict [`crate::recovery::admit_file_name`] gate plus a parent check.

use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::recovery::Recovered;

use crate::anomaly::NtfsAnomaly;
use crate::attr::FileName;
use crate::fixup::{apply_fixups, FixupStatus};
use crate::recovery::{admit_file_name, parent_matches, RecoveryStats};
use crate::reference::FileRef;

/// Signature of an index allocation record.
pub const INDX_MAGIC: &[u8; 4] = b"INDX";
/// Entry flag: has a sub-node VCN at its end.
pub const ENTRY_SUBNODE: u32 = 0x1;
/// Entry flag: last entry of the node (no key).
pub const ENTRY_LAST: u32 = 0x2;
/// Smallest `$I30` entry: 16-byte header + 66-byte key with a one-char name, 8-aligned.
const MIN_ENTRY: usize = 0x58;

/// One `$I30` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// File the entry points to.
    pub reference: FileRef,
    pub flags: u32,
    pub key: FileName,
    /// Child node VCN, when the entry has a sub-node.
    pub subnode_vcn: Option<u64>,
    /// Offset of the entry inside its node buffer.
    pub offset: usize,
}

/// A node (an `INDX` record or the `$INDEX_ROOT` node) with its live entries.
#[derive(Debug, Clone)]
pub struct IndexNode {
    /// VCN of the `INDX` record (`None` for `$INDEX_ROOT`).
    pub vcn: Option<u64>,
    /// Offset of this node inside its stream (the loose `$I30` file, or the `$INDEX_ROOT` value).
    pub stream_offset: u64,
    pub lsn: u64,
    pub fixup: FixupStatus,
    pub entries: Vec<IndexEntry>,
    pub anomalies: Vec<NtfsAnomaly>,
    /// Fixed-up node bytes.
    pub bytes: Vec<u8>,
    /// `[used_end, allocated_end)` in `bytes`.
    pub slack: std::ops::Range<usize>,
}

/// An entry carved from node slack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackEntry {
    pub vcn: Option<u64>,
    /// Offset inside the node.
    pub offset: usize,
    /// Offset inside the stream (node offset + `offset`).
    pub stream_offset: u64,
    pub reference: FileRef,
    pub key: FileName,
}

impl IndexNode {
    /// Parses one `INDX` record. `Ok(None)` for an all-zero (never used) record.
    pub fn parse_indx(raw: &[u8]) -> Result<Option<Self>, &'static str> {
        if raw.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        if raw.get(..4) != Some(&INDX_MAGIC[..]) {
            return Err("not an INDX record");
        }
        let mut bytes = raw.to_vec();
        let usa_offset = crate::attr::u16_at(&bytes, 4)?;
        let usa_count = crate::attr::u16_at(&bytes, 6)?;
        let lsn = crate::attr::u64_at(&bytes, 8)?;
        let vcn = crate::attr::u64_at(&bytes, 16)?;
        let fixup = apply_fixups(&mut bytes, usa_offset, usa_count);
        let mut anomalies = Vec::new();
        if !fixup.is_ok() {
            anomalies.push(NtfsAnomaly::IndxFixupMismatch { vcn });
        }
        let mut node = Self::from_node_header(bytes, 24, Some(vcn), anomalies)?;
        node.lsn = lsn;
        node.fixup = fixup;
        Ok(Some(node))
    }

    /// Parses a resident `$INDEX_ROOT` value (node header at offset 16).
    pub fn parse_root(value: &[u8]) -> Result<Self, &'static str> {
        Self::from_node_header(value.to_vec(), 16, None, Vec::new())
    }

    fn from_node_header(
        bytes: Vec<u8>,
        base: usize,
        vcn: Option<u64>,
        mut anomalies: Vec<NtfsAnomaly>,
    ) -> Result<Self, &'static str> {
        let entries_offset = crate::attr::u32_at(&bytes, base)? as usize;
        let index_length = crate::attr::u32_at(&bytes, base + 4)? as usize;
        let allocated = crate::attr::u32_at(&bytes, base + 8)? as usize;
        let start = base
            .checked_add(entries_offset)
            .ok_or("entries offset overflow")?;
        let mut used_end = base
            .checked_add(index_length)
            .ok_or("index length overflow")?;
        let alloc_end = base
            .checked_add(allocated)
            .ok_or("allocated length overflow")?
            .min(bytes.len());
        if used_end > alloc_end {
            anomalies.push(NtfsAnomaly::AttributeMalformed {
                type_code: crate::record::attribute::ATTR_INDEX_ALLOCATION,
                reason: "index length exceeds allocated length",
            });
            used_end = alloc_end;
        }
        if start > used_end {
            return Err("entries start past the used length");
        }
        let mut entries = Vec::new();
        let mut off = start;
        while off + 16 <= used_end {
            let len = usize::from(crate::attr::u16_at(&bytes, off + 8)?);
            let key_len = usize::from(crate::attr::u16_at(&bytes, off + 10)?);
            let flags = crate::attr::u32_at(&bytes, off + 12)?;
            if len < 16 || len % 8 != 0 || off + len > used_end {
                anomalies.push(NtfsAnomaly::AttributeMalformed {
                    type_code: crate::record::attribute::ATTR_INDEX_ALLOCATION,
                    reason: "index entry length out of range",
                });
                break;
            }
            if flags & ENTRY_LAST != 0 {
                break;
            }
            let key_bytes = bytes
                .get(off + 16..off + 16 + key_len)
                .ok_or("index key outside entry")?;
            match FileName::parse(key_bytes) {
                Ok(key) => {
                    let subnode_vcn = if flags & ENTRY_SUBNODE != 0 {
                        Some(crate::attr::u64_at(&bytes, off + len - 8)?)
                    } else {
                        None
                    };
                    entries.push(IndexEntry {
                        reference: FileRef::from_raw(crate::attr::u64_at(&bytes, off)?),
                        flags,
                        key,
                        subnode_vcn,
                        offset: off,
                    });
                }
                Err(reason) => anomalies.push(NtfsAnomaly::AttributeMalformed {
                    type_code: crate::record::attribute::ATTR_INDEX_ALLOCATION,
                    reason,
                }),
            }
            off += len;
        }
        Ok(Self {
            vcn,
            stream_offset: 0,
            lsn: 0,
            fixup: FixupStatus::Ok,
            entries,
            anomalies,
            slack: used_end..alloc_end,
            bytes,
        })
    }

    /// Structurally valid entries in the slack, before the parent check. Scanned at 8-byte
    /// alignment; an admitted entry skips its own length.
    pub fn slack_candidates(&self, stats: &mut RecoveryStats) -> Vec<SlackEntry> {
        stats.units_scanned += 1;
        let mut out = Vec::new();
        let end = self.slack.end.min(self.bytes.len());
        let mut off = (self.slack.start + 7) & !7;
        while off + MIN_ENTRY <= end {
            let at = off;
            off += 8;
            let (Ok(len), Ok(key_len)) = (
                crate::attr::u16_at(&self.bytes, at + 8),
                crate::attr::u16_at(&self.bytes, at + 10),
            ) else {
                break;
            };
            let (len, key_len) = (usize::from(len), usize::from(key_len));
            if len < MIN_ENTRY
                || len % 8 != 0
                || at + len > end
                || key_len < 0x44
                || 16 + key_len > len
            {
                continue;
            }
            let Some(name_len) = self.bytes.get(at + 16 + 64).map(|&n| usize::from(n)) else {
                continue;
            };
            if key_len != 66 + name_len * 2 {
                continue;
            }
            stats.candidates_found += 1;
            let Some(key) = self
                .bytes
                .get(at + 16..at + 16 + key_len)
                .and_then(admit_file_name)
            else {
                stats.rejected += 1;
                continue;
            };
            let Ok(raw_ref) = crate::attr::u64_at(&self.bytes, at) else {
                continue;
            };
            out.push(SlackEntry {
                vcn: self.vcn,
                offset: at,
                stream_offset: self.stream_offset + at as u64,
                reference: FileRef::from_raw(raw_ref),
                key,
            });
            off = at + len;
        }
        out
    }

    /// Carves slack entries whose parent matches `dir`. Candidates with another parent are
    /// rejected (counted in `stats`).
    pub fn carve_slack(
        &self,
        dir: FileRef,
        attribute_id: u16,
        stats: &mut RecoveryStats,
    ) -> Vec<Recovered<SlackEntry>> {
        let candidates = self.slack_candidates(stats);
        admit_for_directory(candidates, dir, attribute_id, stats)
    }
}

/// Applies the parent check to candidates and wraps admitted ones with their locus.
pub fn admit_for_directory(
    candidates: Vec<SlackEntry>,
    dir: FileRef,
    attribute_id: u16,
    stats: &mut RecoveryStats,
) -> Vec<Recovered<SlackEntry>> {
    let mut out = Vec::new();
    for c in candidates {
        if !parent_matches(c.key.parent, dir) || c.reference.entry == 0 {
            stats.rejected += 1;
            continue;
        }
        stats.admitted += 1;
        let locus = Locus::Ntfs {
            entry: dir.entry,
            sequence: dir.sequence,
            attribute: attribute_id,
            offset: c.stream_offset,
        };
        out.push(Recovered::new(c, Recovery::Slack, locus));
    }
    out
}

/// A loose `$I30` (`$INDEX_ALLOCATION` stream): a sequence of `INDX` records.
#[derive(Debug)]
pub struct IndexAllocation {
    pub record_size: usize,
    pub nodes: Vec<IndexNode>,
    /// Records that are neither zero nor a readable `INDX` record: `(offset, reason)`.
    pub unreadable: Vec<(u64, &'static str)>,
}

impl IndexAllocation {
    /// Parses a whole `$INDEX_ALLOCATION` stream. The record size comes from the first record's
    /// fixup count (a whole number of 512-byte strides).
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let record_size = infer_record_size(bytes).ok_or("no INDX record found")?;
        let mut nodes = Vec::new();
        let mut unreadable = Vec::new();
        for (i, chunk) in bytes.chunks(record_size).enumerate() {
            match IndexNode::parse_indx(chunk) {
                Ok(Some(mut n)) => {
                    n.stream_offset = (i * record_size) as u64;
                    nodes.push(n)
                }
                Ok(None) => {}
                Err(reason) => unreadable.push(((i * record_size) as u64, reason)),
            }
        }
        Ok(Self {
            record_size,
            nodes,
            unreadable,
        })
    }

    /// The directory this index belongs to, inferred from the live entries: the parent reference
    /// shared by all of them. `None` when there are no live entries or they disagree.
    pub fn directory(&self) -> Option<FileRef> {
        let mut parents = self
            .nodes
            .iter()
            .flat_map(|n| n.entries.iter().map(|e| e.key.parent));
        let first = parents.next()?;
        parents.all(|p| p == first).then_some(first)
    }
}

fn infer_record_size(bytes: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    while off + 8 <= bytes.len() {
        if bytes.get(off..off + 4) == Some(&INDX_MAGIC[..]) {
            let usa_count = usize::from(u16::from_le_bytes([bytes[off + 6], bytes[off + 7]]));
            let size = usa_count.checked_sub(1)? * 512;
            return ((512..=65536).contains(&size) && size.is_power_of_two()).then_some(size);
        }
        off += 512;
    }
    None
}

#[cfg(test)]
mod tests;
