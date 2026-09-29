//! `$MFTMirr`: the mirrored copy of the first `$MFT` records, and the cross-check against `$MFT`.
//!
//! NTFS keeps a second copy of the start of the `$MFT` in a separate file, `$MFTMirr` (metafile
//! entry 1), so that a volume whose first `$MFT` records are damaged can still be mounted. The
//! copy is written by the same transaction that writes the record, so on a quiet volume the two
//! agree byte for byte.
//!
//! They disagreeing is evidence, not a yes/no answer: the analyst has to see *both* sides. Every
//! [`MirrorRecordCheck`] therefore carries the record number, the raw bytes of each side as they
//! were stored, the offset each was read from **and the stream that offset is relative to**, the
//! sequence and update sequence numbers as read, and the header fields that differ.
//!
//! # Fixups are not content
//!
//! A `FILE` record is stored with its last two bytes per 512-byte stride replaced by the update
//! sequence number ([`crate::fixup`]). Collection tools differ: `ntfscat` (libntfs) writes a loose
//! `$MFT` with the fixups already reverted, while the same record read out of a disk image still
//! carries them. Comparing raw bytes alone would then call every record of a perfectly consistent
//! volume a mismatch. The comparison here applies the fixups to both sides first, and reports
//! [`MirrorVerdict::FixupOnly`] when only the multi-sector protection differs — consistent content,
//! stored differently.
//!
//! Looking past that difference is only safe while both sides' protection verifies. A record torn
//! mid-write reverts to the same content as a clean copy, so a side whose fixups do not verify is
//! [`MirrorVerdict::FixupTorn`], never `FixupOnly`: the content agrees, how it was stored does not,
//! and the analyst is told which side.

use std::io::{Read, Seek};
use std::sync::Arc;

use forensic_rs::prelude::*;

use crate::anomaly::NtfsAnomaly;
use crate::boot::BootSector;
use crate::error;
use crate::fixup::{apply_fixups, FixupStatus};
use crate::mft::{infer_record_size, Mft};
use crate::record::header::RecordHeader;
use crate::record::MftRecord;
use crate::reference::FileRef;
use crate::source::{BytesSource, RecordSource, StreamSource, WindowSource};

/// `$MFTMirr`'s own metafile entry in the `$MFT`.
pub const MFTMIRR_ENTRY: u64 = 1;

/// Records NTFS guarantees are mirrored: `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`. A `$MFTMirr`
/// can be allocated a whole cluster, but only these four are kept up to date.
pub const MIRRORED_RECORDS: u64 = 4;

/// Most record slots read out of one `$MFTMirr`, whatever its length claims.
///
/// A real mirror is four records, at most a cluster's worth. This cap is 256 times that, so it
/// never trims a genuine copy; it stops a file that is not a `$MFTMirr` at all (a whole image
/// renamed, a padded export) from turning its length into an unbounded allocation. Going over it
/// is reported as [`NtfsAnomaly::MftMirrOversized`], never trimmed in silence.
pub const MAX_MIRROR_RECORDS: u64 = 1024;

/// Name of the stream an offset in a [`MirrorSide`] is relative to.
pub const STREAM_MFT: &str = "$MFT";
/// Name of the stream an offset in a [`MirrorSide`] is relative to.
pub const STREAM_MFTMIRR: &str = "$MFTMirr";

/// One side of a record comparison: exactly what was read, and where from.
///
/// `offset` is relative to the start of the stream named by `stream` — the `$MFT` data stream or
/// the `$MFTMirr` data stream, never the volume or the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSide {
    /// Which stream the bytes come from: [`STREAM_MFT`] or [`STREAM_MFTMIRR`].
    pub stream: &'static str,
    /// Byte offset of the record from the start of `stream`.
    pub offset: u64,
    /// The record bytes exactly as stored, fixups **not** applied. `None` when the read failed.
    pub raw: Option<Vec<u8>>,
    /// The same bytes with the fixups applied, kept next to `raw` rather than recomputed: the
    /// comparison needs both, and what was read must survive next to what was resolved. A record
    /// whose update sequence array is out of range is stored here as read.
    pub fixed: Option<Vec<u8>>,
    /// Why the read failed. `Some` exactly when `raw` is `None`.
    pub unreadable: Option<String>,
    /// Sequence number as stored in the header, when a header could be read.
    pub sequence: Option<u16>,
    /// Update sequence number from the fixup array, as stored.
    pub update_sequence: Option<u16>,
    /// What applying the fixups to this side found.
    pub fixup: Option<FixupStatus>,
}

impl MirrorSide {
    fn unreadable(stream: &'static str, offset: u64, why: impl Into<String>) -> Self {
        Self {
            stream,
            offset,
            raw: None,
            fixed: None,
            unreadable: Some(why.into()),
            sequence: None,
            update_sequence: None,
            fixup: None,
        }
    }

    fn read(stream: &'static str, offset: u64, raw: Vec<u8>) -> Self {
        // A header that will not parse is not fatal here: the raw bytes are still the evidence,
        // and the byte comparison below is what decides the verdict.
        let header = RecordHeader::parse(&raw).ok();
        let update_sequence = header.as_ref().and_then(|h| {
            let at = usize::from(h.usa_offset);
            raw.get(at..at + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
        });
        let mut fixed = raw.clone();
        let fixup = header
            .as_ref()
            .map(|h| apply_fixups(&mut fixed, h.usa_offset, h.usa_count));
        Self {
            stream,
            offset,
            raw: Some(raw),
            fixed: Some(fixed),
            unreadable: None,
            sequence: header.as_ref().map(|h| h.sequence),
            update_sequence,
            fixup,
        }
    }

    /// The record reference this side claims (entry number is the caller's, sequence is as read).
    pub fn reference(&self, entry: u64) -> Option<FileRef> {
        self.sequence.map(|s| FileRef::new(entry, s))
    }

    /// The bytes with the fixups applied, when the record could be read.
    /// A record whose update sequence array is out of range is returned as read.
    pub fn fixed_bytes(&self) -> Option<&[u8]> {
        self.fixed.as_deref()
    }

    /// Whether this side's multi-sector protection verifies. `false` when the record could not be
    /// read, when its header would not parse, and when it was torn mid-write.
    pub fn fixup_verifies(&self) -> bool {
        self.fixup.is_some_and(FixupStatus::is_ok)
    }

    /// Whether a record header could be read from this side at all.
    pub fn has_record_header(&self) -> bool {
        self.sequence.is_some()
    }
}

/// What the comparison of one record number found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorVerdict {
    /// The two records are byte for byte identical as stored.
    Identical,
    /// Identical once the fixups are applied, **and both sides' protection verifies**: only the
    /// multi-sector protection differs, because one copy was extracted with the fixups already
    /// reverted. The content agrees.
    FixupOnly,
    /// Identical once the fixups are applied, but at least one side's protection does **not**
    /// verify: that side was torn mid-write, or altered after it was written. The content agrees;
    /// how it was stored does not. Reported rather than absorbed into [`Self::FixupOnly`], because
    /// each side's `fixup` status only ever reaches output on a check record.
    FixupTorn,
    /// The content differs. See [`MirrorRecordCheck::differing_fields`] and both sides' raw bytes.
    Divergent,
    /// One or both sides could not be read. See each side's `unreadable`.
    Unreadable,
}

impl MirrorVerdict {
    /// Stable snake_case name for output fields.
    pub fn name(self) -> &'static str {
        match self {
            MirrorVerdict::Identical => "identical",
            MirrorVerdict::FixupOnly => "fixup_only",
            MirrorVerdict::FixupTorn => "fixup_torn",
            MirrorVerdict::Divergent => "divergent",
            MirrorVerdict::Unreadable => "unreadable",
        }
    }

    /// Whether the check needs no attention: the two copies agree on the record's content **and**
    /// both sides are intact as stored. [`Self::FixupTorn`] agrees on content but is not clean, so
    /// it does not count here — the torn side has to reach the analyst.
    pub fn agrees(self) -> bool {
        matches!(self, MirrorVerdict::Identical | MirrorVerdict::FixupOnly)
    }

    /// Whether the two copies hold the same record content, however each was stored.
    pub fn content_agrees(self) -> bool {
        matches!(
            self,
            MirrorVerdict::Identical | MirrorVerdict::FixupOnly | MirrorVerdict::FixupTorn
        )
    }
}

/// The comparison of one record number, carrying both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRecordCheck {
    /// Record number in the `$MFT`. `$MFTMirr` stores it at the same position.
    pub entry: u64,
    /// What was read from the `$MFT`.
    pub primary: MirrorSide,
    /// What was read from the `$MFTMirr`.
    pub mirror: MirrorSide,
    pub verdict: MirrorVerdict,
    /// Header fields whose decoded values differ, in header order; `"body"` when the difference is
    /// past the header. Empty unless the verdict is [`MirrorVerdict::Divergent`].
    pub differing_fields: Vec<&'static str>,
    /// Offset of the first differing byte **within the record**, after fixups.
    pub first_difference: Option<usize>,
}

impl MirrorRecordCheck {
    /// Whether this record needs no attention: see [`MirrorVerdict::agrees`].
    pub fn agrees(&self) -> bool {
        self.verdict.agrees()
    }

    /// The anomaly this one record raises, or `None` when it is clean. The evidence stays on the
    /// check; the anomaly only names what kind of disagreement it is.
    pub fn anomaly(&self) -> Option<NtfsAnomaly> {
        match self.verdict {
            MirrorVerdict::Identical | MirrorVerdict::FixupOnly => None,
            MirrorVerdict::FixupTorn => Some(NtfsAnomaly::MftMirrTorn {
                entries: vec![self.entry],
            }),
            MirrorVerdict::Divergent | MirrorVerdict::Unreadable => {
                Some(NtfsAnomaly::MftMirrMismatch {
                    entries: vec![self.entry],
                })
            }
        }
    }
}

impl std::fmt::Display for MirrorRecordCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "record {}: {}", self.entry, self.verdict.name())?;
        if !self.differing_fields.is_empty() {
            write!(f, " ({})", self.differing_fields.join(", "))?;
        }
        if let Some(at) = self.first_difference {
            write!(f, ", first differing byte at {at:#x} of the record")?;
        }
        for side in [&self.primary, &self.mirror] {
            if let Some(why) = &side.unreadable {
                write!(f, "; {} at {}: {why}", side.stream, side.offset)?;
            }
        }
        Ok(())
    }
}

/// The result of cross-checking a `$MFTMirr` against its `$MFT`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorComparison {
    /// Record size both sides were read with.
    pub record_size: u32,
    /// One check per record number, in record order.
    pub checks: Vec<MirrorRecordCheck>,
}

impl MirrorComparison {
    /// Checks whose two sides do not agree, in record order.
    pub fn disagreements(&self) -> impl Iterator<Item = &MirrorRecordCheck> {
        self.checks.iter().filter(|c| !c.agrees())
    }

    /// Whether every compared record agreed.
    pub fn agrees(&self) -> bool {
        self.checks.iter().all(MirrorRecordCheck::agrees)
    }

    /// How many checks reached each verdict.
    pub fn counts(&self) -> MirrorCounts {
        let mut c = MirrorCounts {
            compared: self.checks.len() as u64,
            ..Default::default()
        };
        for check in &self.checks {
            match check.verdict {
                MirrorVerdict::Identical => c.identical += 1,
                MirrorVerdict::FixupOnly => c.fixup_only += 1,
                MirrorVerdict::FixupTorn => c.fixup_torn += 1,
                MirrorVerdict::Divergent => c.divergent += 1,
                MirrorVerdict::Unreadable => c.unreadable += 1,
            }
        }
        c
    }

    /// Whether no slot read from the copy holds a record header.
    ///
    /// A genuine `$MFTMirr` always has one in every mirrored slot, so this means the file is not a
    /// mirror — a collection tool exported the wrong stream, or the name was reused. It is checked
    /// before the divergence is diagnosed: comparing an unrelated file against the `$MFT` produces
    /// a difference in every record, and calling that tampering would be wrong.
    pub fn is_not_a_mirror(&self) -> bool {
        let mut read = 0usize;
        for check in self.checks.iter().filter(|c| c.mirror.raw.is_some()) {
            if check.mirror.has_record_header() {
                return false;
            }
            read += 1;
        }
        read > 0
    }

    /// The summary anomalies, in a fixed order, or empty when every record is clean. The
    /// per-record evidence stays in [`Self::checks`]; an anomaly only names the record numbers.
    pub fn anomalies(&self) -> Vec<NtfsAnomaly> {
        if self.is_not_a_mirror() {
            // Diagnosing "the first MFT records were tampered with" against a file that is not a
            // mirror at all would point the analyst at the wrong thing.
            return vec![NtfsAnomaly::MftMirrNotAMirror {
                slots: self.checks.len() as u64,
            }];
        }
        let mut out = Vec::new();
        let differ: Vec<u64> = self
            .checks
            .iter()
            .filter(|c| !c.verdict.content_agrees())
            .map(|c| c.entry)
            .collect();
        if !differ.is_empty() {
            out.push(NtfsAnomaly::MftMirrMismatch { entries: differ });
        }
        let torn: Vec<u64> = self
            .checks
            .iter()
            .filter(|c| c.verdict == MirrorVerdict::FixupTorn)
            .map(|c| c.entry)
            .collect();
        if !torn.is_empty() {
            out.push(NtfsAnomaly::MftMirrTorn { entries: torn });
        }
        out
    }
}

/// Verdict tallies of a [`MirrorComparison`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MirrorCounts {
    pub compared: u64,
    pub identical: u64,
    pub fixup_only: u64,
    pub fixup_torn: u64,
    pub divergent: u64,
    pub unreadable: u64,
}

/// A `$MFTMirr`: a loose file, or a window of a volume.
pub struct MftMirr {
    source: Box<dyn RecordSource>,
    record_size: u32,
    record_count: u64,
    covered: u64,
    /// Problems with the `$MFTMirr` as a whole (e.g. a truncated copy).
    pub anomalies: Vec<NtfsAnomaly>,
}

impl std::fmt::Debug for MftMirr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MftMirr")
            .field("record_size", &self.record_size)
            .field("record_count", &self.record_count)
            .field("anomalies", &self.anomalies)
            .finish_non_exhaustive()
    }
}

impl MftMirr {
    /// Opens a loose `$MFTMirr` from any `Read + Seek` (a file, a `VirtualFile`, a cursor).
    pub fn from_reader<R: Read + Seek + Send + 'static>(reader: R) -> ForensicResult<Self> {
        Self::open(Box::new(StreamSource::new(reader)?), None)
    }

    /// Opens a loose `$MFTMirr` held in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> ForensicResult<Self> {
        Self::open(Box::new(BytesSource(bytes)), None)
    }

    /// Opens the `MIRRORED_RECORDS` records at the `$MFTMirr` LCN the boot sector declares.
    ///
    /// The locator is the boot sector's, not the `$MFT`'s: a cross-check that asked the `$MFT`
    /// where its own mirror lives would be circular. `media` offsets are relative to the start of
    /// the volume.
    pub fn at_boot_lcn(media: Arc<dyn RecordSource>, boot: &BootSector) -> ForensicResult<Self> {
        let start = boot
            .mftmirr_lcn
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| error::invalid("$MFTMirr LCN overflows"))?;
        let len = u64::from(boot.mft_record_size)
            .checked_mul(MIRRORED_RECORDS)
            .ok_or_else(|| error::invalid("$MFTMirr length overflows"))?;
        let window = WindowSource::new(media, start, len)?;
        Self::open(Box::new(window), Some(boot))
    }

    /// Opens a `$MFTMirr` from any source. With a boot sector the record size comes from it,
    /// otherwise it is inferred from the first record.
    pub fn open(source: Box<dyn RecordSource>, boot: Option<&BootSector>) -> ForensicResult<Self> {
        let record_size = match boot {
            Some(b) => b.mft_record_size,
            None => infer_record_size(source.as_ref())?,
        };
        if record_size == 0 {
            return Err(error::invalid("$MFTMirr record size is zero"));
        }
        let len = source.len();
        let mut anomalies = Vec::new();
        if !len.is_multiple_of(u64::from(record_size)) {
            anomalies.push(NtfsAnomaly::MftFileSizeMismatch {
                length: len,
                record_size,
            });
        }
        // `div_ceil`, so a truncated trailing record is reported as an `Err` item rather than
        // silently dropped.
        let record_count = len.div_ceil(u64::from(record_size));
        let covered = record_count.min(MAX_MIRROR_RECORDS);
        if covered < record_count {
            anomalies.push(NtfsAnomaly::MftMirrOversized {
                records: record_count,
                read: covered,
            });
        }
        Ok(Self {
            record_count,
            covered,
            source,
            record_size,
            anomalies,
        })
    }

    pub fn record_size(&self) -> u32 {
        self.record_size
    }

    /// Number of record slots the file holds, as its length says. A trailing partial record counts
    /// as one slot; it reads as an `Err`.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Slots actually read and compared: [`Self::record_count`] capped at [`MAX_MIRROR_RECORDS`].
    /// Lower than the count only when [`NtfsAnomaly::MftMirrOversized`] is on [`Self::anomalies`].
    pub fn covered(&self) -> u64 {
        self.covered
    }

    /// Byte offset of `entry` from the start of the `$MFTMirr` stream.
    pub fn offset_of(&self, entry: u64) -> u64 {
        entry.saturating_mul(u64::from(self.record_size))
    }

    /// Raw bytes of one record as stored (fixups not applied).
    pub fn raw_record(&self, entry: u64) -> ForensicResult<Vec<u8>> {
        self.source
            .read_vec(self.offset_of(entry), self.record_size as usize)
    }

    /// Reads and parses one record. `Ok(None)` = empty slot or past the end.
    pub fn record(&self, entry: u64) -> ForensicResult<Option<MftRecord>> {
        if entry >= self.covered {
            return Ok(None);
        }
        let offset = self.offset_of(entry);
        let raw = self.raw_record(entry)?;
        MftRecord::parse(entry, &raw).map_err(|e| error::corrupted(offset, e.to_string()))
    }

    /// Every record in the copy, in record order. An unreadable or truncated record is one `Err`
    /// item and iteration continues.
    pub fn records(&self) -> MirrorRecordIter<'_> {
        MirrorRecordIter {
            mirr: self,
            next: 0,
        }
    }

    /// Cross-checks the copy against `mft`, one entry at a time.
    ///
    /// Every record number the copy covers is compared, even when the `$MFT` is shorter: a record
    /// the primary cannot supply is an [`MirrorVerdict::Unreadable`] check naming why, not a
    /// silent skip.
    pub fn compare_with(&self, mft: &Mft) -> MirrorComparison {
        let mut checks = Vec::with_capacity(self.covered as usize);
        for entry in 0..self.covered {
            let primary = match mft.raw_record(entry) {
                Ok(raw) if raw.len() == self.record_size as usize => {
                    MirrorSide::read(STREAM_MFT, mft.offset_of(entry), raw)
                }
                Ok(raw) => MirrorSide::unreadable(
                    STREAM_MFT,
                    mft.offset_of(entry),
                    format!(
                        "read {} bytes, the $MFTMirr record size is {}",
                        raw.len(),
                        self.record_size
                    ),
                ),
                Err(e) => MirrorSide::unreadable(STREAM_MFT, mft.offset_of(entry), e.to_string()),
            };
            let mirror = match self.raw_record(entry) {
                Ok(raw) => MirrorSide::read(STREAM_MFTMIRR, self.offset_of(entry), raw),
                Err(e) => {
                    MirrorSide::unreadable(STREAM_MFTMIRR, self.offset_of(entry), e.to_string())
                }
            };
            checks.push(compare_sides(entry, primary, mirror));
        }
        MirrorComparison {
            record_size: self.record_size,
            checks,
        }
    }
}

/// Iterator returned by [`MftMirr::records`].
pub struct MirrorRecordIter<'a> {
    mirr: &'a MftMirr,
    next: u64,
}

impl Iterator for MirrorRecordIter<'_> {
    type Item = ForensicResult<MftRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.mirr.covered {
            let n = self.next;
            self.next += 1;
            match self.mirr.record(n) {
                Ok(Some(r)) => return Some(Ok(r)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }
}

/// Reads one header field as an integer, so any two headers can be compared field by field.
type HeaderField = (&'static str, fn(&RecordHeader) -> u64);

/// Header fields compared, in header order.
const HEADER_FIELDS: &[HeaderField] = &[
    ("signature", |h| h.signature as u64),
    ("usa_offset", |h| u64::from(h.usa_offset)),
    ("usa_count", |h| u64::from(h.usa_count)),
    ("lsn", |h| h.lsn),
    ("sequence", |h| u64::from(h.sequence)),
    ("link_count", |h| u64::from(h.link_count)),
    ("first_attribute_offset", |h| {
        u64::from(h.first_attribute_offset)
    }),
    ("flags", |h| u64::from(h.flags)),
    ("used_size", |h| u64::from(h.used_size)),
    ("allocated_size", |h| u64::from(h.allocated_size)),
    ("base_reference", |h| h.base_reference.raw()),
    ("next_attribute_id", |h| u64::from(h.next_attribute_id)),
    ("record_number", |h| {
        h.record_number.map_or(u64::MAX, u64::from)
    }),
];

fn compare_sides(entry: u64, primary: MirrorSide, mirror: MirrorSide) -> MirrorRecordCheck {
    let (Some(praw), Some(mraw)) = (primary.raw.as_ref(), mirror.raw.as_ref()) else {
        return MirrorRecordCheck {
            entry,
            primary,
            mirror,
            verdict: MirrorVerdict::Unreadable,
            differing_fields: Vec::new(),
            first_difference: None,
        };
    };
    if praw == mraw {
        return MirrorRecordCheck {
            entry,
            primary,
            mirror,
            verdict: MirrorVerdict::Identical,
            differing_fields: Vec::new(),
            first_difference: None,
        };
    }
    // Borrowed from each side, never copied: the fixed-up form was kept when the side was read.
    let pfix: &[u8] = primary.fixed_bytes().unwrap_or_default();
    let mfix: &[u8] = mirror.fixed_bytes().unwrap_or_default();
    if pfix == mfix {
        // Looking past a raw byte difference is only safe when both sides' protection actually
        // verifies. A torn side reverts to the same content as a clean mirror, so accepting it
        // here would report a half-written (or altered) record as agreeing, and its `fixup`
        // status would never reach output.
        let verdict = if primary.fixup_verifies() && mirror.fixup_verifies() {
            MirrorVerdict::FixupOnly
        } else {
            MirrorVerdict::FixupTorn
        };
        return MirrorRecordCheck {
            entry,
            primary,
            mirror,
            verdict,
            differing_fields: Vec::new(),
            first_difference: None,
        };
    }
    let first_difference = pfix
        .iter()
        .zip(mfix.iter())
        .position(|(a, b)| a != b)
        .or(Some(pfix.len().min(mfix.len())));
    let mut differing_fields = Vec::new();
    match (RecordHeader::parse(pfix), RecordHeader::parse(mfix)) {
        (Ok(ph), Ok(mh)) => {
            for (name, get) in HEADER_FIELDS {
                if get(&ph) != get(&mh) {
                    differing_fields.push(*name);
                }
            }
            let head = crate::record::header::HEADER_SIZE;
            // The header has bytes no named field decodes (the padding before `record_number`).
            // A difference there is still a difference: say where it is rather than report a
            // divergence with an empty field list.
            if differing_fields.is_empty() && pfix.get(..head) != mfix.get(..head) {
                differing_fields.push("header_other");
            }
            if pfix.get(head..) != mfix.get(head..) {
                differing_fields.push("body");
            }
        }
        // A side whose header will not parse at all: say so rather than guess a field list.
        _ => differing_fields.push("header_unparsable"),
    }
    MirrorRecordCheck {
        entry,
        primary,
        mirror,
        verdict: MirrorVerdict::Divergent,
        differing_fields,
        first_difference,
    }
}

#[cfg(test)]
mod tests;
