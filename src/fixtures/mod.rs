//! Synthetic NTFS structures for tests (records, `$MFT`, `INDX`, USN, `$SDS`, boot sector).
//!
//! Hidden from docs and not part of the stable API. Built from the on-disk layouts, never from
//! real case data.

#![allow(clippy::new_without_default)]

pub mod indx;
pub mod sds;
pub mod usn;
#[cfg(feature = "volume")]
pub mod volume;

use crate::fixup::protect;
use crate::record::attribute::*;
use crate::record::header::{FLAG_DIRECTORY, FLAG_IN_USE};
use crate::reference::FileRef;
use crate::time::NtfsTimes;

/// 2020-01-01T00:00:00Z as a FILETIME.
pub const FILE_TIME_2020: u64 = 132_223_104_000_000_000;
/// One day in FILETIME ticks.
pub const DAY: u64 = 864_000_000_000;

/// Encodes a string as UTF-16LE bytes.
pub fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Builds a 512-byte NTFS boot sector.
pub fn boot_sector(
    bps: u16,
    spc: u8,
    total_sectors: u64,
    mft_lcn: u64,
    cpmr: i8,
    cpir: i8,
) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    b[3..11].copy_from_slice(b"NTFS    ");
    b[11..13].copy_from_slice(&bps.to_le_bytes());
    b[13] = spc;
    b[21] = 0xF8;
    b[40..48].copy_from_slice(&total_sectors.to_le_bytes());
    b[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
    b[56..64].copy_from_slice(&2u64.to_le_bytes());
    b[64] = cpmr as u8;
    b[68] = cpir as u8;
    b[72..80].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

/// Same four times everywhere.
pub fn times(t: u64) -> NtfsTimes {
    NtfsTimes {
        created: t,
        modified: t,
        mft_modified: t,
        accessed: t,
    }
}

/// `$FILE_NAME` value bytes.
pub fn file_name_value(parent: FileRef, name: &str, t: u64, namespace: u8) -> Vec<u8> {
    file_name_value_times(parent, name, &times(t), namespace, 0, 0)
}

/// `$FILE_NAME` value bytes with explicit times and sizes.
pub fn file_name_value_times(
    parent: FileRef,
    name: &str,
    t: &NtfsTimes,
    namespace: u8,
    alloc: u64,
    real: u64,
) -> Vec<u8> {
    let n = utf16(name);
    let mut v = vec![0u8; 66];
    v[0..8].copy_from_slice(&parent.raw().to_le_bytes());
    v[8..16].copy_from_slice(&t.created.to_le_bytes());
    v[16..24].copy_from_slice(&t.modified.to_le_bytes());
    v[24..32].copy_from_slice(&t.mft_modified.to_le_bytes());
    v[32..40].copy_from_slice(&t.accessed.to_le_bytes());
    v[40..48].copy_from_slice(&alloc.to_le_bytes());
    v[48..56].copy_from_slice(&real.to_le_bytes());
    v[64] = (n.len() / 2) as u8;
    v[65] = namespace;
    v.extend(n);
    v
}

/// `$STANDARD_INFORMATION` v3 value bytes.
pub fn std_info_value(t: &NtfsTimes, file_attributes: u32, security_id: u32) -> Vec<u8> {
    let mut v = vec![0u8; 72];
    v[0..8].copy_from_slice(&t.created.to_le_bytes());
    v[8..16].copy_from_slice(&t.modified.to_le_bytes());
    v[16..24].copy_from_slice(&t.mft_modified.to_le_bytes());
    v[24..32].copy_from_slice(&t.accessed.to_le_bytes());
    v[32..36].copy_from_slice(&file_attributes.to_le_bytes());
    v[52..56].copy_from_slice(&security_id.to_le_bytes());
    v
}

/// Builder for one `FILE` record.
pub struct RecordBuilder {
    entry: u64,
    sequence: u16,
    flags: u16,
    size: usize,
    base: FileRef,
    lsn: u64,
    attrs: Vec<Vec<u8>>,
    slack: Vec<u8>,
    next_id: u16,
}

impl RecordBuilder {
    /// An in-use file record.
    pub fn file(entry: u64, sequence: u16) -> Self {
        Self {
            entry,
            sequence,
            flags: FLAG_IN_USE,
            size: 1024,
            base: FileRef::default(),
            lsn: 0x1000 + entry,
            attrs: Vec::new(),
            slack: Vec::new(),
            next_id: 0,
        }
    }

    pub fn directory(mut self) -> Self {
        self.flags |= FLAG_DIRECTORY;
        self
    }

    pub fn deleted(mut self) -> Self {
        self.flags &= !FLAG_IN_USE;
        self
    }

    pub fn size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    pub fn base(mut self, base: FileRef) -> Self {
        self.base = base;
        self
    }

    /// Bytes written into the record slack, right after the end marker.
    pub fn slack(mut self, bytes: &[u8]) -> Self {
        self.slack = bytes.to_vec();
        self
    }

    pub fn std_info(self, t: u64) -> Self {
        self.std_info_times(&times(t), 0x20, 0)
    }

    pub fn std_info_times(self, t: &NtfsTimes, file_attributes: u32, security_id: u32) -> Self {
        self.resident(
            ATTR_STANDARD_INFORMATION,
            "",
            &std_info_value(t, file_attributes, security_id),
        )
    }

    pub fn file_name(self, parent_entry: u64, parent_seq: u16, name: &str, t: u64) -> Self {
        self.resident(
            ATTR_FILE_NAME,
            "",
            &file_name_value(FileRef::new(parent_entry, parent_seq), name, t, 3),
        )
    }

    pub fn file_name_full(self, parent: FileRef, name: &str, t: &NtfsTimes, namespace: u8) -> Self {
        self.resident(
            ATTR_FILE_NAME,
            "",
            &file_name_value_times(parent, name, t, namespace, 0, 0),
        )
    }

    pub fn resident_data(self, name: &str, data: &[u8]) -> Self {
        self.resident(ATTR_DATA, name, data)
    }

    /// Any resident attribute.
    pub fn resident(mut self, type_code: u32, name: &str, value: &[u8]) -> Self {
        let name16 = utf16(name);
        let name_off = 24usize;
        let value_off = align8(name_off + name16.len());
        let len = align8(value_off + value.len());
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&type_code.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 0;
        a[9] = (name16.len() / 2) as u8;
        a[10..12].copy_from_slice(&(name_off as u16).to_le_bytes());
        a[14..16].copy_from_slice(&self.next_id.to_le_bytes());
        a[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        a[20..22].copy_from_slice(&(value_off as u16).to_le_bytes());
        a[name_off..name_off + name16.len()].copy_from_slice(&name16);
        a[value_off..value_off + value.len()].copy_from_slice(value);
        self.next_id += 1;
        self.attrs.push(a);
        self
    }

    /// A non-resident attribute with the given runs (`(length, lcn)`).
    pub fn non_resident(
        self,
        type_code: u32,
        name: &str,
        runs: &[(u64, Option<u64>)],
        data_size: u64,
        cluster: u64,
    ) -> Self {
        let clusters: u64 = runs.iter().map(|r| r.0).sum();
        self.non_resident_full(NonResidentSpec {
            type_code,
            name,
            starting_vcn: 0,
            runs,
            allocated_size: clusters * cluster,
            data_size,
            flags: 0,
            compression_unit: 0,
        })
    }

    /// Any non-resident attribute segment.
    pub fn non_resident_full(mut self, spec: NonResidentSpec<'_>) -> Self {
        let name16 = utf16(spec.name);
        let compressed = spec.compression_unit != 0;
        let name_off = if compressed { 72usize } else { 64 };
        let rl = crate::runlist::encode(spec.runs);
        let rl_off = align8(name_off + name16.len());
        let len = align8(rl_off + rl.len());
        let clusters: u64 = spec.runs.iter().map(|r| r.0).sum();
        let stored: u64 = spec
            .runs
            .iter()
            .filter(|r| r.1.is_some())
            .map(|r| r.0)
            .sum();
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&spec.type_code.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 1;
        a[9] = (name16.len() / 2) as u8;
        a[10..12].copy_from_slice(&(name_off as u16).to_le_bytes());
        a[12..14].copy_from_slice(&spec.flags.to_le_bytes());
        a[14..16].copy_from_slice(&self.next_id.to_le_bytes());
        a[16..24].copy_from_slice(&spec.starting_vcn.to_le_bytes());
        a[24..32].copy_from_slice(
            &(spec.starting_vcn + clusters)
                .saturating_sub(1)
                .to_le_bytes(),
        );
        a[32..34].copy_from_slice(&(rl_off as u16).to_le_bytes());
        a[34..36].copy_from_slice(&spec.compression_unit.to_le_bytes());
        a[40..48].copy_from_slice(&spec.allocated_size.to_le_bytes());
        a[48..56].copy_from_slice(&spec.data_size.to_le_bytes());
        a[56..64].copy_from_slice(&spec.data_size.to_le_bytes());
        if compressed {
            let cluster = spec.allocated_size / clusters.max(1);
            a[64..72].copy_from_slice(&(stored * cluster).to_le_bytes());
        }
        a[name_off..name_off + name16.len()].copy_from_slice(&name16);
        a[rl_off..rl_off + rl.len()].copy_from_slice(&rl);
        self.next_id += 1;
        self.attrs.push(a);
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut r = vec![0u8; self.size];
        let strides = self.size / 512;
        let first_attr = align8(0x30 + 2 + strides * 2);
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        r[6..8].copy_from_slice(&((strides + 1) as u16).to_le_bytes());
        r[8..16].copy_from_slice(&self.lsn.to_le_bytes());
        r[16..18].copy_from_slice(&self.sequence.to_le_bytes());
        r[18..20].copy_from_slice(&1u16.to_le_bytes());
        r[20..22].copy_from_slice(&(first_attr as u16).to_le_bytes());
        r[22..24].copy_from_slice(&self.flags.to_le_bytes());
        r[28..32].copy_from_slice(&(self.size as u32).to_le_bytes());
        r[32..40].copy_from_slice(&self.base.raw().to_le_bytes());
        r[40..42].copy_from_slice(&self.next_id.to_le_bytes());
        r[44..48].copy_from_slice(&(self.entry as u32).to_le_bytes());
        let mut off = first_attr;
        for a in &self.attrs {
            r[off..off + a.len()].copy_from_slice(a);
            off += a.len();
        }
        r[off..off + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        off += 8;
        r[24..28].copy_from_slice(&(off as u32).to_le_bytes());
        let slack_len = self.slack.len().min(self.size - off);
        r[off..off + slack_len].copy_from_slice(&self.slack[..slack_len]);
        protect(&mut r, 0x30, 1);
        r
    }
}

/// Parameters of [`RecordBuilder::non_resident_full`].
pub struct NonResidentSpec<'a> {
    pub type_code: u32,
    pub name: &'a str,
    pub starting_vcn: u64,
    /// `(length, lcn)`; `None` = sparse.
    pub runs: &'a [(u64, Option<u64>)],
    pub allocated_size: u64,
    pub data_size: u64,
    pub flags: u16,
    pub compression_unit: u16,
}

/// One `$ATTRIBUTE_LIST` entry.
pub fn attr_list_entry(type_code: u32, starting_vcn: u64, segment: FileRef, id: u16) -> Vec<u8> {
    let mut e = vec![0u8; 32];
    e[0..4].copy_from_slice(&type_code.to_le_bytes());
    e[4..6].copy_from_slice(&32u16.to_le_bytes());
    e[7] = 26;
    e[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
    e[16..24].copy_from_slice(&segment.raw().to_le_bytes());
    e[24..26].copy_from_slice(&id.to_le_bytes());
    e
}

fn align8(v: usize) -> usize {
    (v + 7) & !7
}

/// Builds a loose `$MFT`: a minimal set of metafiles plus caller-added records.
pub struct MftBuilder {
    record_size: usize,
    records: std::collections::BTreeMap<u64, Vec<u8>>,
}

impl MftBuilder {
    /// Metafiles 0 (`$MFT`), 5 (root) and 11 (`$Extend`), all under the root.
    pub fn new() -> Self {
        let mut b = Self {
            record_size: 1024,
            records: Default::default(),
        };
        b.put(
            0,
            RecordBuilder::file(0, 1)
                .std_info(FILE_TIME_2020)
                .file_name(5, 5, "$MFT", FILE_TIME_2020)
                .build(),
        );
        b.put(
            5,
            RecordBuilder::file(5, 5)
                .directory()
                .std_info(FILE_TIME_2020)
                .file_name(5, 5, ".", FILE_TIME_2020)
                .build(),
        );
        b.put(
            11,
            RecordBuilder::file(11, 11)
                .directory()
                .std_info(FILE_TIME_2020)
                .file_name(5, 5, "$Extend", FILE_TIME_2020)
                .build(),
        );
        b
    }

    pub fn put(&mut self, entry: u64, record: Vec<u8>) -> &mut Self {
        self.records.insert(entry, record);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let last = self.records.keys().next_back().copied().unwrap_or(0);
        let mut out = vec![0u8; (last as usize + 1) * self.record_size];
        for (&e, r) in &self.records {
            let at = e as usize * self.record_size;
            let n = r.len().min(self.record_size);
            out[at..at + n].copy_from_slice(&r[..n]);
        }
        out
    }
}
