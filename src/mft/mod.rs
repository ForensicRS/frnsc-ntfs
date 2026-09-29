//! A whole `$MFT`: loose file or (with the `volume` feature) read from a volume.

pub mod entry;
pub mod index;
pub mod mirror;
pub mod paths;
pub mod timestomp;

use std::io::{Read, Seek};

use forensic_rs::prelude::*;

pub use entry::{AttrListState, DataStream, LoggedStream, MftEntry};
pub use index::{MftIndex, Slot};
pub use mirror::{
    MftMirr, MirrorComparison, MirrorCounts, MirrorRecordCheck, MirrorSide, MirrorVerdict,
};
pub use paths::{PathStatus, ResolvedPath};

use crate::anomaly::NtfsAnomaly;
use crate::boot::{BootSector, MAX_RECORD_SIZE, MIN_RECORD_SIZE};
use crate::error;
use crate::record::MftRecord;
use crate::reference::{FileRef, ROOT_ENTRY};
use crate::source::{BytesSource, RecordSource, StreamSource};
use paths::PathTable;

/// How often (in records) long loops poll for cancellation.
pub const CANCEL_POLL: u64 = 4096;

/// A parsed `$MFT` with its pass-1 index and directory path table.
pub struct Mft {
    source: Box<dyn RecordSource>,
    record_size: u32,
    entry_count: u64,
    index: MftIndex,
    paths: PathTable,
    /// Problems with the `$MFT` as a whole (e.g. truncated collection).
    pub anomalies: Vec<NtfsAnomaly>,
}

impl std::fmt::Debug for Mft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mft")
            .field("record_size", &self.record_size)
            .field("entry_count", &self.entry_count)
            .finish_non_exhaustive()
    }
}

impl Mft {
    /// Opens a loose `$MFT` from any `Read + Seek` (a file, a `VirtualFile`, a cursor).
    pub fn from_reader<R: Read + Seek + Send + 'static>(reader: R) -> ForensicResult<Self> {
        Self::open(Box::new(StreamSource::new(reader)?), None, &|| false)
    }

    /// Opens a loose `$MFT` held in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> ForensicResult<Self> {
        Self::open(Box::new(BytesSource(bytes)), None, &|| false)
    }

    /// Opens a `$MFT` from any source. With a boot sector (a loose `$Boot` or the volume's), the
    /// record size comes from it; otherwise it is inferred from record 0. `cancelled` is polled
    /// during pass 1.
    pub fn open(
        source: Box<dyn RecordSource>,
        boot: Option<&BootSector>,
        cancelled: &dyn Fn() -> bool,
    ) -> ForensicResult<Self> {
        let record_size = match boot {
            Some(b) => b.mft_record_size,
            None => infer_record_size(source.as_ref())?,
        };
        let len = source.len();
        let mut anomalies = Vec::new();
        if !len.is_multiple_of(u64::from(record_size)) {
            anomalies.push(NtfsAnomaly::MftFileSizeMismatch {
                length: len,
                record_size,
            });
        }
        let mut mft = Self {
            entry_count: len / u64::from(record_size),
            source,
            record_size,
            index: MftIndex::default(),
            paths: PathTable::default(),
            anomalies,
        };
        mft.build_index(cancelled)?;
        mft.paths = PathTable::build(&mft.index);
        Ok(mft)
    }

    pub fn record_size(&self) -> u32 {
        self.record_size
    }

    /// Number of record slots (including empty ones).
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn index(&self) -> &MftIndex {
        &self.index
    }

    /// Byte offset of `entry` in the source.
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
        if entry >= self.entry_count {
            return Ok(None);
        }
        let offset = self.offset_of(entry);
        let raw = self.source.read_vec(offset, self.record_size as usize)?;
        MftRecord::parse(entry, &raw).map_err(|e| error::corrupted(offset, e.to_string()))
    }

    fn build_index(&mut self, cancelled: &dyn Fn() -> bool) -> ForensicResult<()> {
        let count = usize::try_from(self.entry_count)
            .map_err(|_| error::invalid("MFT too large for this platform"))?;
        let mut index = MftIndex {
            slots: Vec::with_capacity(count),
            ..Default::default()
        };
        for entry in 0..self.entry_count {
            if entry % CANCEL_POLL == 0 && cancelled() {
                return Err(ForensicError::other(
                    "ntfs",
                    "cancelled while indexing the MFT".into(),
                ));
            }
            let slot = match self.record(entry) {
                Ok(None) => {
                    index.empty += 1;
                    Slot::Empty
                }
                Err(_) => {
                    index.invalid += 1;
                    Slot::Invalid
                }
                Ok(Some(rec)) => {
                    let has_name = rec
                        .attributes_of(crate::record::attribute::ATTR_FILE_NAME)
                        .next()
                        .is_some();
                    if !rec.header.in_use() && !rec.header.is_extension() && !has_name {
                        index.free += 1;
                        Slot::Free {
                            sequence: rec.header.sequence,
                        }
                    } else {
                        let slot = Slot::Present {
                            flags: rec.header.flags,
                            sequence: rec.header.sequence,
                            base: rec.header.base_reference,
                        };
                        self.index_record(&mut index, &rec, slot);
                        slot
                    }
                }
            };
            index.slots.push(slot);
        }
        index.finish();
        self.index = index;
        Ok(())
    }

    fn index_record(&self, index: &mut MftIndex, rec: &MftRecord, slot: Slot) {
        use crate::record::attribute::{AttrBody, ATTR_FILE_NAME, ATTR_STANDARD_INFORMATION};
        // Decode failures here are not lost: pass 2 re-parses the record and reports them as
        // `AttributeMalformed` anomalies on the entry.
        if rec.entry == 0 {
            index.volume_created = rec
                .attributes_of(ATTR_STANDARD_INFORMATION)
                .find_map(|a| a.resident_value())
                .and_then(|v| crate::attr::StdInfo::parse(v).ok())
                .map(|s| s.times.created)
                .filter(|&t| t != 0);
        }
        let names = rec
            .attributes_of(ATTR_FILE_NAME)
            .filter_map(|a| match &a.body {
                AttrBody::Resident { value, .. } => crate::attr::FileName::parse(value).ok(),
                AttrBody::NonResident(_) => None,
            });
        if slot.is_extension() {
            let base = rec.header.base_reference.entry;
            index.extensions.entry(base).or_default().push(rec.entry);
            let pending: Vec<_> = names
                .map(|n| index::DirName {
                    parent: n.parent,
                    name: n.name,
                    namespace: n.namespace,
                })
                .collect();
            if !pending.is_empty() {
                index.pending_names.entry(base).or_default().extend(pending);
            }
        } else if slot.is_directory() {
            for n in names {
                index.offer_dir_name(rec.entry, &n);
            }
        }
    }

    /// The file at `entry`, with its extension records merged. `Ok(None)` for an empty slot or an
    /// extension record that belongs to a live base (it is reported with its base).
    pub fn entry(&self, entry: u64) -> ForensicResult<Option<MftEntry>> {
        let Some(base) = self.record(entry)? else {
            return Ok(None);
        };
        let slot = self.index.slot(entry);
        if slot.is_extension() {
            if self
                .index
                .extension_belongs(slot, base.header.base_reference.entry)
            {
                return Ok(None);
            }
            let mut e = MftEntry::from_records(base, Vec::new());
            e.anomalies.push(NtfsAnomaly::ExtensionOrphan {
                base: e.header.base_reference,
            });
            return Ok(Some(e));
        }
        let mut extensions = Vec::new();
        if let Some(exts) = self.index.extensions.get(&entry) {
            for &x in exts {
                if !self.index.extension_belongs(self.index.slot(x), entry) {
                    continue;
                }
                // An unreadable extension was already counted in pass 1; the base is still evidence.
                if let Ok(Some(rec)) = self.record(x) {
                    extensions.push(rec);
                }
            }
        }
        Ok(Some(MftEntry::from_records(base, extensions)))
    }

    /// Every file in entry order. Empty slots and merged extensions are skipped; an unreadable
    /// record is one `Err` item and iteration continues.
    pub fn entries(&self) -> EntryIter<'_> {
        EntryIter { mft: self, next: 0 }
    }

    /// Every path of every hard link of `entry` (DOS duplicates dropped), sorted.
    pub fn paths_of(&self, entry: &MftEntry) -> Vec<ResolvedPath> {
        let mut out: Vec<ResolvedPath> = entry
            .link_names()
            .into_iter()
            .map(|n| {
                self.paths
                    .resolve(&self.index, n.parent, &n.name, entry.reference.entry)
            })
            .collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out.dedup_by(|a, b| a.path == b.path);
        out
    }

    /// The path of the primary name.
    pub fn path_of(&self, entry: &MftEntry) -> ResolvedPath {
        match entry.primary_name() {
            Some(n) => self
                .paths
                .resolve(&self.index, n.parent, &n.name, entry.reference.entry),
            None if entry.reference.entry == ROOT_ENTRY => {
                self.paths
                    .resolve(&self.index, FileRef::default(), "", ROOT_ENTRY)
            }
            None => ResolvedPath {
                path: format!("{}\\[{}]", paths::ORPHAN_ROOT, entry.reference),
                status: PathStatus::NoName,
                anomaly: None,
            },
        }
    }

    /// Resolves the path of any `(parent, name)` pair, e.g. a name carved from `$I30` slack or a
    /// USN record.
    pub fn resolve(&self, parent: FileRef, name: &str) -> ResolvedPath {
        self.paths.resolve(&self.index, parent, name, u64::MAX)
    }

    /// Resolves a directory reference to its own path (e.g. a USN parent reference).
    pub fn directory_path(&self, dir: FileRef) -> Option<ResolvedPath> {
        if dir.entry == ROOT_ENTRY {
            return Some(ResolvedPath {
                path: "\\".into(),
                status: PathStatus::Resolved,
                anomaly: None,
            });
        }
        let name = self.index.dir_names.get(&dir.entry)?;
        let slot = self.index.slot(dir.entry);
        let mut p = self
            .paths
            .resolve(&self.index, name.parent, &name.name, dir.entry);
        if slot.sequence() != Some(dir.sequence) {
            p.status = p.status.max(PathStatus::StaleParent);
        }
        Some(p)
    }
}

/// Iterator returned by [`Mft::entries`].
pub struct EntryIter<'a> {
    mft: &'a Mft,
    next: u64,
}

impl Iterator for EntryIter<'_> {
    type Item = ForensicResult<MftEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.mft.entry_count {
            let n = self.next;
            self.next += 1;
            match self.mft.index.slot(n) {
                Slot::Empty | Slot::Free { .. } => continue,
                Slot::Invalid | Slot::Present { .. } => {}
            }
            match self.mft.entry(n) {
                Ok(Some(e)) => return Some(Ok(e)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }
}

/// Infers the record size of a loose `$MFT` from record 0 (header allocated size and fixup
/// count must agree), falling back to finding a second `FILE` signature at 1 KiB or 4 KiB.
pub fn infer_record_size(source: &dyn RecordSource) -> ForensicResult<u32> {
    let mut head = vec![0u8; 8192];
    let n = source.read_at(0, &mut head)?;
    head.truncate(n);
    let sig = |at: usize| {
        head.get(at..at + 4)
            .is_some_and(|s| s == b"FILE" || s == b"BAAD")
    };
    if sig(0) && head.len() >= 32 {
        let usa_count = u16::from_le_bytes([head[6], head[7]]);
        let alloc = u32::from_le_bytes([head[28], head[29], head[30], head[31]]);
        if (MIN_RECORD_SIZE..=MAX_RECORD_SIZE).contains(&alloc)
            && alloc.is_power_of_two()
            && u32::from(usa_count.saturating_sub(1)) * 512 == alloc
        {
            return Ok(alloc);
        }
    }
    for size in [1024usize, 4096] {
        if sig(size) {
            return Ok(size as u32);
        }
    }
    Err(error::invalid(
        "cannot infer the MFT record size: record 0 and the next record are not FILE records",
    ))
}

#[cfg(test)]
mod tests;
