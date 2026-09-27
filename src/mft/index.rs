//! Pass 1 over the MFT: a compact table of every entry, enough to merge extension records and
//! resolve directory paths without holding the records in memory.

use std::collections::BTreeMap;

use crate::attr::{FileName, Namespace};
use crate::reference::FileRef;

/// What pass 1 found at one MFT position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Never initialised (all zero).
    Empty,
    /// Not a readable `FILE`/`BAAD` record.
    Invalid,
    /// A formatted record that holds no file: not in use, not an extension, no `$FILE_NAME`.
    /// NTFS pre-formats MFT records like this; they are not deleted files.
    Free { sequence: u16 },
    Present {
        flags: u16,
        sequence: u16,
        /// Non-zero for an extension record.
        base: FileRef,
    },
}

impl Slot {
    pub fn in_use(self) -> bool {
        matches!(self, Slot::Present { flags, .. } if flags & crate::record::header::FLAG_IN_USE != 0)
    }

    pub fn is_directory(self) -> bool {
        matches!(self, Slot::Present { flags, .. } if flags & crate::record::header::FLAG_DIRECTORY != 0)
    }

    pub fn is_extension(self) -> bool {
        matches!(self, Slot::Present { base, .. } if !base.is_zero())
    }

    pub fn sequence(self) -> Option<u16> {
        match self {
            Slot::Present { sequence, .. } => Some(sequence),
            _ => None,
        }
    }
}

/// A directory's name as used for path building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirName {
    pub parent: FileRef,
    pub name: String,
    pub namespace: Namespace,
}

/// Pass 1 result.
#[derive(Debug, Default)]
pub struct MftIndex {
    pub slots: Vec<Slot>,
    /// Base entry -> extension entries that name it.
    pub extensions: BTreeMap<u64, Vec<u64>>,
    /// Best name of every entry that is (or whose base is) a directory.
    pub dir_names: BTreeMap<u64, DirName>,
    /// Names found in extension records, attached to their base after the pass.
    pub pending_names: BTreeMap<u64, Vec<DirName>>,
    pub empty: u64,
    pub invalid: u64,
    pub free: u64,
    /// `$SI` creation FILETIME of entry 0 (`$MFT`): approximately when the volume was formatted.
    pub volume_created: Option<u64>,
}

impl MftIndex {
    pub fn slot(&self, entry: u64) -> Slot {
        usize::try_from(entry)
            .ok()
            .and_then(|i| self.slots.get(i))
            .copied()
            .unwrap_or(Slot::Invalid)
    }

    /// Offers a candidate name for `entry`; keeps the best-ranked namespace.
    pub fn offer_dir_name(&mut self, entry: u64, name: &FileName) {
        let candidate = DirName {
            parent: name.parent,
            name: name.name.clone(),
            namespace: name.namespace,
        };
        match self.dir_names.get(&entry) {
            Some(existing) if existing.namespace.rank() <= candidate.namespace.rank() => {}
            _ => {
                self.dir_names.insert(entry, candidate);
            }
        }
    }

    /// Attaches names found in extension records to directory bases.
    pub fn finish(&mut self) {
        let pending = std::mem::take(&mut self.pending_names);
        for (base, names) in pending {
            if !self.slot(base).is_directory() {
                continue;
            }
            for n in names {
                let as_fn = FileName {
                    parent: n.parent,
                    times: Default::default(),
                    allocated_size: 0,
                    real_size: 0,
                    flags: 0,
                    reparse_or_ea: 0,
                    namespace: n.namespace,
                    name: n.name,
                };
                self.offer_dir_name(base, &as_fn);
            }
        }
    }

    /// Whether extension `ext` belongs to base `base_entry`: same sequence, or both freed and the
    /// base's sequence bumped by one on deletion.
    pub fn extension_belongs(&self, ext: Slot, base_entry: u64) -> bool {
        let (Slot::Present { base: link, .. }, base_slot) = (ext, self.slot(base_entry)) else {
            return false;
        };
        let Slot::Present {
            sequence,
            base: base_of_base,
            ..
        } = base_slot
        else {
            return false;
        };
        if !base_of_base.is_zero() || link.entry != base_entry {
            return false;
        }
        sequence == link.sequence
            || (!base_slot.in_use() && !ext.in_use() && sequence == link.sequence.wrapping_add(1))
    }
}
