//! Full path reconstruction from `$FILE_NAME` parent references.
//!
//! Rules (in this order, per link from a name to its parent):
//! * parent sequence equals the reference's sequence: same directory (deleted if not in use);
//! * parent not in use and its sequence is the reference's + 1: the same directory, deleted
//!   (NTFS bumps the sequence when it frees a record);
//! * any other sequence: the directory was deleted and its record reused -> `StaleParent`,
//!   the path is re-rooted under `\$Orphan`;
//! * parent missing, unreadable or not a directory -> `Orphan`, re-rooted under `\$Orphan`.
//!
//! Cycles and chains deeper than [`MAX_DEPTH`] stop the walk and are reported.

use std::collections::{BTreeMap, BTreeSet};

use crate::anomaly::NtfsAnomaly;
use crate::mft::index::{MftIndex, Slot};
use crate::reference::{FileRef, ROOT_ENTRY};

/// Deepest parent chain followed.
pub const MAX_DEPTH: usize = 512;
/// Prefix of a path whose chain could not be followed to the root.
pub const ORPHAN_ROOT: &str = "\\$Orphan";

/// How far the path could be trusted, from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathStatus {
    /// Every link verified up to the root.
    Resolved,
    /// Verified, but some directory on the way is deleted.
    ParentDeleted,
    /// A directory on the way has no name.
    NoName,
    /// A parent is missing, unreadable or not a directory.
    Orphan,
    /// A parent record was reused (sequence mismatch).
    StaleParent,
    /// The chain is deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The chain loops.
    Cycle,
}

impl PathStatus {
    pub fn name(self) -> &'static str {
        match self {
            PathStatus::Resolved => "resolved",
            PathStatus::ParentDeleted => "parent_deleted",
            PathStatus::NoName => "no_name",
            PathStatus::Orphan => "orphan",
            PathStatus::StaleParent => "stale_parent",
            PathStatus::TooDeep => "too_deep",
            PathStatus::Cycle => "cycle",
        }
    }
}

/// A resolved path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Volume-relative path with `\` separators, e.g. `\Users\bob\a.txt`.
    pub path: String,
    pub status: PathStatus,
    /// Anomaly on the direct link from the name to its parent, if any.
    pub anomaly: Option<NtfsAnomaly>,
}

/// Result of checking one parent link.
enum Link {
    Ok { deleted: bool },
    Broken(PathStatus, NtfsAnomaly),
}

fn check_link(index: &MftIndex, parent: FileRef) -> Link {
    let slot = index.slot(parent.entry);
    let Slot::Present { sequence, .. } = slot else {
        return Link::Broken(PathStatus::Orphan, NtfsAnomaly::ParentMissing { parent });
    };
    if slot.is_extension() || !slot.is_directory() {
        return Link::Broken(
            PathStatus::Orphan,
            NtfsAnomaly::ParentNotDirectory { parent },
        );
    }
    if sequence == parent.sequence {
        return Link::Ok {
            deleted: !slot.in_use(),
        };
    }
    if !slot.in_use() && sequence == parent.sequence.wrapping_add(1) {
        return Link::Ok { deleted: true };
    }
    Link::Broken(
        PathStatus::StaleParent,
        NtfsAnomaly::ParentStale {
            parent,
            found_sequence: sequence,
        },
    )
}

#[derive(Debug, Clone)]
struct DirPath {
    path: String,
    status: PathStatus,
}

/// Precomputed directory paths.
#[derive(Debug, Default)]
pub struct PathTable {
    dirs: BTreeMap<u64, DirPath>,
}

impl PathTable {
    /// Resolves every named directory once, iteratively (no recursion on evidence).
    pub fn build(index: &MftIndex) -> Self {
        let mut t = Self::default();
        let entries: Vec<u64> = index.dir_names.keys().copied().collect();
        for e in entries {
            t.dir_path(index, e);
        }
        t
    }

    fn dir_path(&mut self, index: &MftIndex, start: u64) -> DirPath {
        // Walk up until the root, a memoised directory, or a broken link.
        let mut chain: Vec<(u64, String, PathStatus)> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut cur = start;
        let base = loop {
            if cur == ROOT_ENTRY {
                break DirPath {
                    path: String::new(),
                    status: PathStatus::Resolved,
                };
            }
            if let Some(p) = self.dirs.get(&cur) {
                break p.clone();
            }
            if !seen.insert(cur) {
                break orphan(PathStatus::Cycle);
            }
            if chain.len() >= MAX_DEPTH {
                break orphan(PathStatus::TooDeep);
            }
            let Some(dn) = index.dir_names.get(&cur) else {
                break orphan(PathStatus::NoName);
            };
            match check_link(index, dn.parent) {
                Link::Ok { deleted } => {
                    let st = if deleted {
                        PathStatus::ParentDeleted
                    } else {
                        PathStatus::Resolved
                    };
                    chain.push((cur, dn.name.clone(), st));
                    cur = dn.parent.entry;
                }
                Link::Broken(st, _) => {
                    chain.push((cur, dn.name.clone(), PathStatus::Resolved));
                    break orphan(st);
                }
            }
        };
        let mut acc = base;
        while let Some((entry, name, link_status)) = chain.pop() {
            acc = DirPath {
                path: format!("{}\\{}", acc.path, name),
                status: acc.status.max(link_status),
            };
            self.dirs.entry(entry).or_insert_with(|| acc.clone());
        }
        acc
    }

    /// Resolves the path of a name whose parent is `parent`.
    pub fn resolve(
        &self,
        index: &MftIndex,
        parent: FileRef,
        name: &str,
        own_entry: u64,
    ) -> ResolvedPath {
        if own_entry == ROOT_ENTRY {
            return ResolvedPath {
                path: "\\".to_string(),
                status: PathStatus::Resolved,
                anomaly: None,
            };
        }
        match check_link(index, parent) {
            Link::Ok { deleted } => {
                let (prefix, status) = if parent.entry == ROOT_ENTRY {
                    (String::new(), PathStatus::Resolved)
                } else if parent.entry == own_entry {
                    (ORPHAN_ROOT.to_string(), PathStatus::Cycle)
                } else {
                    match self.dirs.get(&parent.entry) {
                        Some(d) => (d.path.clone(), d.status),
                        None => (ORPHAN_ROOT.to_string(), PathStatus::NoName),
                    }
                };
                let link = if deleted {
                    PathStatus::ParentDeleted
                } else {
                    PathStatus::Resolved
                };
                ResolvedPath {
                    path: format!("{prefix}\\{name}"),
                    status: status.max(link),
                    anomaly: (status == PathStatus::Cycle && parent.entry == own_entry)
                        .then_some(NtfsAnomaly::ParentCycle { at: own_entry }),
                }
            }
            Link::Broken(status, anomaly) => ResolvedPath {
                path: format!("{ORPHAN_ROOT}\\{name}"),
                status,
                anomaly: Some(anomaly),
            },
        }
    }
}

fn orphan(status: PathStatus) -> DirPath {
    DirPath {
        path: ORPHAN_ROOT.to_string(),
        status,
    }
}
