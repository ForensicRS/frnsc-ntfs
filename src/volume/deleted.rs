//! Deleted-file content recovery through a strict admission gate.
//!
//! A deleted MFT entry still describes where its content was. That content is only returned when
//! nothing contradicts that it is still there:
//!
//! 1. the record has a `FILE` signature, is not in use, and passed its fixup check (a torn
//!    record's run list cannot be trusted; its metadata is still reported);
//! 2. resident content is admitted as is (it lives in the record itself, which is not reused);
//! 3. non-resident content needs a run list that decodes inside the volume, and **every stored
//!    cluster must still be free in `$Bitmap`**; one reallocated cluster refuses the whole file
//!    (`ClustersReallocated`, no bytes);
//! 4. no other deleted candidate may claim the same clusters (`DeletedCrossClaim`, both refused);
//! 5. compressed content must decompress within its compression units.
//!
//! What cannot be detected: clusters that were reused *and freed again* since the deletion. That
//! is why recovered content is graded `Recovery::DeletedMetadata`, never `Allocated`.

use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::recovery::{Recovered, RecoveryReport};
use forensic_rs::traits::vfs::{DeletedEntry, DeletedFiles, VMetadata};

use super::fs::{metadata_of, NtfsFs};
use super::stream::SourceFile;
use crate::anomaly::NtfsAnomaly;
use crate::mft::{MftEntry, PathStatus, ResolvedPath};
use crate::reference::FileRef;
use crate::runlist::Run;

/// What can be said about a deleted file's content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentStatus {
    /// Content is resident in the record.
    Resident,
    /// Every stored cluster is still free and unclaimed: content returned by `open_deleted`.
    Recoverable,
    /// Some clusters are allocated again: content refused.
    Reallocated { clusters: u64 },
    /// Clusters also claimed by another deleted file: content refused.
    CrossClaimed { other: FileRef },
    /// The file had no unnamed `$DATA` (a directory, or an empty file).
    NoData,
    /// The metadata cannot back a read (torn record, bad run list, unsupported compression).
    Unreadable(String),
}

impl ContentStatus {
    pub fn name(&self) -> &'static str {
        match self {
            ContentStatus::Resident => "resident",
            ContentStatus::Recoverable => "recoverable",
            ContentStatus::Reallocated { .. } => "reallocated",
            ContentStatus::CrossClaimed { .. } => "cross_claimed",
            ContentStatus::NoData => "no_data",
            ContentStatus::Unreadable(_) => "unreadable",
        }
    }

    pub fn is_readable(&self) -> bool {
        matches!(self, ContentStatus::Resident | ContentStatus::Recoverable)
    }
}

/// A deleted file found in the MFT.
#[derive(Debug, Clone)]
pub struct DeletedFile {
    pub reference: FileRef,
    /// The record's own primary `$FILE_NAME`, known even when its path can't be rebuilt.
    pub name: Option<String>,
    pub path: ResolvedPath,
    pub metadata: VMetadata,
    pub content: ContentStatus,
    pub anomalies: Vec<NtfsAnomaly>,
}

struct Candidate {
    entry: MftEntry,
    runs: Vec<Run>,
    status: ContentStatus,
    anomalies: Vec<NtfsAnomaly>,
}

/// One deleted-file scan: every deleted base record and the scan counters.
pub(crate) type DeletedScan = (Vec<Recovered<DeletedFile>>, RecoveryReport);

impl NtfsFs {
    /// Every deleted base record, with the verdict of the content gate. Unreadable records are
    /// counted in the report, not returned. The scan runs once per `NtfsFs`; later calls reuse it.
    pub fn deleted_files(&self) -> ForensicResult<DeletedScan> {
        Ok(self.cached_scan()?.as_ref().clone())
    }

    fn cached_scan(&self) -> ForensicResult<Arc<DeletedScan>> {
        let mut cache = self
            .deleted_scan
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(scan) = cache.as_ref() {
            return Ok(Arc::clone(scan));
        }
        // A failed scan is not cached: the next call tries again.
        let scan = Arc::new(self.scan_deleted()?);
        *cache = Some(Arc::clone(&scan));
        Ok(scan)
    }

    fn scan_deleted(&self) -> ForensicResult<DeletedScan> {
        let vol = self.volume();
        let bitmap = vol.bitmap()?;
        let mut report = RecoveryReport::default();
        let mut candidates: Vec<Candidate> = Vec::new();
        for item in vol.mft.entries() {
            report.units_scanned += 1;
            let e = match item {
                Ok(e) => e,
                Err(err) => {
                    forensic_rs::debug!("deleted scan: unreadable record: {}", err);
                    report.unreadable += 1;
                    continue;
                }
            };
            if e.in_use() || e.header.is_extension() {
                continue;
            }
            report.candidates_found += 1;
            let mut anomalies = Vec::new();
            let (status, runs) = match e.data() {
                None => (ContentStatus::NoData, Vec::new()),
                Some(_) if !e.fixup.is_ok() => {
                    (ContentStatus::Unreadable("torn record".into()), Vec::new())
                }
                Some(d) if d.is_resident() => (ContentStatus::Resident, Vec::new()),
                Some(d) => match vol.decode_segments(&d.segments) {
                    Err(err) => (ContentStatus::Unreadable(err.to_string()), Vec::new()),
                    Ok(rl) => {
                        let reallocated: u64 = rl
                            .runs
                            .iter()
                            .filter_map(|r| r.lcn.map(|l| (l, r.length)))
                            .flat_map(|(l, n)| l..l + n)
                            .filter(|&lcn| bitmap.is_allocated(lcn) != Some(false))
                            .count() as u64;
                        let covered = rl.total_clusters();
                        let expected = d
                            .non_resident
                            .as_ref()
                            .map_or(0, |nr| nr.allocated_size.div_ceil(vol.cluster_size()));
                        if reallocated > 0 {
                            anomalies.push(NtfsAnomaly::ClustersReallocated {
                                clusters: reallocated,
                            });
                            (
                                ContentStatus::Reallocated {
                                    clusters: reallocated,
                                },
                                Vec::new(),
                            )
                        } else if covered < expected {
                            (
                                ContentStatus::Unreadable(
                                    "run list shorter than the allocated size".into(),
                                ),
                                Vec::new(),
                            )
                        } else {
                            (ContentStatus::Recoverable, rl.runs)
                        }
                    }
                },
            };
            candidates.push(Candidate {
                entry: e,
                runs,
                status,
                anomalies,
            });
        }
        cross_claims(&mut candidates);
        let mut out = Vec::with_capacity(candidates.len());
        for c in candidates {
            if c.status.is_readable() {
                report.admitted += 1;
            } else {
                report.rejected += 1;
            }
            let attribute = c.entry.data().map_or(0, |d| d.attribute_id);
            let locus = Locus::Ntfs {
                entry: c.entry.reference.entry,
                sequence: c.entry.reference.sequence,
                attribute,
                offset: 0,
            };
            let file = DeletedFile {
                reference: c.entry.reference,
                name: c.entry.primary_name().map(|n| n.name.clone()),
                path: vol.mft.path_of(&c.entry),
                metadata: metadata_of(&c.entry),
                content: c.status,
                anomalies: c.anomalies,
            };
            out.push(Recovered::new(file, Recovery::DeletedMetadata, locus));
        }
        Ok((out, report))
    }

    /// Opens a deleted file's content if the gate admitted it.
    pub fn open_deleted(&self, f: &DeletedFile) -> ForensicResult<Recovered<Box<dyn VirtualFile>>> {
        if !f.content.is_readable() {
            return Err(ForensicError::other(
                "ntfs",
                format!(
                    "content of deleted {} not recoverable: {}",
                    f.reference,
                    f.content.name()
                ),
            ));
        }
        let vol = self.volume();
        let e = vol.mft.entry(f.reference.entry)?.ok_or_else(|| {
            ForensicError::missing_data(
                "mft record",
                "deleted record vanished since the scan".into(),
            )
        })?;
        if e.reference != f.reference || e.in_use() {
            return Err(ForensicError::other(
                "ntfs",
                format!("record {} changed since the scan", f.reference),
            ));
        }
        let src = vol.open_data(&e, "")?;
        let attribute = e.data().map_or(0, |d| d.attribute_id);
        let file: Box<dyn VirtualFile> =
            Box::new(SourceFile::new(Arc::clone(&src), f.metadata.clone()));
        Ok(Recovered::new(
            file,
            Recovery::DeletedMetadata,
            Locus::Ntfs {
                entry: f.reference.entry,
                sequence: f.reference.sequence,
                attribute,
                offset: 0,
            },
        ))
    }
}

/// The generic view of [`NtfsFs::deleted_files`], so tools reach deleted files through any
/// wrapper (`ContainerFs`, a chroot) without knowing the backend. `id` is the file reference
/// ([`FileRef::raw`]). What this view leaves out -- the [`PathStatus`] of a path that could not be
/// rebuilt, and the [`NtfsAnomaly`]s -- stays available through `deleted_files`.
///
/// `scope` must be the volume root (`""` or `"/"`): an `NtfsFs` is one volume.
impl DeletedFiles for NtfsFs {
    fn deleted_entries(&self, scope: &FPath) -> ForensicResult<DeletedEntriesScan> {
        check_scope(scope)?;
        let scan = self.cached_scan()?;
        let entries = scan
            .0
            .iter()
            .cloned()
            .map(|r| r.map(|f| to_entry(&f)))
            .collect();
        Ok((entries, scan.1))
    }

    fn open_deleted(
        &self,
        scope: &FPath,
        id: u64,
    ) -> ForensicResult<Recovered<Box<dyn VirtualFile>>> {
        check_scope(scope)?;
        let scan = self.cached_scan()?;
        let reference = FileRef::from_raw(id);
        let file = scan
            .0
            .iter()
            .map(|r| r.value())
            .find(|f| f.reference == reference)
            .ok_or_else(|| {
                ForensicError::other("ntfs", format!("no deleted record {reference} in the scan"))
            })?;
        NtfsFs::open_deleted(self, file)
    }
}

type DeletedEntriesScan = (Vec<Recovered<DeletedEntry>>, RecoveryReport);

fn check_scope(scope: &FPath) -> ForensicResult<()> {
    match scope.as_str() {
        "" | "/" | "\\" => Ok(()),
        other => Err(ForensicError::other(
            "ntfs",
            format!("an NTFS volume has no nested scope '{other}'; use the volume root"),
        )),
    }
}

/// A path only when every link to the root was verified; never the `$Orphan` re-rooting.
fn to_entry(f: &DeletedFile) -> DeletedEntry {
    let mut entry = DeletedEntry::new(f.reference.raw(), f.metadata.clone())
        .with_content(f.content.is_readable(), f.content.name());
    if matches!(
        f.path.status,
        PathStatus::Resolved | PathStatus::ParentDeleted
    ) {
        entry = entry.with_path(f.path.path.trim_start_matches('\\').replace('\\', "/"));
    }
    if let Some(name) = &f.name {
        entry = entry.with_name(name.clone());
    }
    entry
}

/// Marks both sides of any overlap between recoverable candidates.
fn cross_claims(c: &mut [Candidate]) {
    let mut spans: Vec<(u64, u64, usize)> = Vec::new();
    for (i, cand) in c.iter().enumerate() {
        if cand.status != ContentStatus::Recoverable {
            continue;
        }
        for r in &cand.runs {
            if let Some(l) = r.lcn {
                spans.push((l, l + r.length, i));
            }
        }
    }
    spans.sort_unstable();
    let mut hits: Vec<(usize, usize)> = Vec::new();
    for w in 0..spans.len() {
        let (_, end, i) = spans[w];
        for &(s2, _, j) in &spans[w + 1..] {
            if s2 >= end {
                break;
            }
            if i != j {
                hits.push((i, j));
            }
        }
    }
    for (i, j) in hits {
        let (ri, rj) = (c[i].entry.reference, c[j].entry.reference);
        for (k, other) in [(i, rj), (j, ri)] {
            if c[k].status == ContentStatus::Recoverable {
                c[k].status = ContentStatus::CrossClaimed { other };
                c[k].anomalies
                    .push(NtfsAnomaly::DeletedCrossClaim { other });
            }
        }
    }
}

/// Largest `$INDEX_ALLOCATION` read for slack carving.
pub const MAX_INDEX_ALLOCATION: u64 = 64 * 1024 * 1024;

impl NtfsFs {
    /// Carves deleted entries from a directory's `$I30` slack (`$INDEX_ROOT` and every `INDX`
    /// record of `$INDEX_ALLOCATION`), keeping only entries whose parent is this directory.
    pub fn index_slack(
        &self,
        dir: &FPath,
    ) -> ForensicResult<(
        Vec<Recovered<crate::indx::SlackEntry>>,
        crate::recovery::RecoveryStats,
    )> {
        use crate::indx::IndexNode;
        use crate::record::attribute::{ATTR_INDEX_ALLOCATION, ATTR_INDEX_ROOT};
        let vol = self.volume();
        let r = vol.lookup(dir)?;
        let e = vol.entry(r)?;
        if !e.is_directory() {
            return Err(ForensicError::other(
                "ntfs",
                format!("{} is not a directory", dir.as_str()),
            ));
        }
        let mut stats = crate::recovery::RecoveryStats::default();
        let mut out = Vec::new();
        if let Some(root) = &e.index_root {
            match IndexNode::parse_root(root) {
                Ok(node) => {
                    out.extend(node.carve_slack(e.reference, ATTR_INDEX_ROOT as u16, &mut stats))
                }
                Err(_) => stats.unreadable += 1,
            }
        }
        if let Some(nr) = &e.index_allocation {
            let rl = vol.decode_segments(&[(nr.starting_vcn, nr.runlist.clone())])?;
            let size = nr.data_size.min(MAX_INDEX_ALLOCATION);
            let src = super::stream::NonResidentStream::new(
                Arc::clone(&vol.media),
                vol.cluster_size(),
                &rl,
                size,
                nr.initialized_size.min(size),
            );
            let rs = vol.boot.index_record_size as usize;
            let bytes = crate::source::RecordSource::read_vec(&src, 0, size as usize)?;
            for (i, chunk) in bytes.chunks(rs).enumerate() {
                match IndexNode::parse_indx(chunk) {
                    Ok(Some(mut node)) => {
                        node.stream_offset = (i * rs) as u64;
                        out.extend(node.carve_slack(
                            e.reference,
                            ATTR_INDEX_ALLOCATION as u16,
                            &mut stats,
                        ));
                    }
                    Ok(None) => {}
                    Err(_) => stats.unreadable += 1,
                }
            }
        }
        Ok((out, stats))
    }
}
