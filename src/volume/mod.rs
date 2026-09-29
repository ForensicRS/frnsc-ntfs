//! A whole NTFS volume (feature `volume`): boot sector, the `$MFT` read through its own data
//! runs, directory tree, attribute streams, `$Bitmap`, and deleted-content recovery.

pub mod deleted;
pub mod format;
pub mod fs;
pub mod stream;

use std::collections::BTreeMap;
use std::io::{Read, Seek};
use std::sync::{Arc, OnceLock};

use forensic_rs::prelude::*;

pub use format::NtfsFormatFactory;
pub use fs::NtfsFs;

use crate::anomaly::NtfsAnomaly;
use crate::attr::attr_list::{self, MAX_ATTRIBUTE_LIST};
use crate::boot::{BootSector, BOOT_SECTOR_SIZE};
use crate::error;
use crate::mft::mirror::MirrorComparison;
use crate::mft::{Mft, MftEntry, MftMirr, Slot};
use crate::record::attribute::{AttrBody, ATTR_ATTRIBUTE_LIST, ATTR_DATA};
use crate::record::MftRecord;
use crate::reference::{FileRef, ROOT_ENTRY};
use crate::runlist::{self, Runlist};
use crate::source::{BytesSource, RecordSource, StreamSource};
use stream::{CompressedStream, NonResidentStream};

/// `$Bitmap` metafile entry.
pub const BITMAP_ENTRY: u64 = 6;
/// Largest `$Bitmap` loaded (256 MiB covers 8 TiB of 4 KiB clusters).
pub const MAX_BITMAP: u64 = 256 * 1024 * 1024;
/// Rounds of `$MFT` extension-record discovery.
const MFT_BOOTSTRAP_ROUNDS: usize = 8;

/// One directory child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    pub name: String,
    pub reference: FileRef,
    pub is_dir: bool,
}

/// Live directory tree, built from `$FILE_NAME` parent references of in-use records.
#[derive(Debug, Default)]
pub struct Tree {
    pub children: BTreeMap<u64, Vec<Child>>,
    /// Records that could not be read while building the tree (their names are missing).
    pub unreadable: u64,
}

/// Allocation state of every cluster, from `$Bitmap`.
#[derive(Debug, Clone)]
pub struct ClusterBitmap {
    bits: Vec<u8>,
    clusters: u64,
}

impl ClusterBitmap {
    /// `None` for a cluster outside the bitmap.
    pub fn is_allocated(&self, lcn: u64) -> Option<bool> {
        if lcn >= self.clusters {
            return None;
        }
        let byte = *self.bits.get(usize::try_from(lcn / 8).ok()?)?;
        Some(byte & (1 << (lcn % 8)) != 0)
    }

    /// Maximal runs of free clusters `(lcn, length)`.
    pub fn free_runs(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut start = None;
        for lcn in 0..self.clusters {
            let free = self.is_allocated(lcn) == Some(false);
            match (free, start) {
                (true, None) => start = Some(lcn),
                (false, Some(s)) => {
                    out.push((s, lcn - s));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            out.push((s, self.clusters - s));
        }
        out
    }
}

/// An opened NTFS volume.
pub struct Volume {
    pub media: Arc<dyn RecordSource>,
    pub boot: BootSector,
    pub mft: Mft,
    pub mft_runs: Runlist,
    /// Volume-level anomalies (boot sector, truncation, `$MFTMirr`, `$MFT` run list).
    pub anomalies: Vec<NtfsAnomaly>,
    /// The `$MFTMirr` cross-check, record by record with both sides, or why it could not run.
    pub mirror: Result<MirrorComparison, String>,
    tree: OnceLock<Tree>,
    bitmap: OnceLock<Result<ClusterBitmap, String>>,
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume")
            .field("boot", &self.boot)
            .field("mft", &self.mft)
            .finish_non_exhaustive()
    }
}

impl Volume {
    /// Opens a volume image from any `Read + Seek` (library use, no pipeline).
    pub fn from_reader<R: Read + Seek + Send + 'static>(reader: R) -> ForensicResult<Self> {
        Self::open(Arc::new(StreamSource::new(reader)?), &|| false)
    }

    /// Opens a volume from a positioned source.
    pub fn open(
        media: Arc<dyn RecordSource>,
        cancelled: &dyn Fn() -> bool,
    ) -> ForensicResult<Self> {
        let (boot, mut anomalies) = read_boot(media.as_ref())?;
        let declared = boot.volume_size();
        // The backup boot sector lives in the sector after the declared volume.
        let expected = declared.saturating_add(u64::from(boot.bytes_per_sector));
        if media.len() < expected {
            anomalies.push(NtfsAnomaly::VolumeTruncated {
                declared: expected,
                actual: media.len(),
            });
        }
        let rec0_offset = boot
            .mft_lcn
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| error::invalid("MFT LCN overflows"))?;
        let raw0 = media.read_vec(rec0_offset, boot.mft_record_size as usize)?;
        let rec0 = MftRecord::parse(0, &raw0)
            .map_err(|e| error::corrupted(rec0_offset, format!("$MFT record 0: {e}")))?
            .ok_or_else(|| error::corrupted(rec0_offset, "$MFT record 0 is empty"))?;
        let (mft_runs, data_size, initialized) = mft_data(&media, &boot, &rec0, &mut anomalies)?;
        let mft_stream = NonResidentStream::new(
            Arc::clone(&media),
            boot.cluster_size,
            &mft_runs,
            data_size,
            initialized,
        );
        let mft = Mft::open(Box::new(mft_stream), Some(&boot), cancelled)?;
        let mut vol = Self {
            media,
            boot,
            mft,
            mft_runs,
            anomalies,
            mirror: Err("not checked".to_string()),
            tree: OnceLock::new(),
            bitmap: OnceLock::new(),
        };
        vol.mirror = vol.check_mirror();
        match &vol.mirror {
            Ok(c) => vol.anomalies.extend(c.anomaly()),
            // Not a finding by itself: a volume too short to hold its own mirror already carries
            // `VolumeTruncated`. The reason stays on `Volume::mirror` for the caller.
            Err(why) => forensic_rs::warn!("$MFTMirr not checked: {}", why),
        }
        Ok(vol)
    }

    /// Cross-checks the `$MFTMirr` at the LCN the **boot sector** declares against the `$MFT`.
    ///
    /// The locator is deliberately the boot sector's: asking the `$MFT` where its own mirror lives
    /// would make the check circular. Each side's raw record bytes are kept on the result.
    fn check_mirror(&self) -> Result<MirrorComparison, String> {
        let mirr = MftMirr::at_boot_lcn(Arc::clone(&self.media), &self.boot)
            .map_err(|e| format!("$MFTMirr at LCN {}: {e}", self.boot.mftmirr_lcn))?;
        Ok(mirr.compare_with(&self.mft))
    }

    pub fn cluster_size(&self) -> u64 {
        self.boot.cluster_size
    }

    /// The live directory tree (built on first use).
    pub fn tree(&self) -> &Tree {
        self.tree.get_or_init(|| build_tree(&self.mft))
    }

    /// Resolves a path (`/` or `\` separated, case-insensitive; an exact-case match wins).
    pub fn lookup(&self, path: &FPath) -> ForensicResult<FileRef> {
        let root_seq = self
            .mft
            .index()
            .slot(ROOT_ENTRY)
            .sequence()
            .unwrap_or(ROOT_ENTRY as u16);
        let mut cur = FileRef::new(ROOT_ENTRY, root_seq);
        for comp in path
            .as_str()
            .split(['/', '\\'])
            .filter(|c| !c.is_empty() && *c != ".")
        {
            let kids = self.tree().children.get(&cur.entry);
            let found = kids.and_then(|k| {
                k.iter().find(|c| c.name == comp).or_else(|| {
                    k.iter()
                        .find(|c| c.name.to_uppercase() == comp.to_uppercase())
                })
            });
            match found {
                Some(c) => cur = c.reference,
                None => return Err(ForensicError::path_not_found(path)),
            }
        }
        Ok(cur)
    }

    /// The merged entry for a live reference.
    pub fn entry(&self, r: FileRef) -> ForensicResult<MftEntry> {
        self.mft.entry(r.entry)?.ok_or_else(|| {
            error::corrupted(self.mft.offset_of(r.entry), format!("entry {r} is empty"))
        })
    }

    /// Opens a `$DATA` stream (`""` = unnamed) of an entry.
    pub fn open_data(&self, e: &MftEntry, name: &str) -> ForensicResult<Arc<dyn RecordSource>> {
        let s = e.streams.iter().find(|s| s.name == name).ok_or_else(|| {
            ForensicError::missing_data(
                "data stream",
                format!("{}: no stream named '{name}'", e.reference).into(),
            )
        })?;
        if let Some(v) = &s.resident {
            return Ok(Arc::new(BytesSource(v.clone())));
        }
        let nr = s.non_resident.as_ref().ok_or_else(|| {
            error::corrupted(
                0,
                format!("{}: stream '{}' has no first segment", e.reference, name),
            )
        })?;
        let rl = self.decode_segments(&s.segments)?;
        if s.is_compressed() && nr.compression_unit != 0 {
            Ok(Arc::new(CompressedStream::new(
                Arc::clone(&self.media),
                self.boot.cluster_size,
                nr.compression_unit,
                &rl,
                nr.data_size,
            )?))
        } else {
            Ok(Arc::new(NonResidentStream::new(
                Arc::clone(&self.media),
                self.boot.cluster_size,
                &rl,
                nr.data_size,
                nr.initialized_size,
            )))
        }
    }

    /// Decodes every segment of a stream against the volume size; any malformed run is an error.
    pub fn decode_segments(&self, segments: &[(u64, Vec<u8>)]) -> ForensicResult<Runlist> {
        let mut out = Runlist::default();
        for (vcn, bytes) in segments {
            let rl = runlist::decode(bytes, *vcn, Some(self.boot.total_clusters()));
            if let Some(reason) = rl.error {
                return Err(error::corrupted(0, format!("data runs: {reason}")));
            }
            out.runs.extend(rl.runs);
        }
        out.runs.sort_by_key(|r| r.vcn);
        Ok(out)
    }

    /// Cluster allocation bitmap (loaded on first use).
    pub fn bitmap(&self) -> ForensicResult<&ClusterBitmap> {
        let r = self
            .bitmap
            .get_or_init(|| self.load_bitmap().map_err(|e| e.to_string()));
        r.as_ref()
            .map_err(|e| error::corrupted(0, format!("$Bitmap: {e}")))
    }

    fn load_bitmap(&self) -> ForensicResult<ClusterBitmap> {
        let e = self
            .mft
            .entry(BITMAP_ENTRY)?
            .ok_or_else(|| error::invalid("$Bitmap record is empty"))?;
        let src = self.open_data(&e, "")?;
        let clusters = self.boot.total_clusters();
        let need = clusters.div_ceil(8);
        if need > MAX_BITMAP || src.len() < need {
            return Err(error::invalid(format!(
                "$Bitmap is {} bytes, {need} needed",
                src.len()
            )));
        }
        let bits = src.read_vec(0, need as usize)?;
        Ok(ClusterBitmap { bits, clusters })
    }
}

/// Reads the primary boot sector, falling back to the backup in the last sector.
fn read_boot(media: &dyn RecordSource) -> ForensicResult<(BootSector, Vec<NtfsAnomaly>)> {
    let primary = media
        .read_vec(0, BOOT_SECTOR_SIZE)
        .and_then(|b| BootSector::parse(&b));
    let backup_at = media.len().checked_sub(BOOT_SECTOR_SIZE as u64);
    let backup = backup_at.map(|at| {
        media
            .read_vec(at, BOOT_SECTOR_SIZE)
            .and_then(|b| BootSector::parse(&b))
    });
    match (primary, backup) {
        (Ok(p), Some(Ok(b))) => {
            let mut a = Vec::new();
            if p.raw != b.raw {
                a.push(NtfsAnomaly::BootBackupMismatch);
            }
            Ok((p, a))
        }
        (Ok(p), _) => Ok((p, Vec::new())),
        (Err(_), Some(Ok(b))) => {
            forensic_rs::warn!("primary NTFS boot sector unreadable, using the backup");
            Ok((b, vec![NtfsAnomaly::BootBackupUsed]))
        }
        (Err(e), _) => Err(e),
    }
}

/// `$MFT`'s own `$DATA` runs: from record 0, then from the extension records its attribute list
/// names, read through the runs known so far until nothing new appears.
fn mft_data(
    media: &Arc<dyn RecordSource>,
    boot: &BootSector,
    rec0: &MftRecord,
    anomalies: &mut Vec<NtfsAnomaly>,
) -> ForensicResult<(Runlist, u64, u64)> {
    let total = boot.total_clusters();
    let rs = u64::from(boot.mft_record_size);
    let mut segments: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut sizes = None;
    let mut take = |rec: &MftRecord, segments: &mut BTreeMap<u64, Vec<u8>>| {
        for a in rec.attributes_of(ATTR_DATA).filter(|a| a.name.is_empty()) {
            if let AttrBody::NonResident(nr) = &a.body {
                if nr.starting_vcn == 0 {
                    sizes = Some((nr.data_size, nr.initialized_size));
                }
                segments
                    .entry(nr.starting_vcn)
                    .or_insert_with(|| nr.runlist.clone());
            }
        }
    };
    take(rec0, &mut segments);
    // Extension records named by the attribute list.
    let mut pending: Vec<u64> = Vec::new();
    for a in rec0.attributes_of(ATTR_ATTRIBUTE_LIST) {
        let bytes = match &a.body {
            AttrBody::Resident { value, .. } => value.clone(),
            AttrBody::NonResident(nr) => {
                let rl = runlist::decode(&nr.runlist, 0, Some(total));
                let size = nr.data_size.min(MAX_ATTRIBUTE_LIST as u64);
                NonResidentStream::new(Arc::clone(media), boot.cluster_size, &rl, size, size)
                    .read_vec(0, size as usize)?
            }
        };
        let mut list = Vec::new();
        if let Err(reason) = attr_list::parse(&bytes, &mut list) {
            anomalies.push(NtfsAnomaly::AttributeMalformed {
                type_code: ATTR_ATTRIBUTE_LIST,
                reason,
            });
        }
        pending.extend(
            list.iter()
                .filter(|e| e.type_code == ATTR_DATA && e.name.is_empty() && e.segment.entry != 0)
                .map(|e| e.segment.entry),
        );
    }
    pending.sort_unstable();
    pending.dedup();
    let build = |segments: &BTreeMap<u64, Vec<u8>>, anomalies: &mut Vec<NtfsAnomaly>| {
        let mut rl = Runlist::default();
        for (vcn, bytes) in segments {
            let d = runlist::decode(bytes, *vcn, Some(total));
            if let Some(reason) = d.error {
                anomalies.push(NtfsAnomaly::RunlistMalformed { reason });
            }
            rl.runs.extend(d.runs);
        }
        rl.runs.sort_by_key(|r| r.vcn);
        rl
    };
    for _ in 0..MFT_BOOTSTRAP_ROUNDS {
        if pending.is_empty() {
            break;
        }
        let mut scratch = Vec::new();
        let rl = build(&segments, &mut scratch);
        let covered = rl.total_clusters().saturating_mul(boot.cluster_size);
        let stream =
            NonResidentStream::new(Arc::clone(media), boot.cluster_size, &rl, covered, covered);
        let before = pending.len();
        let mut still = Vec::new();
        for n in pending.drain(..) {
            let at = n.saturating_mul(rs);
            if at + rs > covered {
                still.push(n);
                continue;
            }
            let raw = stream.read_vec(at, rs as usize)?;
            match MftRecord::parse(n, &raw) {
                Ok(Some(rec)) if rec.header.base_reference.entry == 0 => take(&rec, &mut segments),
                _ => anomalies.push(NtfsAnomaly::ExtensionOrphan {
                    base: FileRef::new(0, rec0.header.sequence),
                }),
            }
        }
        pending = still;
        if pending.len() == before {
            break;
        }
    }
    for n in pending {
        forensic_rs::warn!(
            "$MFT extension record {} not reachable through the known runs",
            n
        );
        anomalies.push(NtfsAnomaly::RunlistMalformed {
            reason: "$MFT extension record not reachable",
        });
    }
    let (data_size, initialized) =
        sizes.ok_or_else(|| error::corrupted(0, "$MFT record 0 has no non-resident $DATA"))?;
    let rl = build(&segments, anomalies);
    Ok((rl, data_size, initialized))
}

fn build_tree(mft: &Mft) -> Tree {
    let mut tree = Tree::default();
    let index = mft.index();
    for item in mft.entries() {
        let e = match item {
            Ok(e) => e,
            Err(err) => {
                forensic_rs::debug!("tree: skipping unreadable record: {}", err);
                tree.unreadable += 1;
                continue;
            }
        };
        if !e.in_use() || e.header.is_extension() {
            continue;
        }
        for n in e.link_names() {
            if n.parent.entry == e.reference.entry {
                continue;
            }
            let p = index.slot(n.parent.entry);
            let ok = matches!(p, Slot::Present { sequence, .. } if sequence == n.parent.sequence)
                && p.in_use()
                && p.is_directory();
            if ok {
                tree.children
                    .entry(n.parent.entry)
                    .or_default()
                    .push(Child {
                        name: n.name.clone(),
                        reference: e.reference,
                        is_dir: e.is_directory(),
                    });
            }
        }
    }
    for kids in tree.children.values_mut() {
        kids.sort_by(|a, b| a.name.cmp(&b.name).then(a.reference.cmp(&b.reference)));
        kids.dedup();
    }
    tree
}

#[cfg(test)]
mod tests;
