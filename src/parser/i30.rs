//! `I30ParserFactory`: loose `$I30` (`$INDEX_ALLOCATION`) exports -> live and slack entries.

use forensic_rs::prelude::*;
use forensic_rs::provenance::{
    Acquisition, Parsed, ProvenanceId, ProvenanceStore, Recovery, SourceKey,
};

use super::companions::MftCache;
use super::discovery::{find, is_i30_name};
use super::schema::index_record;
use crate::anomaly::{to_core, NtfsAnomaly};
use crate::attr::FileName;
use crate::fields as f;
use crate::indx::{admit_for_directory, IndexAllocation, SlackEntry};
use crate::mft::{Mft, Slot};
use crate::record::attribute::ATTR_INDEX_ALLOCATION;
use crate::recovery::RecoveryStats;
use crate::reference::FileRef;

/// Artifact tag for `$I30` records.
pub fn i30_artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::Other("NTFS_I30".into()))
}

/// Options for [`I30ParserFactory`].
#[derive(Debug, Clone)]
pub struct I30ParserOptions {
    pub max_depth: u32,
    pub extra_patterns: Vec<String>,
    /// Carve deleted entries from node slack.
    pub carve_slack: bool,
}

impl Default for I30ParserOptions {
    fn default() -> Self {
        Self {
            max_depth: 8,
            extra_patterns: Vec::new(),
            carve_slack: true,
        }
    }
}

/// Parses exported `$I30` index allocations: live entries and entries carved from slack.
///
/// The directory an export belongs to is inferred from its live entries (they all share one
/// parent). An export with no live entries only yields slack entries if every candidate agrees on
/// one parent and there are at least two of them; otherwise candidates are rejected, because a
/// name that cannot be tied to its directory is not trustworthy evidence.
pub struct I30ParserFactory {
    descriptor: ParserDescriptor,
    opts: I30ParserOptions,
}

impl Default for I30ParserFactory {
    fn default() -> Self {
        Self::new(I30ParserOptions::default())
    }
}

impl I30ParserFactory {
    pub fn new(opts: I30ParserOptions) -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.ntfs.i30",
                "NTFS $I30 index",
                "Parses exported $I30 directory indexes: live entries and deleted entries carved \
                 from index slack",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![i30_artifact()]),
            opts,
        }
    }
}

impl ArtifactParserFactory for I30ParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let Some(fs) = ctx.vfs().cloned() else {
            return Ok(ParserRun::push(|_| Ok(())));
        };
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let store = ctx.provenance_store().clone();
        let cancellation = ctx.cancellation().clone();
        let opts = self.opts.clone();
        Ok(ParserRun::push(move |out| {
            let found = find(
                fs.as_ref(),
                &is_i30_name,
                &opts.extra_patterns,
                opts.max_depth,
            );
            for e in found.errors {
                if out.emit(Err(e)).is_stop() {
                    return Ok(());
                }
            }
            let mut cache = MftCache::default();
            for path in found.paths {
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                let cancelled = || cancellation.is_cancelled();
                let mut errors = Vec::new();
                let mft =
                    cache.for_artifact(fs.as_ref(), &path, &cancelled, &mut |e| errors.push(e));
                for e in errors {
                    if out.emit(Err(e)).is_stop() {
                        return Ok(());
                    }
                }
                let job = Job {
                    host: &host,
                    path: &path,
                    acquisition,
                    store: &store,
                    mft: mft.as_deref(),
                    carve: opts.carve_slack,
                };
                if job.run(fs.as_ref(), out).is_stop() {
                    return Ok(());
                }
            }
            Ok(())
        }))
    }
}

struct Job<'a> {
    host: &'a str,
    path: &'a FPath,
    acquisition: Acquisition,
    store: &'a ProvenanceStore,
    mft: Option<&'a Mft>,
    carve: bool,
}

impl Job<'_> {
    fn run(&self, fs: &dyn FileSystem, out: &mut dyn ParserOutput) -> OutputFlow {
        let bytes = match fs.read_all(self.path) {
            Ok(b) => b,
            Err(e) => return out.emit(Err(e.with_path(self.path))),
        };
        let ia = match IndexAllocation::parse(&bytes) {
            Ok(ia) => ia,
            Err(reason) => {
                return out.emit(Err(crate::error::invalid(reason).with_path(self.path)))
            }
        };
        let source = self
            .store
            .register_source(SourceKey::Path(self.path.as_str().to_string()));
        let prov_live = source.mint(self.acquisition, Recovery::Allocated);
        let prov_slack = source.mint(self.acquisition, Recovery::Slack);
        for (offset, reason) in &ia.unreadable {
            let e = crate::error::corrupted(*offset, *reason).with_path(self.path);
            if out.emit(Err(e)).is_stop() {
                return OutputFlow::Stop;
            }
        }
        let dir = ia.directory();
        for node in &ia.nodes {
            for e in &node.entries {
                let mut anomalies = node.anomalies.clone();
                let status = self.mft_status(e.reference, &e.key, &mut anomalies, true);
                let mut d = self.record(
                    f::RECORD_TYPE_INDEX_ENTRY,
                    e.reference,
                    &e.key,
                    prov_live,
                    "allocated",
                );
                d.set(f::INDEX_OFFSET, node.stream_offset + e.offset as u64);
                if let Some(vcn) = node.vcn {
                    d.set(f::INDEX_VCN, vcn);
                }
                if let Some(s) = status {
                    d.set(f::INDEX_MFT_STATUS, s);
                }
                attach(&mut d, &anomalies, prov_live);
                if out.emit(Ok(d)).is_stop() {
                    return OutputFlow::Stop;
                }
            }
        }
        if !self.carve {
            return OutputFlow::Continue;
        }
        let mut stats = RecoveryStats::default();
        let candidates: Vec<SlackEntry> = ia
            .nodes
            .iter()
            .flat_map(|n| n.slack_candidates(&mut stats))
            .collect();
        let dir = dir.or_else(|| consensus_parent(&candidates));
        let admitted = match dir {
            Some(dir) => {
                admit_for_directory(candidates, dir, ATTR_INDEX_ALLOCATION as u16, &mut stats)
            }
            None => {
                stats.rejected += candidates.len() as u64;
                Vec::new()
            }
        };
        for r in admitted {
            let c = r.value();
            let mut anomalies = Vec::new();
            let status = self.mft_status(c.reference, &c.key, &mut anomalies, false);
            let mut d = self.record(
                f::RECORD_TYPE_INDEX_SLACK,
                c.reference,
                &c.key,
                prov_slack,
                "slack",
            );
            d.set(f::INDEX_OFFSET, c.stream_offset);
            if let Some(vcn) = c.vcn {
                d.set(f::INDEX_VCN, vcn);
            }
            if let Some(s) = status {
                d.set(f::INDEX_MFT_STATUS, s);
            }
            attach(&mut d, &anomalies, prov_slack);
            if out.emit(Ok(d)).is_stop() {
                return OutputFlow::Stop;
            }
        }
        forensic_rs::debug!(
            "$I30 {}: slack candidates {} admitted {} rejected {}",
            self.path.as_str(),
            stats.candidates_found,
            stats.admitted,
            stats.rejected
        );
        OutputFlow::Continue
    }

    fn record(
        &self,
        kind: &'static str,
        reference: FileRef,
        key: &FileName,
        prov: ProvenanceId,
        recovery: &'static str,
    ) -> ForensicData {
        index_record(
            self.host,
            self.path.as_str(),
            self.mft,
            kind,
            recovery,
            reference,
            key,
            prov,
        )
    }

    /// Compares the entry with the companion MFT. Live entries naming a record that was freed or
    /// reused are stale (the index lags behind the MFT).
    fn mft_status(
        &self,
        r: FileRef,
        key: &FileName,
        anomalies: &mut Vec<NtfsAnomaly>,
        live: bool,
    ) -> Option<&'static str> {
        let m = self.mft?;
        let slot = m.index().slot(r.entry);
        let status = match slot {
            Slot::Present { sequence, .. } if sequence == r.sequence && slot.in_use() => {
                match m.entry(r.entry) {
                    Ok(Some(e))
                        if e.names
                            .iter()
                            .any(|n| n.name == key.name && n.parent.entry == key.parent.entry) =>
                    {
                        "live"
                    }
                    Ok(Some(_)) => "renamed_or_moved",
                    Ok(None) | Err(_) => "unreadable",
                }
            }
            Slot::Present { sequence, .. }
                if !slot.in_use()
                    && (sequence == r.sequence || sequence == r.sequence.wrapping_add(1)) =>
            {
                "deleted"
            }
            Slot::Present { .. } => "reused",
            Slot::Free { .. } => "free",
            Slot::Empty | Slot::Invalid => "not_in_mft",
        };
        if live && matches!(status, "deleted" | "reused" | "free" | "not_in_mft") {
            anomalies.push(NtfsAnomaly::IndexEntryStale { reference: r });
        }
        Some(status)
    }
}

fn attach(d: &mut ForensicData, anomalies: &[NtfsAnomaly], prov: ProvenanceId) {
    if anomalies.is_empty() {
        return;
    }
    let (names, core) = to_core(anomalies);
    d.set_parsed(f::ANOMALIES, Parsed::with_anomalies(names, core, prov));
}

/// With no live entries, the directory is the one parent every candidate agrees on (at least two).
fn consensus_parent(c: &[SlackEntry]) -> Option<FileRef> {
    let first = c.first()?.key.parent;
    (c.len() >= 2 && c.iter().all(|x| x.key.parent == first)).then_some(first)
}
