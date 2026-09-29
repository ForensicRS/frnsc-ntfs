//! `MftParserFactory`: every loose `$MFT` in the VFS -> one record per file.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::provenance::{Recovery, SourceKey};

use super::discovery::{self, companion, find, named};
use super::schema::{
    entry_record, index_record, slack_name_record, summary_record, SchemaContext, SummaryCounts,
};
use crate::boot::BootSector;
use crate::fields;
use crate::indx::IndexNode;
use crate::mft::{Mft, CANCEL_POLL};
use crate::record::attribute::ATTR_INDEX_ROOT;
use crate::recovery::record_slack;
use crate::source::StreamSource;

/// Options for [`MftParserFactory`].
#[derive(Debug, Clone)]
pub struct MftParserOptions {
    /// How deep to walk the VFS looking for `$MFT` files.
    pub max_depth: u32,
    /// Extra glob patterns naming MFT files that are not called `$MFT` (e.g. `**/C_MFT.bin`).
    pub extra_patterns: Vec<String>,
    /// Max resident bytes hex-encoded into `ntfs.data.resident_hex` (0 = off).
    pub resident_hex_max: usize,
    /// Carve old `$FILE_NAME` attributes from record slack.
    pub carve_record_slack: bool,
    /// Emit one `mft_summary` record per `$MFT`.
    pub summary: bool,
    /// Parse `$MFTMirr` files too, and cross-check each against the `$MFT` it sits next to.
    pub mirror: bool,
}

impl Default for MftParserOptions {
    fn default() -> Self {
        Self {
            max_depth: 8,
            extra_patterns: Vec::new(),
            resident_hex_max: 1024,
            carve_record_slack: true,
            summary: true,
            mirror: true,
        }
    }
}

/// Parses loose `$MFT` files: allocated and deleted entries, full paths, `$SI`/`$FN` times with
/// timestomp checks, resident data, ADS, and names carved from record slack.
pub struct MftParserFactory {
    descriptor: ParserDescriptor,
    opts: MftParserOptions,
}

impl Default for MftParserFactory {
    fn default() -> Self {
        Self::new(MftParserOptions::default())
    }
}

impl MftParserFactory {
    pub fn new(opts: MftParserOptions) -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.ntfs.mft",
                "NTFS $MFT and $MFTMirr",
                "Parses loose $MFT files: allocated and deleted entries, full paths, $SI/$FN \
                 timestamps with timestomp checks, resident data, alternate data streams and \
                 names carved from record slack; parses $MFTMirr and cross-checks it against \
                 the $MFT it sits next to",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Windows(WindowsArtifacts::MFT)]),
            opts,
        }
    }
}

impl ArtifactParserFactory for MftParserFactory {
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
                &named(discovery::MFT_NAMES),
                &opts.extra_patterns,
                opts.max_depth,
            );
            for e in found.errors {
                if out.emit(Err(e)).is_stop() {
                    return Ok(());
                }
            }
            let mut mirrors_done: BTreeSet<FPathBuf> = BTreeSet::new();
            for path in found.paths {
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                let cancelled = || cancellation.is_cancelled();
                let flow = parse_one(
                    fs.as_ref(),
                    &path,
                    &host,
                    acquisition,
                    &store,
                    &opts,
                    &cancelled,
                    &mut mirrors_done,
                    out,
                );
                if flow.is_stop() {
                    return Ok(());
                }
            }
            if !opts.mirror {
                return Ok(());
            }
            // A `$MFTMirr` collected without its `$MFT` is still evidence: parse it on its own
            // and let its summary say the cross-check did not run.
            let mirrors = find(
                fs.as_ref(),
                &named(discovery::MFTMIRR_NAMES),
                &[],
                opts.max_depth,
            );
            for e in mirrors.errors {
                if out.emit(Err(e)).is_stop() {
                    return Ok(());
                }
            }
            for path in mirrors.paths {
                if cancellation.is_cancelled() || mirrors_done.contains(&path) {
                    continue;
                }
                let boot = load_boot(fs.as_ref(), path.as_path());
                let flow = super::mirror::parse_mirror(
                    fs.as_ref(),
                    path.as_path(),
                    None,
                    boot.as_ref(),
                    &host,
                    acquisition,
                    &store,
                    out,
                );
                if flow.is_stop() {
                    return Ok(());
                }
            }
            Ok(())
        }))
    }
}

/// Parses one `$MFT` and, when `opts.mirror` is set, the `$MFTMirr` beside it. Any `$MFTMirr` it
/// consumes is added to `mirrors_done`, so it is neither parsed again on its own nor paired with a
/// second `$MFT`.
#[allow(clippy::too_many_arguments)]
fn parse_one(
    fs: &dyn FileSystem,
    path: &FPath,
    host: &str,
    acquisition: forensic_rs::provenance::Acquisition,
    store: &forensic_rs::provenance::ProvenanceStore,
    opts: &MftParserOptions,
    cancelled: &dyn Fn() -> bool,
    mirrors_done: &mut BTreeSet<FPathBuf>,
    out: &mut dyn ParserOutput,
) -> OutputFlow {
    let boot = load_boot(fs, path);
    let owners = super::sds_owners(fs, path);
    let mft = match fs
        .open(path)
        .and_then(StreamSource::new)
        .and_then(|src| Mft::open(Box::new(src), boot.as_ref(), cancelled))
    {
        Ok(m) => m,
        Err(e) => return out.emit(Err(e.with_path(path))),
    };
    let source = store.register_source(SourceKey::Path(path.as_str().to_string()));
    let prov_allocated = source.mint(acquisition, Recovery::Allocated);
    let prov_deleted = source.mint(acquisition, Recovery::DeletedMetadata);
    let prov_slack = source.mint(acquisition, Recovery::Slack);
    let ctx = SchemaContext {
        host,
        source_path: path.as_str(),
        mft: &mft,
        owners: owners.as_ref(),
        resident_hex_max: opts.resident_hex_max,
    };
    let provenance = EntryProvenance {
        allocated: prov_allocated,
        deleted: prov_deleted,
        slack: prov_slack,
    };
    let flow = emit_entries(&ctx, &mft, path, opts, cancelled, provenance, out);
    if flow.is_stop() || !opts.mirror {
        return flow;
    }
    // The `$MFTMirr` beside this `$MFT`, cross-checked against it. Deliberately this directory
    // only: a mirror found in a shared ancestor would be paired with every `$MFT` under it, and a
    // multi-volume export would have one volume's mirror declare another volume's records
    // tampered with.
    let Some(mirror_path) = discovery::companion_in_dir(fs, path, discovery::MFTMIRR_NAMES) else {
        return OutputFlow::Continue;
    };
    // One `$MFTMirr` belongs to one `$MFT`. If an export put two (say `$MFT` and `$MFT.bin`) in
    // the same directory, the first pairing stands and the second is left alone rather than
    // silently cross-checked against the wrong primary.
    if !mirrors_done.insert(mirror_path.clone()) {
        forensic_rs::warn!(
            "{} is already cross-checked against another $MFT; not paired with {}",
            mirror_path.as_str(),
            path.as_str()
        );
        return OutputFlow::Continue;
    }
    super::mirror::parse_mirror(
        fs,
        mirror_path.as_path(),
        Some((&mft, path)),
        boot.as_ref(),
        host,
        acquisition,
        store,
        out,
    )
}

/// One provenance id per recovery grade of the same `$MFT`.
#[derive(Debug, Clone, Copy)]
struct EntryProvenance {
    allocated: forensic_rs::provenance::ProvenanceId,
    deleted: forensic_rs::provenance::ProvenanceId,
    slack: forensic_rs::provenance::ProvenanceId,
}

/// Emits every entry of one `$MFT`, plus the names carved from its slack and its summary.
#[allow(clippy::too_many_arguments)]
fn emit_entries(
    ctx: &SchemaContext<'_>,
    mft: &Mft,
    path: &FPath,
    opts: &MftParserOptions,
    cancelled: &dyn Fn() -> bool,
    provenance: EntryProvenance,
    out: &mut dyn ParserOutput,
) -> OutputFlow {
    let EntryProvenance {
        allocated: prov_allocated,
        deleted: prov_deleted,
        slack: prov_slack,
    } = provenance;
    let host = ctx.host;
    let mut counts = SummaryCounts::default();
    for (i, item) in mft.entries().enumerate() {
        if (i as u64).is_multiple_of(CANCEL_POLL) && cancelled() {
            return OutputFlow::Stop;
        }
        let entry = match item {
            Ok(e) => e,
            Err(e) => {
                if out.emit(Err(e.with_path(path))).is_stop() {
                    return OutputFlow::Stop;
                }
                continue;
            }
        };
        let prov = if entry.in_use() {
            counts.in_use += 1;
            prov_allocated
        } else {
            counts.deleted += 1;
            prov_deleted
        };
        if out.emit(Ok(entry_record(ctx, &entry, prov))).is_stop() {
            return OutputFlow::Stop;
        }
        if opts.carve_record_slack && !entry.slack.is_empty() {
            let carved = record_slack::carve(
                entry.reference,
                &entry.slack,
                entry.slack_offset,
                &entry.names,
                mft.index(),
                &mut counts.slack,
            );
            for c in carved {
                if out
                    .emit(Ok(slack_name_record(ctx, c.value(), prov_slack)))
                    .is_stop()
                {
                    return OutputFlow::Stop;
                }
            }
        }
        if opts.carve_record_slack {
            if let Some(root) = entry.index_root.as_deref() {
                // Small directories keep their whole index in the record: deleted children's
                // entries survive in the $INDEX_ROOT node slack.
                match IndexNode::parse_root(root) {
                    Ok(node) => {
                        for c in node.carve_slack(
                            entry.reference,
                            ATTR_INDEX_ROOT as u16,
                            &mut counts.slack,
                        ) {
                            let c = c.value();
                            let d = index_record(
                                host,
                                path.as_str(),
                                Some(mft),
                                fields::RECORD_TYPE_INDEX_SLACK,
                                "slack",
                                c.reference,
                                &c.key,
                                prov_slack,
                            );
                            if out.emit(Ok(d)).is_stop() {
                                return OutputFlow::Stop;
                            }
                        }
                    }
                    Err(reason) => forensic_rs::debug!(
                        "{}: $INDEX_ROOT of {} not parsed: {}",
                        path.as_str(),
                        entry.reference,
                        reason
                    ),
                }
            }
        }
    }
    if opts.summary {
        return out.emit(Ok(summary_record(ctx, &counts, prov_allocated)));
    }
    OutputFlow::Continue
}

/// A companion `$Boot` gives the exact record size. A damaged one is not fatal: the size is then
/// inferred from the `$MFT` itself.
fn load_boot(fs: &dyn FileSystem, mft_path: &FPath) -> Option<BootSector> {
    let p = companion(fs, mft_path, discovery::BOOT_NAMES)?;
    match fs.read_all(p.as_path()).and_then(|b| BootSector::parse(&b)) {
        Ok(b) => Some(b),
        Err(e) => {
            forensic_rs::warn!("ignoring unreadable $Boot {}: {}", p.as_str(), e);
            None
        }
    }
}

/// Convenience for callers that already hold the VFS.
pub fn parse_mft_file(fs: Arc<dyn FileSystem>, path: &FPath) -> ForensicResult<Mft> {
    let boot = load_boot(fs.as_ref(), path);
    let src = StreamSource::new(fs.open(path)?)?;
    Mft::open(Box::new(src), boot.as_ref(), &|| false)
}

/// Owners table type (security id -> SID string).
pub type Owners = BTreeMap<u32, String>;
