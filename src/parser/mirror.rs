//! `$MFTMirr` in the pipeline: the mirrored records, and the cross-check against `$MFT`.
//!
//! The KB catalogues `$MFT` and `$MFTMirr` together under `NTFSMFTFiles`, so both are emitted
//! under the same artifact tag ([`WindowsArtifacts::MFT`]) by [`super::MftParserFactory`]. A
//! `$MFTMirr` found next to a `$MFT` is cross-checked against it; one found on its own is still
//! parsed, and the summary says the check did not run.

use forensic_rs::dictionary;
use forensic_rs::prelude::*;
use forensic_rs::provenance::{
    Acquisition, MergeReason, ProvenanceId, ProvenanceStore, Recovery, SourceKey,
};

use super::hex;
use super::schema::mft_artifact;
use crate::anomaly::to_core;
use crate::boot::BootSector;
use crate::fields as f;
use crate::mft::mirror::{MftMirr, MirrorComparison, MirrorRecordCheck, MirrorSide};
use crate::mft::Mft;
use crate::record::MftRecord;
use crate::source::StreamSource;

/// Everything the `$MFTMirr` record builders need.
pub struct MirrorContext<'a> {
    pub host: &'a str,
    /// Path of the `$MFTMirr` itself.
    pub source_path: &'a str,
    /// Path of the `$MFT` it was checked against, when there was one.
    pub mft_path: Option<&'a str>,
    pub record_size: u32,
    /// Record slots the file holds.
    pub record_count: u64,
    /// Record slots actually read (see `MAX_MIRROR_RECORDS`).
    pub covered: u64,
}

/// Parses `$MFTMirr` at `path` and, when `mft` is given, cross-checks it record by record.
#[allow(clippy::too_many_arguments)]
pub fn parse_mirror(
    fs: &dyn FileSystem,
    path: &FPath,
    mft: Option<(&Mft, &FPath)>,
    boot: Option<&BootSector>,
    host: &str,
    acquisition: Acquisition,
    store: &ProvenanceStore,
    out: &mut dyn ParserOutput,
) -> OutputFlow {
    let mirr = match fs
        .open(path)
        .and_then(StreamSource::new)
        .and_then(|src| MftMirr::open(Box::new(src), boot))
    {
        Ok(m) => m,
        Err(e) => return out.emit(Err(e.with_path(path))),
    };
    let source = store.register_source(SourceKey::Path(path.as_str().to_string()));
    let prov = source.mint(acquisition, Recovery::Allocated);
    // A cross-check record is half `$MFT` bytes and half `$MFTMirr` bytes. Minting it from the
    // mirror alone would attribute the primary's raw record to the wrong file, and a chain of
    // custody for the finding would not list the `$MFT` at all. `register_source` is interned, so
    // naming the `$MFT` again here costs nothing.
    let cross_prov = mft.map(|(_, mft_path)| {
        let mft_source = store.register_source(SourceKey::Path(mft_path.as_str().to_string()));
        let mft_prov = mft_source.mint(acquisition, Recovery::Allocated);
        (
            store.merge(&[prov, mft_prov], MergeReason::Reconciliation),
            store.merge(&[prov, mft_prov], MergeReason::CrossSourceCorroboration),
        )
    });
    let ctx = MirrorContext {
        host,
        source_path: path.as_str(),
        mft_path: mft.map(|(_, p)| p.as_str()),
        record_size: mirr.record_size(),
        record_count: mirr.record_count(),
        covered: mirr.covered(),
    };

    for item in mirr.records() {
        match item {
            // A record that will not parse is one `Err` item; the copy keeps being read.
            Err(e) => {
                if out.emit(Err(e.with_path(path))).is_stop() {
                    return OutputFlow::Stop;
                }
            }
            Ok(rec) => {
                if out
                    .emit(Ok(mirror_entry_record(&ctx, &rec, prov)))
                    .is_stop()
                {
                    return OutputFlow::Stop;
                }
            }
        }
    }

    let comparison = mft.map(|(m, _)| mirr.compare_with(m));
    // A disagreement is reconciled evidence from both files; a summary that ran is the two files
    // corroborating each other. Either way both sources are retained on the record.
    let (check_prov, summary_prov) = cross_prov.unwrap_or((prov, prov));
    if let Some(c) = &comparison {
        for check in c.disagreements() {
            if out
                .emit(Ok(mirror_check_record(&ctx, check, check_prov)))
                .is_stop()
            {
                return OutputFlow::Stop;
            }
        }
    }
    out.emit(Ok(mirror_summary_record(
        &ctx,
        comparison.as_ref(),
        &mirr.anomalies,
        summary_prov,
    )))
}

/// One record as `$MFTMirr` stores it. The `$MFT` parser reports the same files in full; this is
/// the copy, kept apart so the two can be compared without being confused for each other.
pub fn mirror_entry_record(
    ctx: &MirrorContext<'_>,
    rec: &MftRecord,
    prov: ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(ctx.host, mft_artifact(), prov);
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY);
    d.set(f::SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::MIRROR_SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::RECOVERY, "allocated");
    d.set(f::ENTRY, rec.entry);
    d.set(f::SEQUENCE, u64::from(rec.header.sequence));
    d.set(f::REFERENCE, rec.reference().to_string());
    d.set(dictionary::FILE_INODE, rec.entry);
    d.set(f::IN_USE, rec.header.in_use());
    d.set(f::IS_DIRECTORY, rec.header.is_directory());
    d.set(
        f::RECORD_OFFSET,
        rec.entry.saturating_mul(u64::from(ctx.record_size)),
    );
    d.set(f::RECORD_FLAGS, u64::from(rec.header.flags));
    d.set(f::RECORD_FLAG_NAMES, rec.header.flag_names());
    d.set(f::RECORD_LSN, rec.header.lsn);
    d.set(f::RECORD_LINK_COUNT, u64::from(rec.header.link_count));
    d.set(f::RECORD_USED_SIZE, u64::from(rec.header.used_size));
    d.set(
        f::RECORD_ALLOCATED_SIZE,
        u64::from(rec.header.allocated_size),
    );
    if let Some(n) = rec.header.record_number {
        d.set(f::RECORD_NUMBER, u64::from(n));
    }
    if rec.header.is_extension() {
        d.set(f::BASE_REFERENCE, rec.header.base_reference.to_string());
    }
    d.set(f::RECORD_FIXUP, rec.fixup.name());
    // The name the copy itself carries, never one borrowed from the $MFT.
    if let Some(name) = rec
        .attributes_of(crate::record::attribute::ATTR_FILE_NAME)
        .filter_map(|a| a.resident_value())
        .filter_map(|v| crate::attr::FileName::parse(v).ok())
        .max_by_key(|n| n.name.len())
    {
        d.set(dictionary::FILE_NAME, name.name.clone());
    }
    if !rec.anomalies.is_empty() {
        let (names, core) = to_core(&rec.anomalies);
        d.set_parsed(
            f::ANOMALIES,
            forensic_rs::provenance::Parsed::with_anomalies(names, core, prov),
        );
    }
    d
}

fn set_side(d: &mut ForensicData, side: &MirrorSide, keys: [&'static str; 7]) {
    let [stream, offset, record_hex, sequence, update_sequence, fixup, error] = keys;
    d.set(stream, side.stream);
    d.set(offset, side.offset);
    // The whole record, not a prefix: a mismatch is only a finding if both sides can be shown.
    if let Some(raw) = &side.raw {
        d.set(record_hex, hex(raw, raw.len()));
    }
    if let Some(v) = side.sequence {
        d.set(sequence, u64::from(v));
    }
    if let Some(v) = side.update_sequence {
        d.set(update_sequence, u64::from(v));
    }
    if let Some(v) = side.fixup {
        d.set(fixup, v.name());
    }
    if let Some(why) = &side.unreadable {
        d.set(error, why.clone());
    }
}

/// One record number where `$MFT` and `$MFTMirr` disagree, carrying both sides.
pub fn mirror_check_record(
    ctx: &MirrorContext<'_>,
    check: &MirrorRecordCheck,
    prov: ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(ctx.host, mft_artifact(), prov);
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK);
    d.set(f::SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::MIRROR_SOURCE_PATH, ctx.source_path.to_string());
    if let Some(p) = ctx.mft_path {
        d.set(dictionary::FILE_PATH, p.to_string());
    }
    d.set(f::RECOVERY, "allocated");
    d.set(f::ENTRY, check.entry);
    d.set(dictionary::FILE_INODE, check.entry);
    d.set(f::MIRROR_RECORD_SIZE, u64::from(ctx.record_size));
    d.set(f::MIRROR_VERDICT, check.verdict.name());
    if !check.differing_fields.is_empty() {
        // Static names: borrowed, never reallocated per record.
        let names: Vec<Text> = check
            .differing_fields
            .iter()
            .map(|n| Text::Borrowed(n))
            .collect();
        d.set(f::MIRROR_DIFFERING_FIELDS, names);
    }
    if let Some(at) = check.first_difference {
        d.set(f::MIRROR_FIRST_DIFFERENCE, at as u64);
    }
    set_side(
        &mut d,
        &check.primary,
        [
            f::MIRROR_PRIMARY_STREAM,
            f::MIRROR_PRIMARY_OFFSET,
            f::MIRROR_PRIMARY_HEX,
            f::MIRROR_PRIMARY_SEQUENCE,
            f::MIRROR_PRIMARY_UPDATE_SEQUENCE,
            f::MIRROR_PRIMARY_FIXUP,
            f::MIRROR_PRIMARY_ERROR,
        ],
    );
    set_side(
        &mut d,
        &check.mirror,
        [
            f::MIRROR_COPY_STREAM,
            f::MIRROR_COPY_OFFSET,
            f::MIRROR_COPY_HEX,
            f::MIRROR_COPY_SEQUENCE,
            f::MIRROR_COPY_UPDATE_SEQUENCE,
            f::MIRROR_COPY_FIXUP,
            f::MIRROR_COPY_ERROR,
        ],
    );
    // The kind of disagreement, not a blanket "mismatch": a record the two copies agree on but
    // whose protection does not verify is a torn write, and saying "$MFTMirr differs" would point
    // the analyst at the wrong thing.
    if let Some(anomaly) = check.anomaly() {
        let (names, core) = to_core(std::slice::from_ref(&anomaly));
        d.set_parsed(
            f::ANOMALIES,
            forensic_rs::provenance::Parsed::with_anomalies(names, core, prov),
        );
    }
    d
}

/// One record per `$MFTMirr`: what was compared and what came out of it. Emitted even when the
/// two copies agree, so "checked and clean" is distinguishable from "not checked".
pub fn mirror_summary_record(
    ctx: &MirrorContext<'_>,
    comparison: Option<&MirrorComparison>,
    anomalies: &[crate::NtfsAnomaly],
    prov: ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(ctx.host, mft_artifact(), prov);
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    d.set(f::SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::MIRROR_SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::MIRROR_RECORD_SIZE, u64::from(ctx.record_size));
    d.set(f::MIRROR_RECORDS, ctx.record_count);
    d.set(f::MIRROR_READ, ctx.covered);
    let mut all = anomalies.to_vec();
    match comparison {
        Some(c) => {
            let counts = c.counts();
            if let Some(p) = ctx.mft_path {
                d.set(dictionary::FILE_PATH, p.to_string());
            }
            d.set(f::MIRROR_COMPARED, counts.compared);
            d.set(f::MIRROR_IDENTICAL, counts.identical);
            d.set(f::MIRROR_FIXUP_ONLY, counts.fixup_only);
            d.set(f::MIRROR_FIXUP_TORN, counts.fixup_torn);
            d.set(f::MIRROR_DIVERGENT, counts.divergent);
            d.set(f::MIRROR_UNREADABLE, counts.unreadable);
            let disagreements: Vec<u64> = c.disagreements().map(|x| x.entry).collect();
            if !disagreements.is_empty() {
                d.set(
                    f::MIRROR_DISAGREEMENTS,
                    super::texts(disagreements.iter().map(u64::to_string)),
                );
            }
            all.extend(c.anomalies());
        }
        // No `$MFT` next to this copy: say the check did not run rather than imply it passed.
        None => d.set(f::MIRROR_COMPARED, 0u64),
    }
    if !all.is_empty() {
        let (names, core) = to_core(&all);
        d.set_parsed(
            f::ANOMALIES,
            forensic_rs::provenance::Parsed::with_anomalies(names, core, prov),
        );
    }
    d
}
