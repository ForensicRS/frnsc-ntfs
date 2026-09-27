//! `SdsParserFactory`: loose `$Secure:$SDS` -> one record per security descriptor.

use std::collections::BTreeMap;

use forensic_rs::prelude::*;
use forensic_rs::provenance::{Parsed, Recovery, SourceKey};

use super::discovery::{self, companion, find, named};
use super::texts;
use crate::anomaly::to_core;
use crate::fields as f;
use crate::secure::{self, SdsEntry};

/// Largest `$SDS` read into memory.
pub const MAX_SDS: u64 = 512 * 1024 * 1024;

pub fn sds_artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::Secure)
}

/// Reads and parses one `$SDS` file (bounded by [`MAX_SDS`]).
pub fn read_sds(fs: &dyn FileSystem, path: &FPath) -> ForensicResult<(Vec<SdsEntry>, Vec<u64>)> {
    let size = fs.metadata(path)?.size;
    if size > MAX_SDS {
        return Err(ForensicError::too_big("reading $SDS", size, MAX_SDS));
    }
    let bytes = fs.read_all(path)?;
    Ok(secure::parse(&bytes))
}

/// Owner SIDs by security id from the `$SDS` next to `artifact`. Unreadable = no owners; the
/// failure is logged (the MFT records are still complete without `file.uid`).
pub(crate) fn owners_for(fs: &dyn FileSystem, artifact: &FPath) -> Option<BTreeMap<u32, String>> {
    let path = companion(fs, artifact, discovery::SDS_NAMES)?;
    match read_sds(fs, path.as_path()) {
        Ok((entries, _)) => Some(
            entries
                .into_iter()
                .filter_map(|e| Some((e.security_id, e.owner?)))
                .collect(),
        ),
        Err(e) => {
            forensic_rs::warn!(
                "owners not resolved: $SDS {} unreadable: {}",
                path.as_str(),
                e
            );
            None
        }
    }
}

/// Parses loose `$Secure:$SDS` streams.
pub struct SdsParserFactory {
    descriptor: ParserDescriptor,
    max_depth: u32,
}

impl Default for SdsParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.ntfs.sds",
                "NTFS $Secure:$SDS",
                "Parses the NTFS shared security descriptor stream: owner, group and DACL per \
                 security id, with hash and mirror checks",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![sds_artifact()]),
            max_depth: 8,
        }
    }
}

impl ArtifactParserFactory for SdsParserFactory {
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
        let max_depth = self.max_depth;
        Ok(ParserRun::push(move |out| {
            let found = find(fs.as_ref(), &named(discovery::SDS_NAMES), &[], max_depth);
            for e in found.errors {
                if out.emit(Err(e)).is_stop() {
                    return Ok(());
                }
            }
            for path in found.paths {
                let (entries, bad) = match read_sds(fs.as_ref(), &path) {
                    Ok(v) => v,
                    Err(e) => {
                        if out.emit(Err(e.with_path(path.as_path()))).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                let prov = store
                    .register_source(SourceKey::Path(path.as_str().to_string()))
                    .mint(acquisition, Recovery::Allocated);
                for offset in bad {
                    let e = crate::error::corrupted(offset, "unreadable $SDS entry")
                        .with_path(path.as_path());
                    if out.emit(Err(e)).is_stop() {
                        return Ok(());
                    }
                }
                for e in entries {
                    let mut d = ForensicData::new(&host, sds_artifact(), prov);
                    d.set(f::RECORD_TYPE, f::RECORD_TYPE_SECURITY_DESCRIPTOR);
                    d.set(f::SOURCE_PATH, path.as_str().to_string());
                    d.set(f::SDS_SECURITY_ID, u64::from(e.security_id));
                    d.set(f::SDS_HASH, u64::from(e.hash));
                    d.set(f::SDS_OFFSET, e.offset);
                    d.set(f::SDS_CONTROL, u64::from(e.control));
                    if let Some(o) = &e.owner {
                        d.set(f::SDS_OWNER, o.clone());
                    }
                    if let Some(g) = &e.group {
                        d.set(f::SDS_GROUP, g.clone());
                    }
                    if let Some(dacl) = &e.dacl {
                        d.set(f::SDS_DACL, texts(dacl.iter().map(|a| a.summary())));
                    }
                    d.set(f::SDS_SACL_PRESENT, e.sacl_present);
                    if !e.anomalies.is_empty() {
                        let (names, core) = to_core(&e.anomalies);
                        d.set_parsed(f::ANOMALIES, Parsed::with_anomalies(names, core, prov));
                    }
                    if out.emit(Ok(d)).is_stop() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        }))
    }
}
