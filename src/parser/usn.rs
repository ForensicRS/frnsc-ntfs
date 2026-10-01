//! `UsnParserFactory`: loose `$UsnJrnl:$J` -> one event per journal record.

use forensic_rs::dictionary;
use forensic_rs::prelude::*;
use forensic_rs::provenance::{Recovery, SourceKey};

use super::companions::MftCache;
use super::discovery::{self, find, named};
use super::texts;
use crate::fields as f;
use crate::mft::{Mft, PathStatus, CANCEL_POLL};
use crate::source::StreamSource;
use crate::time::filetime;
use crate::usn::{reason_names, UsnReader, UsnRecord};

/// Artifact tag for USN records.
pub fn usn_artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::UsnJrnl)
}

/// Options for [`UsnParserFactory`].
#[derive(Debug, Clone)]
pub struct UsnParserOptions {
    pub max_depth: u32,
    pub extra_patterns: Vec<String>,
}

impl Default for UsnParserOptions {
    fn default() -> Self {
        Self {
            max_depth: 8,
            extra_patterns: Vec::new(),
        }
    }
}

/// Parses loose `$UsnJrnl:$J` streams. Every record is an event (`@timestamp` = the record's own
/// time). With the `$MFT` alongside, the parent directory is resolved to a path; since the MFT is
/// the *current* state and the journal is history, a parent whose sequence number no longer
/// matches is reported with `ntfs.path_status = stale_parent`.
pub struct UsnParserFactory {
    descriptor: ParserDescriptor,
    opts: UsnParserOptions,
}

impl Default for UsnParserFactory {
    fn default() -> Self {
        Self::new(UsnParserOptions::default())
    }
}

/// The ForensicArtifacts definition this parser reads: the change journal. Declared, not used to
/// locate files: the definition names only `$Extend\$UsnJrnl`, not the `$J` stream or the names
/// export tools give it, which [`super::discovery::USN_NAMES`] matches.
pub const DEFINITION: &str = "NTFSUSNJournal";

impl UsnParserFactory {
    pub fn new(opts: UsnParserOptions) -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.ntfs.usnjrnl",
                "NTFS $UsnJrnl:$J",
                "Parses the NTFS change journal ($UsnJrnl:$J): file creation, deletion, rename \
                 and data changes, with paths resolved through the $MFT when present",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![usn_artifact()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
            opts,
        }
    }
}

impl ArtifactParserFactory for UsnParserFactory {
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
                &named(discovery::USN_NAMES),
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
                let cancelled = || cancellation.is_cancelled();
                if cancelled() {
                    return Ok(());
                }
                let mut errors = Vec::new();
                let mft =
                    cache.for_artifact(fs.as_ref(), &path, &cancelled, &mut |e| errors.push(e));
                for e in errors {
                    if out.emit(Err(e)).is_stop() {
                        return Ok(());
                    }
                }
                let src = match fs.open(&path).and_then(StreamSource::new) {
                    Ok(s) => s,
                    Err(e) => {
                        if out.emit(Err(e.with_path(path.as_path()))).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                let source = store.register_source(SourceKey::Path(path.as_str().to_string()));
                let prov = source.mint(acquisition, Recovery::Allocated);
                for (i, item) in UsnReader::new(&src).enumerate() {
                    if (i as u64).is_multiple_of(CANCEL_POLL) && cancelled() {
                        return Ok(());
                    }
                    let item = item
                        .map(|r| usn_record(&host, path.as_str(), mft.as_deref(), &r, prov))
                        .map_err(|e| e.with_path(path.as_path()));
                    if out.emit(item).is_stop() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        }))
    }
}

/// Builds the record for one journal entry.
pub fn usn_record(
    host: &str,
    source_path: &str,
    mft: Option<&Mft>,
    r: &UsnRecord,
    prov: forensic_rs::provenance::ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(host, usn_artifact(), prov);
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_USN);
    d.set(f::SOURCE_PATH, source_path.to_string());
    d.set(f::RECOVERY, "allocated");
    if let Some(ts) = r.timestamp.and_then(filetime) {
        d.set(f::TIMESTAMP, ts);
    }
    if let Some(raw) = r.timestamp {
        d.set(f::USN_TIMESTAMP_RAW, raw);
    }
    d.set(f::USN, r.usn);
    d.set(f::USN_OFFSET, r.offset);
    d.set(f::USN_VERSION, format!("{}.{}", r.major, r.minor));
    d.set(f::USN_REASON, u64::from(r.reason));
    let reasons = reason_names(r.reason);
    d.set(dictionary::EVENT_ACTION, reasons.join("|"));
    d.set(f::USN_REASON_NAMES, texts(reasons));
    d.set(f::USN_SOURCE_INFO, u64::from(r.source_info));
    if let Some(v) = r.security_id {
        d.set(f::USN_SECURITY_ID, u64::from(v));
    }
    if let Some(v) = r.file_attributes {
        d.set(f::USN_FILE_ATTRIBUTES, u64::from(v));
        d.set(
            dictionary::FILE_ATTRIBUTES,
            texts(crate::attr::std_info::attribute_names(v)),
        );
    }
    d.set(f::USN_FILE_REFERENCE, r.file_reference.to_string());
    d.set(f::USN_PARENT_REFERENCE, r.parent_reference.to_string());
    d.set(f::ENTRY, r.file_reference.entry);
    d.set(f::SEQUENCE, u64::from(r.file_reference.sequence));
    d.set(dictionary::FILE_INODE, r.file_reference.entry);
    if let Some(name) = &r.name {
        d.set(dictionary::FILE_NAME, name.clone());
        if let Some(m) = mft {
            match m.directory_path(r.parent_reference) {
                Some(dir) => {
                    let path = if dir.path == "\\" {
                        format!("\\{name}")
                    } else {
                        format!("{}\\{name}", dir.path)
                    };
                    d.set(dictionary::FILE_DIRECTORY, dir.path);
                    d.set(dictionary::FILE_PATH, path);
                    d.set(f::PATH_STATUS, dir.status.name());
                }
                None => d.set(f::PATH_STATUS, PathStatus::Orphan.name()),
            }
        }
    }
    d
}
