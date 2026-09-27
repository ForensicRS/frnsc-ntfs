//! `MftEntry` -> `ForensicData`.

use std::collections::BTreeMap;

use forensic_rs::dictionary;
use forensic_rs::prelude::*;
use forensic_rs::provenance::{Parsed, ProvenanceId};

use super::{hex, texts};
use crate::anomaly::{to_core, NtfsAnomaly, NtfsIndicator};
use crate::attr::reparse::{tag_name, TAG_MOUNT_POINT, TAG_SYMLINK};
use crate::attr::std_info::attribute_names;
use crate::attr::FileName;
use crate::fields as f;
use crate::mft::{timestomp, Mft, MftEntry, PathStatus};
use crate::recovery::record_slack::SlackName;
use crate::runlist;
use crate::time::{filetime, NtfsTimes};

/// Largest resident `Zone.Identifier` decoded as text.
const MAX_ZONE_IDENTIFIER: usize = 4096;
/// Largest run list emitted in `ntfs.data.runs` (longer lists only get `ntfs.data.run_count`).
const MAX_RUNS_EMITTED: usize = 64;

/// Everything the record builder needs besides the entry.
pub struct SchemaContext<'a> {
    pub host: &'a str,
    pub source_path: &'a str,
    pub mft: &'a Mft,
    /// `security_id` -> owner SID, from a companion `$Secure:$SDS`.
    pub owners: Option<&'a BTreeMap<u32, String>>,
    /// Max resident bytes hex-encoded into `ntfs.data.resident_hex` (0 = off).
    pub resident_hex_max: usize,
}

fn artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::MFT)
}

fn set_times(
    d: &mut ForensicData,
    t: &NtfsTimes,
    keys: [&'static str; 4],
    raw_keys: [&'static str; 4],
) {
    for ((k, rk), v) in keys.into_iter().zip(raw_keys).zip(t.all()) {
        if let Some(ts) = filetime(v) {
            d.set(k, ts);
        }
        d.set(rk, v);
    }
}

fn set_fn(d: &mut ForensicData, n: &FileName) {
    set_times(
        d,
        &n.times,
        [
            f::FN_CREATED,
            f::FN_MODIFIED,
            f::FN_MFT_MODIFIED,
            f::FN_ACCESSED,
        ],
        [
            f::FN_CREATED_RAW,
            f::FN_MODIFIED_RAW,
            f::FN_MFT_MODIFIED_RAW,
            f::FN_ACCESSED_RAW,
        ],
    );
    d.set(f::FN_PARENT_ENTRY, n.parent.entry);
    d.set(f::FN_PARENT_SEQUENCE, u64::from(n.parent.sequence));
    d.set(f::FN_NAMESPACE, n.namespace.name());
    d.set(f::FN_FLAGS, u64::from(n.flags));
    d.set(f::FN_ALLOCATED_SIZE, n.allocated_size);
    d.set(f::FN_REAL_SIZE, n.real_size);
}

/// Splits a `\`-separated path into (directory, name, extension).
fn split_path(path: &str) -> (String, Option<String>) {
    let (dir, name) = match path.rfind('\\') {
        Some(0) => ("\\".to_string(), &path[1..]),
        Some(i) => (path[..i].to_string(), &path[i + 1..]),
        None => (String::new(), path),
    };
    let ext = name
        .rfind('.')
        .filter(|&i| i > 0 && i + 1 < name.len())
        .map(|i| name[i + 1..].to_ascii_lowercase());
    (dir, ext)
}

fn attach_anomalies(d: &mut ForensicData, anomalies: &[NtfsAnomaly], prov: ProvenanceId) {
    if anomalies.is_empty() {
        return;
    }
    let (names, core) = to_core(anomalies);
    d.set_parsed(f::ANOMALIES, Parsed::with_anomalies(names, core, prov));
}

/// Builds the record for one MFT entry.
pub fn entry_record(ctx: &SchemaContext<'_>, e: &MftEntry, prov: ProvenanceId) -> ForensicData {
    let mut d = ForensicData::new(ctx.host, artifact(), prov);
    let mut anomalies = e.anomalies.clone();
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_MFT_ENTRY);
    d.set(f::SOURCE_PATH, ctx.source_path.to_string());
    d.set(
        f::RECOVERY,
        if e.in_use() {
            "allocated"
        } else {
            "deleted_metadata"
        },
    );

    // Identity and header.
    d.set(f::ENTRY, e.reference.entry);
    d.set(f::SEQUENCE, u64::from(e.reference.sequence));
    d.set(f::REFERENCE, e.reference.to_string());
    d.set(dictionary::FILE_INODE, e.reference.entry);
    d.set(f::IN_USE, e.in_use());
    d.set(f::IS_DIRECTORY, e.is_directory());
    if e.header.is_extension() {
        d.set(f::BASE_REFERENCE, e.header.base_reference.to_string());
    }
    d.set(f::RECORD_OFFSET, ctx.mft.offset_of(e.reference.entry));
    d.set(f::RECORD_FLAGS, u64::from(e.header.flags));
    d.set(f::RECORD_FLAG_NAMES, e.header.flag_names());
    d.set(f::RECORD_LSN, e.header.lsn);
    d.set(f::RECORD_LINK_COUNT, u64::from(e.header.link_count));
    d.set(f::RECORD_USED_SIZE, u64::from(e.header.used_size));
    d.set(f::RECORD_ALLOCATED_SIZE, u64::from(e.header.allocated_size));
    if let Some(n) = e.header.record_number {
        d.set(f::RECORD_NUMBER, u64::from(n));
    }
    d.set(f::RECORD_FIXUP, e.fixup.name());

    // Type.
    let is_link = e
        .reparse
        .as_ref()
        .is_some_and(|r| r.tag == TAG_SYMLINK || r.tag == TAG_MOUNT_POINT);
    let file_type = if is_link {
        "symlink"
    } else if e.is_directory() {
        "dir"
    } else {
        "file"
    };
    d.set(dictionary::FILE_TYPE, file_type);

    // $STANDARD_INFORMATION.
    if let Some(si) = &e.std_info {
        set_times(
            &mut d,
            &si.times,
            [
                dictionary::FILE_CREATED,
                dictionary::FILE_MODIFIED,
                dictionary::FILE_CHANGED,
                dictionary::FILE_ACCESSED,
            ],
            [
                f::SI_CREATED_RAW,
                f::SI_MODIFIED_RAW,
                f::SI_MFT_MODIFIED_RAW,
                f::SI_ACCESSED_RAW,
            ],
        );
        for (k, v) in [
            (f::SI_CREATED, si.times.created),
            (f::SI_MODIFIED, si.times.modified),
            (f::SI_MFT_MODIFIED, si.times.mft_modified),
            (f::SI_ACCESSED, si.times.accessed),
        ] {
            if let Some(ts) = filetime(v) {
                d.set(k, ts);
            }
        }
        d.set(f::SI_ATTRIBUTES, u64::from(si.file_attributes));
        d.set(
            dictionary::FILE_ATTRIBUTES,
            texts(attribute_names(si.file_attributes)),
        );
        d.set(f::SI_LAYOUT, u64::from(si.layout));
        if let Some(v) = si.owner_id {
            d.set(f::SI_OWNER_ID, u64::from(v));
        }
        if let Some(v) = si.security_id {
            d.set(f::SI_SECURITY_ID, u64::from(v));
        }
        if let Some(v) = si.quota_charged {
            d.set(f::SI_QUOTA_CHARGED, v);
        }
        if let Some(v) = si.usn {
            d.set(f::SI_USN, v);
        }
    }

    // Owner: the file's own descriptor, else its security id looked up in `$Secure:$SDS`.
    let sds_owner = e
        .std_info
        .as_ref()
        .and_then(|si| si.security_id)
        .and_then(|id| ctx.owners.and_then(|o| o.get(&id)));
    if let Some(owner) = e.descriptor_owner.as_ref().or(sds_owner) {
        d.set(dictionary::FILE_UID, owner.clone());
    }

    // Names and paths.
    let primary = e.primary_name();
    let path = ctx.mft.path_of(e);
    if let Some(n) = primary {
        d.set(dictionary::FILE_NAME, n.name.clone());
        set_fn(&mut d, n);
    }
    d.set(dictionary::FILE_PATH, path.path.clone());
    let (dir, ext) = split_path(&path.path);
    d.set(dictionary::FILE_DIRECTORY, dir);
    if let (Some(ext), false) = (ext, e.is_directory()) {
        d.set(dictionary::FILE_EXTENSION, ext);
    }
    d.set(f::PATH_STATUS, path.status.name());
    if let Some(a) = path.anomaly.clone() {
        anomalies.push(a);
    }
    if let Some(s) = e.short_name() {
        d.set(f::SHORT_NAME, s.name.clone());
    }
    d.set(
        f::NAMES,
        texts(
            e.names
                .iter()
                .map(|n| format!("{}:{}:{}", n.parent, n.namespace.name(), n.name)),
        ),
    );
    let all_paths = ctx.mft.paths_of(e);
    if all_paths.len() > 1 {
        d.set(f::PATHS, texts(all_paths.iter().map(|p| p.path.clone())));
    }
    if all_paths.iter().any(|p| p.status >= PathStatus::Orphan) && path.status < PathStatus::Orphan
    {
        // A secondary hard link is broken: surface it even though the primary path resolved.
        for p in &all_paths {
            if let Some(a) = &p.anomaly {
                if !anomalies.contains(a) {
                    anomalies.push(a.clone());
                }
            }
        }
    }

    // $DATA.
    if let Some(data) = e.data() {
        d.set(dictionary::FILE_SIZE, data.size());
        d.set(f::DATA_RESIDENT, data.is_resident());
        let mut flags = Vec::new();
        if data.is_compressed() {
            flags.push("compressed");
        }
        if data.is_sparse() {
            flags.push("sparse");
        }
        if data.is_encrypted() {
            flags.push("encrypted");
        }
        if !flags.is_empty() {
            d.set(f::DATA_FLAGS, texts(flags));
        }
        if let Some(nr) = &data.non_resident {
            d.set(f::DATA_ALLOCATED_SIZE, nr.allocated_size);
            d.set(f::DATA_INITIALIZED_SIZE, nr.initialized_size);
        }
        if !data.segments.is_empty() {
            let mut runs = Vec::new();
            for (vcn, bytes) in &data.segments {
                let rl = runlist::decode(bytes, *vcn, None);
                if let Some(reason) = rl.error {
                    anomalies.push(NtfsAnomaly::RunlistMalformed { reason });
                }
                runs.extend(rl.runs);
            }
            d.set(f::DATA_RUN_COUNT, runs.len() as u64);
            if runs.len() <= MAX_RUNS_EMITTED {
                d.set(
                    f::DATA_RUNS,
                    texts(runs.iter().map(|r| match r.lcn {
                        Some(lcn) => format!("{}:{}:{}", r.vcn, lcn, r.length),
                        None => format!("{}:sparse:{}", r.vcn, r.length),
                    })),
                );
            }
        }
        if let (Some(v), true) = (&data.resident, ctx.resident_hex_max > 0) {
            if !v.is_empty() {
                d.set(f::DATA_RESIDENT_HEX, hex(v, ctx.resident_hex_max));
            }
        }
    }
    let ads: Vec<String> = e
        .alternate_streams()
        .map(|s| {
            format!(
                "{}:{}:{}",
                s.name,
                s.size(),
                if s.is_resident() {
                    "resident"
                } else {
                    "non_resident"
                }
            )
        })
        .collect();
    if !ads.is_empty() {
        d.set(f::STREAMS, texts(ads));
    }
    if let Some(zone) = e.resident_data("Zone.Identifier") {
        set_zone_identifier(&mut d, zone);
    }

    // Other attributes.
    if let Some(o) = &e.object_id {
        d.set(f::OBJECT_ID, o.object_id.clone());
        if let Some(v) = &o.birth_volume_id {
            d.set(f::OBJECT_ID_BIRTH_VOLUME, v.clone());
        }
        if let Some(v) = &o.birth_object_id {
            d.set(f::OBJECT_ID_BIRTH_OBJECT, v.clone());
        }
        if let Some(v) = &o.domain_id {
            d.set(f::OBJECT_ID_DOMAIN, v.clone());
        }
    }
    if let Some(r) = &e.reparse {
        d.set(f::REPARSE_TAG, u64::from(r.tag));
        d.set(f::REPARSE_TAG_NAME, tag_name(r.tag));
        if let Some(t) = r.target() {
            d.set(f::REPARSE_TARGET, t.to_string());
        }
        if let Some(s) = &r.substitute_name {
            d.set(f::REPARSE_SUBSTITUTE, s.clone());
        }
    }
    if !e.eas.is_empty() {
        d.set(f::EA_NAMES, texts(e.eas.iter().map(|x| x.name.clone())));
        d.set(
            f::EA_SIZE,
            e.eas.iter().map(|x| x.value.len() as u64).sum::<u64>(),
        );
    }
    if !e.logged_streams.is_empty() {
        d.set(
            f::LOGGED_STREAMS,
            texts(
                e.logged_streams
                    .iter()
                    .map(|l| format!("{}:{}", l.name, l.size)),
            ),
        );
        d.set(f::EFS, e.logged_streams.iter().any(|l| l.name == "$EFS"));
    }
    d.set(
        f::ATTRIBUTE_TYPES,
        texts(e.attribute_types.iter().map(|t| format!("{t:#x}"))),
    );
    if let Some(al) = &e.attribute_list {
        d.set(f::ATTRIBUTE_LIST, al.name());
    }
    if !e.extensions.is_empty() {
        d.set(
            f::EXTENSIONS,
            texts(e.extensions.iter().map(|r| r.to_string())),
        );
    }
    if let Some(n) = &e.volume_name {
        d.set(f::VOLUME_NAME, n.clone());
    }
    if let Some(v) = &e.volume_info {
        d.set(f::VOLUME_VERSION, format!("{}.{}", v.major, v.minor));
        d.set(f::VOLUME_DIRTY, v.is_dirty());
    }

    // Slack.
    d.set(f::SLACK_LENGTH, e.slack.len() as u64);
    d.set(f::SLACK_NONZERO, e.slack.iter().any(|&b| b != 0));

    // Timestamp checks.
    let (ts_anomalies, indicators) = timestomp::check(e, ctx.mft.index().volume_created);
    anomalies.extend(ts_anomalies);
    if !indicators.is_empty() {
        d.set(
            f::INDICATORS,
            texts(indicators.iter().map(|i: &NtfsIndicator| i.name())),
        );
    }
    attach_anomalies(&mut d, &anomalies, prov);
    d
}

fn set_zone_identifier(d: &mut ForensicData, zone: &[u8]) {
    if zone.len() > MAX_ZONE_IDENTIFIER {
        return;
    }
    let Ok(text) = std::str::from_utf8(zone) else {
        return;
    };
    d.set(f::ZONE_IDENTIFIER, text.to_string());
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim() {
            "ZoneId" => d.set(f::ZONE_ID, v),
            "HostUrl" => d.set(f::ZONE_HOST_URL, v),
            "ReferrerUrl" => d.set(f::ZONE_REFERRER_URL, v),
            _ => {}
        }
    }
}

/// Builds the record for a name carved from MFT record slack.
pub fn slack_name_record(
    ctx: &SchemaContext<'_>,
    s: &SlackName,
    prov: ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(ctx.host, artifact(), prov);
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_RECORD_SLACK_NAME);
    d.set(f::SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::RECOVERY, "slack");
    d.set(f::ENTRY, s.record.entry);
    d.set(f::SEQUENCE, u64::from(s.record.sequence));
    d.set(f::REFERENCE, s.record.to_string());
    d.set(f::SLACK_OFFSET, s.offset as u64);
    d.set(dictionary::FILE_NAME, s.name.name.clone());
    let path = ctx.mft.resolve(s.name.parent, &s.name.name);
    d.set(dictionary::FILE_PATH, path.path.clone());
    d.set(f::PATH_STATUS, path.status.name());
    set_fn(&mut d, &s.name);
    d
}

/// Builds the record of a `$I30` entry (live or carved from slack). With an MFT, the path is
/// resolved from the key's parent reference.
#[allow(clippy::too_many_arguments)]
pub fn index_record(
    host: &str,
    source_path: &str,
    mft: Option<&Mft>,
    kind: &'static str,
    recovery: &'static str,
    reference: crate::reference::FileRef,
    key: &FileName,
    prov: ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(host, crate::parser::i30::i30_artifact(), prov);
    d.set(f::RECORD_TYPE, kind);
    d.set(f::SOURCE_PATH, source_path.to_string());
    d.set(f::RECOVERY, recovery);
    d.set(f::ENTRY, reference.entry);
    d.set(f::SEQUENCE, u64::from(reference.sequence));
    d.set(f::REFERENCE, reference.to_string());
    d.set(dictionary::FILE_INODE, reference.entry);
    d.set(dictionary::FILE_NAME, key.name.clone());
    d.set(dictionary::FILE_SIZE, key.real_size);
    d.set(f::INDEX_DIRECTORY, key.parent.to_string());
    d.set(
        dictionary::FILE_ATTRIBUTES,
        texts(attribute_names(key.flags)),
    );
    set_fn(&mut d, key);
    if let Some(m) = mft {
        let p = m.resolve(key.parent, &key.name);
        d.set(dictionary::FILE_PATH, p.path);
        d.set(f::PATH_STATUS, p.status.name());
    }
    d
}

/// Builds the per-`$MFT` summary record.
pub fn summary_record(
    ctx: &SchemaContext<'_>,
    counts: &SummaryCounts,
    prov: ProvenanceId,
) -> ForensicData {
    let mut d = ForensicData::new(ctx.host, artifact(), prov);
    d.set(f::RECORD_TYPE, f::RECORD_TYPE_MFT_SUMMARY);
    d.set(f::SOURCE_PATH, ctx.source_path.to_string());
    d.set(f::MFT_RECORD_SIZE, u64::from(ctx.mft.record_size()));
    d.set(f::MFT_ENTRIES, ctx.mft.entry_count());
    d.set(f::MFT_EMPTY, ctx.mft.index().empty);
    d.set(f::MFT_INVALID, ctx.mft.index().invalid);
    d.set(f::MFT_IN_USE, counts.in_use);
    d.set(f::MFT_DELETED, counts.deleted);
    d.set(f::MFT_SLACK_NAMES, counts.slack.admitted);
    d.set(f::MFT_SLACK_REJECTED, counts.slack.rejected);
    attach_anomalies(&mut d, &ctx.mft.anomalies, prov);
    d
}

/// Counters accumulated while emitting.
#[derive(Debug, Default, Clone, Copy)]
pub struct SummaryCounts {
    pub in_use: u64,
    pub deleted: u64,
    pub slack: crate::recovery::RecoveryStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split() {
        assert_eq!(split_path("\\a\\b.TXT"), ("\\a".into(), Some("txt".into())));
        assert_eq!(split_path("\\b"), ("\\".into(), None));
        assert_eq!(split_path("\\.hidden"), ("\\".into(), None));
        assert_eq!(split_path("\\x."), ("\\".into(), None));
    }
}
