//! Output field names. ECS names come from `forensic_rs::dictionary`; everything NTFS-specific is
//! namespaced `ntfs.*` and defined only here.

/// Event time of records that have one (USN). MFT entries are state, not events: no `@timestamp`.
pub const TIMESTAMP: &str = "@timestamp";

/// What kind of record this is (see the `RECORD_TYPE_*` values).
pub const RECORD_TYPE: &str = "ntfs.record_type";
pub const RECORD_TYPE_MFT_ENTRY: &str = "mft_entry";
pub const RECORD_TYPE_MFT_SUMMARY: &str = "mft_summary";
pub const RECORD_TYPE_MFTMIRR_ENTRY: &str = "mftmirr_entry";
pub const RECORD_TYPE_MFTMIRR_CHECK: &str = "mftmirr_check";
pub const RECORD_TYPE_MFTMIRR_SUMMARY: &str = "mftmirr_summary";
pub const RECORD_TYPE_RECORD_SLACK_NAME: &str = "record_slack_name";
pub const RECORD_TYPE_INDEX_ENTRY: &str = "index_entry";
pub const RECORD_TYPE_INDEX_SLACK: &str = "index_slack";
pub const RECORD_TYPE_USN: &str = "usn";
pub const RECORD_TYPE_SECURITY_DESCRIPTOR: &str = "security_descriptor";

/// Path of the evidence file the record was read from (the `$MFT`, `$I30`, `$J`, ...).
pub const SOURCE_PATH: &str = "ntfs.source";
/// How the record was found: `allocated`, `deleted_metadata`, `slack`.
pub const RECOVERY: &str = "ntfs.recovery";

// Identity and header
pub const ENTRY: &str = "ntfs.entry";
pub const SEQUENCE: &str = "ntfs.sequence";
pub const REFERENCE: &str = "ntfs.reference";
pub const IN_USE: &str = "ntfs.in_use";
pub const IS_DIRECTORY: &str = "ntfs.is_directory";
pub const BASE_REFERENCE: &str = "ntfs.base_reference";
pub const RECORD_FLAGS: &str = "ntfs.record.flags";
pub const RECORD_FLAG_NAMES: &str = "ntfs.record.flag_names";
pub const RECORD_LSN: &str = "ntfs.record.lsn";
pub const RECORD_LINK_COUNT: &str = "ntfs.record.link_count";
pub const RECORD_USED_SIZE: &str = "ntfs.record.used_size";
pub const RECORD_ALLOCATED_SIZE: &str = "ntfs.record.allocated_size";
pub const RECORD_NUMBER: &str = "ntfs.record.number";
pub const RECORD_FIXUP: &str = "ntfs.record.fixup";
pub const RECORD_OFFSET: &str = "ntfs.record.offset";

// $STANDARD_INFORMATION
pub const SI_CREATED: &str = "ntfs.si.created";
pub const SI_MODIFIED: &str = "ntfs.si.modified";
pub const SI_MFT_MODIFIED: &str = "ntfs.si.mft_modified";
pub const SI_ACCESSED: &str = "ntfs.si.accessed";
pub const SI_CREATED_RAW: &str = "ntfs.si.created_raw";
pub const SI_MODIFIED_RAW: &str = "ntfs.si.modified_raw";
pub const SI_MFT_MODIFIED_RAW: &str = "ntfs.si.mft_modified_raw";
pub const SI_ACCESSED_RAW: &str = "ntfs.si.accessed_raw";
pub const SI_ATTRIBUTES: &str = "ntfs.si.attributes";
pub const SI_LAYOUT: &str = "ntfs.si.layout";
pub const SI_OWNER_ID: &str = "ntfs.si.owner_id";
pub const SI_SECURITY_ID: &str = "ntfs.si.security_id";
pub const SI_QUOTA_CHARGED: &str = "ntfs.si.quota_charged";
pub const SI_USN: &str = "ntfs.si.usn";

// $FILE_NAME (primary name)
pub const FN_CREATED: &str = "ntfs.fn.created";
pub const FN_MODIFIED: &str = "ntfs.fn.modified";
pub const FN_MFT_MODIFIED: &str = "ntfs.fn.mft_modified";
pub const FN_ACCESSED: &str = "ntfs.fn.accessed";
pub const FN_CREATED_RAW: &str = "ntfs.fn.created_raw";
pub const FN_MODIFIED_RAW: &str = "ntfs.fn.modified_raw";
pub const FN_MFT_MODIFIED_RAW: &str = "ntfs.fn.mft_modified_raw";
pub const FN_ACCESSED_RAW: &str = "ntfs.fn.accessed_raw";
pub const FN_PARENT_ENTRY: &str = "ntfs.fn.parent_entry";
pub const FN_PARENT_SEQUENCE: &str = "ntfs.fn.parent_sequence";
pub const FN_NAMESPACE: &str = "ntfs.fn.namespace";
pub const FN_FLAGS: &str = "ntfs.fn.flags";
pub const FN_ALLOCATED_SIZE: &str = "ntfs.fn.allocated_size";
pub const FN_REAL_SIZE: &str = "ntfs.fn.real_size";

// Names and paths
pub const SHORT_NAME: &str = "ntfs.short_name";
/// Every `$FILE_NAME` as `parent_entry-parent_seq:namespace:name`.
pub const NAMES: &str = "ntfs.names";
/// Every hard-link path.
pub const PATHS: &str = "ntfs.paths";
pub const PATH_STATUS: &str = "ntfs.path_status";

// $DATA
pub const DATA_RESIDENT: &str = "ntfs.data.resident";
pub const DATA_ALLOCATED_SIZE: &str = "ntfs.data.allocated_size";
pub const DATA_INITIALIZED_SIZE: &str = "ntfs.data.initialized_size";
pub const DATA_FLAGS: &str = "ntfs.data.flags";
pub const DATA_RUN_COUNT: &str = "ntfs.data.run_count";
pub const DATA_RUNS: &str = "ntfs.data.runs";
pub const DATA_RESIDENT_HEX: &str = "ntfs.data.resident_hex";
/// Alternate data streams as `name:size:resident|non_resident`.
pub const STREAMS: &str = "ntfs.streams";
pub const ZONE_IDENTIFIER: &str = "ntfs.zone_identifier";
pub const ZONE_ID: &str = "ntfs.zone.id";
pub const ZONE_HOST_URL: &str = "ntfs.zone.host_url";
pub const ZONE_REFERRER_URL: &str = "ntfs.zone.referrer_url";

// Other attributes
pub const OBJECT_ID: &str = "ntfs.object_id";
pub const OBJECT_ID_BIRTH_VOLUME: &str = "ntfs.object_id.birth_volume";
pub const OBJECT_ID_BIRTH_OBJECT: &str = "ntfs.object_id.birth_object";
pub const OBJECT_ID_DOMAIN: &str = "ntfs.object_id.domain";
pub const REPARSE_TAG: &str = "ntfs.reparse.tag";
pub const REPARSE_TAG_NAME: &str = "ntfs.reparse.tag_name";
pub const REPARSE_TARGET: &str = "ntfs.reparse.target";
pub const REPARSE_SUBSTITUTE: &str = "ntfs.reparse.substitute_name";
pub const EA_NAMES: &str = "ntfs.ea.names";
pub const EA_SIZE: &str = "ntfs.ea.size";
pub const LOGGED_STREAMS: &str = "ntfs.logged_streams";
pub const EFS: &str = "ntfs.efs";
pub const ATTRIBUTE_TYPES: &str = "ntfs.attribute_types";
pub const ATTRIBUTE_LIST: &str = "ntfs.attribute_list";
pub const EXTENSIONS: &str = "ntfs.extensions";
pub const VOLUME_NAME: &str = "ntfs.volume.name";
pub const VOLUME_VERSION: &str = "ntfs.volume.version";
pub const VOLUME_DIRTY: &str = "ntfs.volume.dirty";

// Slack
pub const SLACK_LENGTH: &str = "ntfs.slack.length";
pub const SLACK_NONZERO: &str = "ntfs.slack.nonzero";
pub const SLACK_OFFSET: &str = "ntfs.slack.offset";

// Findings on the record
pub const ANOMALIES: &str = "ntfs.anomalies";
pub const INDICATORS: &str = "ntfs.indicators";
pub const ERROR: &str = "ntfs.error";

// MFT summary
pub const MFT_RECORD_SIZE: &str = "ntfs.mft.record_size";
pub const MFT_ENTRIES: &str = "ntfs.mft.entries";
pub const MFT_EMPTY: &str = "ntfs.mft.empty";
pub const MFT_INVALID: &str = "ntfs.mft.invalid";
pub const MFT_IN_USE: &str = "ntfs.mft.in_use";
pub const MFT_DELETED: &str = "ntfs.mft.deleted";
pub const MFT_SLACK_NAMES: &str = "ntfs.mft.slack_names_admitted";
pub const MFT_SLACK_REJECTED: &str = "ntfs.mft.slack_names_rejected";

// $MFTMirr and its cross-check against $MFT.
//
// A disagreement is a finding, so both sides travel with it: `*.record_hex` is the record exactly
// as stored on that side (fixups **not** applied), and `*.offset` is relative to the start of the
// stream named by `*.stream`, never to the volume or the image.
/// Path of the `$MFTMirr` the records were read from.
pub const MIRROR_SOURCE_PATH: &str = "ntfs.mirror.source";
pub const MIRROR_RECORD_SIZE: &str = "ntfs.mirror.record_size";
/// Record slots the `$MFTMirr` covers.
pub const MIRROR_RECORDS: &str = "ntfs.mirror.records";
/// Record slots actually read out of it (lower than `MIRROR_RECORDS` only when the file is far
/// larger than any mirror; the difference is the `mft_mirr_oversized` anomaly).
pub const MIRROR_READ: &str = "ntfs.mirror.read";
/// `identical`, `fixup_only`, `divergent` or `unreadable`.
pub const MIRROR_VERDICT: &str = "ntfs.mirror.verdict";
/// Header fields whose decoded values differ, plus `body` for a difference past the header.
pub const MIRROR_DIFFERING_FIELDS: &str = "ntfs.mirror.differing_fields";
/// Offset of the first differing byte within the record, after fixups.
pub const MIRROR_FIRST_DIFFERENCE: &str = "ntfs.mirror.first_difference";
pub const MIRROR_PRIMARY_STREAM: &str = "ntfs.mirror.primary.stream";
pub const MIRROR_PRIMARY_OFFSET: &str = "ntfs.mirror.primary.offset";
pub const MIRROR_PRIMARY_HEX: &str = "ntfs.mirror.primary.record_hex";
pub const MIRROR_PRIMARY_SEQUENCE: &str = "ntfs.mirror.primary.sequence";
pub const MIRROR_PRIMARY_UPDATE_SEQUENCE: &str = "ntfs.mirror.primary.update_sequence";
pub const MIRROR_PRIMARY_FIXUP: &str = "ntfs.mirror.primary.fixup";
pub const MIRROR_PRIMARY_ERROR: &str = "ntfs.mirror.primary.error";
pub const MIRROR_COPY_STREAM: &str = "ntfs.mirror.copy.stream";
pub const MIRROR_COPY_OFFSET: &str = "ntfs.mirror.copy.offset";
pub const MIRROR_COPY_HEX: &str = "ntfs.mirror.copy.record_hex";
pub const MIRROR_COPY_SEQUENCE: &str = "ntfs.mirror.copy.sequence";
pub const MIRROR_COPY_UPDATE_SEQUENCE: &str = "ntfs.mirror.copy.update_sequence";
pub const MIRROR_COPY_FIXUP: &str = "ntfs.mirror.copy.fixup";
pub const MIRROR_COPY_ERROR: &str = "ntfs.mirror.copy.error";
pub const MIRROR_COMPARED: &str = "ntfs.mirror.compared";
pub const MIRROR_IDENTICAL: &str = "ntfs.mirror.identical";
pub const MIRROR_FIXUP_ONLY: &str = "ntfs.mirror.fixup_only";
pub const MIRROR_DIVERGENT: &str = "ntfs.mirror.divergent";
pub const MIRROR_UNREADABLE: &str = "ntfs.mirror.unreadable";
/// Record numbers where the two copies disagree.
pub const MIRROR_DISAGREEMENTS: &str = "ntfs.mirror.disagreements";

// Index ($I30)
pub const INDEX_DIRECTORY: &str = "ntfs.index.directory";
pub const INDEX_VCN: &str = "ntfs.index.vcn";
pub const INDEX_OFFSET: &str = "ntfs.index.offset";
pub const INDEX_MFT_STATUS: &str = "ntfs.index.mft_status";

// USN journal
pub const USN: &str = "ntfs.usn.usn";
pub const USN_OFFSET: &str = "ntfs.usn.offset";
pub const USN_VERSION: &str = "ntfs.usn.version";
pub const USN_REASON: &str = "ntfs.usn.reason";
pub const USN_REASON_NAMES: &str = "ntfs.usn.reasons";
pub const USN_SOURCE_INFO: &str = "ntfs.usn.source_info";
pub const USN_SECURITY_ID: &str = "ntfs.usn.security_id";
pub const USN_FILE_ATTRIBUTES: &str = "ntfs.usn.file_attributes";
pub const USN_FILE_REFERENCE: &str = "ntfs.usn.file_reference";
pub const USN_PARENT_REFERENCE: &str = "ntfs.usn.parent_reference";
pub const USN_TIMESTAMP_RAW: &str = "ntfs.usn.timestamp_raw";

// $Secure:$SDS
pub const SDS_SECURITY_ID: &str = "ntfs.sds.security_id";
pub const SDS_HASH: &str = "ntfs.sds.hash";
pub const SDS_OFFSET: &str = "ntfs.sds.offset";
pub const SDS_OWNER: &str = "ntfs.sds.owner";
pub const SDS_GROUP: &str = "ntfs.sds.group";
pub const SDS_CONTROL: &str = "ntfs.sds.control";
pub const SDS_DACL: &str = "ntfs.sds.dacl";
pub const SDS_SACL_PRESENT: &str = "ntfs.sds.sacl_present";
