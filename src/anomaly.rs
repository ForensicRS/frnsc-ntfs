//! NTFS-specific anomalies and indicators.
//!
//! An [`NtfsAnomaly`] is evidence that the structure is inconsistent. It maps onto a core
//! [`AnomalyFlags`] bit (so the pipeline's anomaly tally turns it into a `Finding` and lowers the
//! record's confidence) and always carries the observed and expected values. Every variant has a
//! [`NtfsAnomaly::benign_explanation`]: an analyst must be able to tell ordinary wear from tampering.
//!
//! An [`NtfsIndicator`] is a weak heuristic. It is reported in `ntfs.indicators` only and never
//! raises a flag, so ordinary NTFS behaviour cannot flood a report with high-severity findings.

use std::fmt;

use forensic_rs::prelude::*;
use forensic_rs::provenance::{Anomalies, AnomalyDetail, AnomalyFlags};

use crate::reference::FileRef;

/// A structural inconsistency found while parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtfsAnomaly {
    /// Some 512-byte strides of a `FILE` record did not end with the update sequence number.
    FixupMismatch { mismatched: u16, first: u16 },
    /// The update sequence array header is out of range; fixups could not be applied.
    FixupInvalid { usa_offset: u16, usa_count: u16 },
    /// Record signature is `BAAD` (marked bad by chkdsk / multi-sector transfer failure).
    BaadSignature,
    /// The record number stored in the header differs from the record's position.
    RecordNumberMismatch { stored: u32, actual: u64 },
    /// An attribute runs past the used part of the record, or its header is malformed.
    AttributeOverrun { offset: usize, length: u32 },
    /// No `0xFFFFFFFF` end marker before the end of the used area.
    MissingEndMarker,
    /// Header `used_size` is larger than `allocated_size` or the record buffer.
    UsedSizeExceedsAllocated { used: u32, allocated: u32 },
    /// An attribute value that should have a fixed layout is too short or inconsistent.
    AttributeMalformed {
        type_code: u32,
        reason: &'static str,
    },
    /// The loose `$MFT` length is not a multiple of the record size.
    MftFileSizeMismatch { length: u64, record_size: u32 },
    /// Extension record whose base record is missing, not in use, or reused.
    ExtensionOrphan { base: FileRef },
    /// `$FILE_NAME` parent reference names a record whose sequence number does not match
    /// (the parent directory was deleted and its record reused).
    ParentStale {
        parent: FileRef,
        found_sequence: u16,
    },
    /// `$FILE_NAME` parent reference names a record that is not a directory.
    ParentNotDirectory { parent: FileRef },
    /// `$FILE_NAME` parent reference names an empty or unreadable record.
    ParentMissing { parent: FileRef },
    /// Parent chain loops back on itself.
    ParentCycle { at: u64 },
    /// Parent chain deeper than the resolver's cap.
    PathTooDeep { depth: usize },
    /// `$STANDARD_INFORMATION` creation time is earlier than the `$FILE_NAME` creation time, and a
    /// second sign agrees (`second_sign`: `si_changed_before_fn_created` or `si_whole_seconds`).
    /// The comparison alone is only the indicator
    /// [`NtfsIndicator::SiCreatedBeforeFn`]: installed files keep their original `$SI` times.
    SiCreatedBeforeFnCreated {
        si: u64,
        fn_: u64,
        second_sign: &'static str,
    },
    /// A run in a data run list is malformed or points outside the volume.
    RunlistMalformed { reason: &'static str },
    /// An `INDX` record failed its fixup check.
    IndxFixupMismatch { vcn: u64 },
    /// An index entry names a file whose current MFT record does not carry that name/sequence.
    IndexEntryStale { reference: FileRef },
    /// A USN record header is malformed; the reader re-synchronised past it.
    UsnRecordMalformed { offset: u64, reason: &'static str },
    /// A `$SDS` entry's self-describing header disagrees with its mirror copy or its own hash.
    SdsEntryMismatch {
        security_id: u32,
        reason: &'static str,
    },
    /// The primary boot sector is unreadable; the backup (last sector) was used.
    BootBackupUsed,
    /// Primary and backup boot sectors both parse but differ.
    BootBackupMismatch,
    /// The image is shorter than the volume the boot sector declares.
    VolumeTruncated { declared: u64, actual: u64 },
    /// `$MFTMirr` records differ from the first `$MFT` records.
    MftMirrMismatch { entries: Vec<u64> },
    /// A deleted file's clusters are allocated again in `$Bitmap`: its content is gone.
    ClustersReallocated { clusters: u64 },
    /// Two deleted files claim the same free clusters: neither content can be attributed.
    DeletedCrossClaim { other: FileRef },
}

impl NtfsAnomaly {
    /// Stable snake_case name, used in `ntfs.anomalies`.
    pub fn name(&self) -> &'static str {
        match self {
            NtfsAnomaly::FixupMismatch { .. } => "fixup_mismatch",
            NtfsAnomaly::FixupInvalid { .. } => "fixup_invalid",
            NtfsAnomaly::BaadSignature => "baad_signature",
            NtfsAnomaly::RecordNumberMismatch { .. } => "record_number_mismatch",
            NtfsAnomaly::AttributeOverrun { .. } => "attribute_overrun",
            NtfsAnomaly::MissingEndMarker => "missing_end_marker",
            NtfsAnomaly::UsedSizeExceedsAllocated { .. } => "used_size_exceeds_allocated",
            NtfsAnomaly::AttributeMalformed { .. } => "attribute_malformed",
            NtfsAnomaly::MftFileSizeMismatch { .. } => "mft_file_size_mismatch",
            NtfsAnomaly::ExtensionOrphan { .. } => "extension_orphan",
            NtfsAnomaly::ParentStale { .. } => "parent_stale",
            NtfsAnomaly::ParentNotDirectory { .. } => "parent_not_directory",
            NtfsAnomaly::ParentMissing { .. } => "parent_missing",
            NtfsAnomaly::ParentCycle { .. } => "parent_cycle",
            NtfsAnomaly::PathTooDeep { .. } => "path_too_deep",
            NtfsAnomaly::SiCreatedBeforeFnCreated { .. } => "si_created_before_fn_created",
            NtfsAnomaly::RunlistMalformed { .. } => "runlist_malformed",
            NtfsAnomaly::IndxFixupMismatch { .. } => "indx_fixup_mismatch",
            NtfsAnomaly::IndexEntryStale { .. } => "index_entry_stale",
            NtfsAnomaly::UsnRecordMalformed { .. } => "usn_record_malformed",
            NtfsAnomaly::SdsEntryMismatch { .. } => "sds_entry_mismatch",
            NtfsAnomaly::BootBackupUsed => "boot_backup_used",
            NtfsAnomaly::BootBackupMismatch => "boot_backup_mismatch",
            NtfsAnomaly::VolumeTruncated { .. } => "volume_truncated",
            NtfsAnomaly::MftMirrMismatch { .. } => "mft_mirr_mismatch",
            NtfsAnomaly::ClustersReallocated { .. } => "clusters_reallocated",
            NtfsAnomaly::DeletedCrossClaim { .. } => "deleted_cross_claim",
        }
    }

    /// Core anomaly flag this maps onto.
    pub fn flag(&self) -> AnomalyFlags {
        match self {
            NtfsAnomaly::FixupMismatch { .. }
            | NtfsAnomaly::FixupInvalid { .. }
            | NtfsAnomaly::BaadSignature
            | NtfsAnomaly::IndxFixupMismatch { .. }
            | NtfsAnomaly::SdsEntryMismatch { .. } => AnomalyFlags::CHECKSUM_MISMATCH,
            NtfsAnomaly::AttributeOverrun { .. }
            | NtfsAnomaly::MissingEndMarker
            | NtfsAnomaly::UsedSizeExceedsAllocated { .. }
            | NtfsAnomaly::AttributeMalformed { .. }
            | NtfsAnomaly::MftFileSizeMismatch { .. }
            | NtfsAnomaly::PathTooDeep { .. }
            | NtfsAnomaly::RunlistMalformed { .. }
            | NtfsAnomaly::UsnRecordMalformed { .. } => AnomalyFlags::TRUNCATED,
            NtfsAnomaly::ExtensionOrphan { .. }
            | NtfsAnomaly::ParentStale { .. }
            | NtfsAnomaly::ParentNotDirectory { .. }
            | NtfsAnomaly::ParentMissing { .. }
            | NtfsAnomaly::IndexEntryStale { .. } => AnomalyFlags::STALE_REFERENCE,
            NtfsAnomaly::ParentCycle { .. } => AnomalyFlags::REFERENCE_CYCLE,
            NtfsAnomaly::SiCreatedBeforeFnCreated { .. } => AnomalyFlags::TIMESTAMP_DIVERGENCE,
            NtfsAnomaly::RecordNumberMismatch { .. }
            | NtfsAnomaly::BootBackupUsed
            | NtfsAnomaly::BootBackupMismatch
            | NtfsAnomaly::MftMirrMismatch { .. } => AnomalyFlags::SOURCE_DIVERGENCE,
            NtfsAnomaly::VolumeTruncated { .. } => AnomalyFlags::TRUNCATED,
            NtfsAnomaly::ClustersReallocated { .. } | NtfsAnomaly::DeletedCrossClaim { .. } => {
                AnomalyFlags::ALLOCATION_CONFLICT
            }
        }
    }

    /// The ordinary, non-malicious reason this can happen. Always present: an analyst weighs
    /// the anomaly against it.
    pub fn benign_explanation(&self) -> &'static str {
        match self {
            NtfsAnomaly::FixupMismatch { .. } | NtfsAnomaly::IndxFixupMismatch { .. } => {
                "torn write: power loss, or the record changed while a live system was being acquired"
            }
            NtfsAnomaly::FixupInvalid { .. } => "record overwritten by unrelated data (carving residue, disk damage)",
            NtfsAnomaly::BaadSignature => "chkdsk or the driver marked the record bad after a failed multi-sector write",
            NtfsAnomaly::RecordNumberMismatch { .. } => {
                "the $MFT was extracted or rebuilt out of order by a collection tool, or the record was copied"
            }
            NtfsAnomaly::AttributeOverrun { .. }
            | NtfsAnomaly::MissingEndMarker
            | NtfsAnomaly::UsedSizeExceedsAllocated { .. }
            | NtfsAnomaly::AttributeMalformed { .. } => "disk damage or a partial overwrite of the record",
            NtfsAnomaly::MftFileSizeMismatch { .. } => "incomplete collection: the $MFT copy was truncated",
            NtfsAnomaly::ExtensionOrphan { .. } => {
                "the base record was deleted and reused while this extension record was left behind"
            }
            NtfsAnomaly::ParentStale { .. } | NtfsAnomaly::ParentNotDirectory { .. } | NtfsAnomaly::ParentMissing { .. } => {
                "the parent directory was deleted and its MFT record reused (normal on a busy volume)"
            }
            NtfsAnomaly::ParentCycle { .. } => "none known: indicates corruption",
            NtfsAnomaly::PathTooDeep { .. } => "a genuinely very deep directory tree, or corruption",
            NtfsAnomaly::SiCreatedBeforeFnCreated { .. } => {
                "a copy tool that preserves every $SI time including the change time, or one that \
                 writes whole seconds; otherwise timestomping (installers alone only raise the \
                 si_created_before_fn indicator)"
            }
            NtfsAnomaly::RunlistMalformed { .. } => "disk damage or a partial overwrite of the record",
            NtfsAnomaly::IndexEntryStale { .. } => "directory indexes are updated lazily after a delete or rename",
            NtfsAnomaly::UsnRecordMalformed { .. } => {
                "the journal wraps and is trimmed in place; a record can straddle the cut"
            }
            NtfsAnomaly::SdsEntryMismatch { .. } => "a torn write of the $SDS stream",
            NtfsAnomaly::BootBackupUsed => "damage to the first sector (disk error, partial overwrite by a partitioning tool)",
            NtfsAnomaly::BootBackupMismatch => {
                "the volume was resized or reformatted without the backup boot sector being rewritten"
            }
            NtfsAnomaly::VolumeTruncated { .. } => "the image is shorter than the partition (incomplete acquisition)",
            NtfsAnomaly::MftMirrMismatch { .. } => {
                "an interrupted write or a chkdsk repair; otherwise tampering with the first MFT records"
            }
            NtfsAnomaly::ClustersReallocated { .. } => "normal: freed clusters are reused by later writes",
            NtfsAnomaly::DeletedCrossClaim { .. } => {
                "two files deleted at different times over the same free space"
            }
        }
    }

    /// Core anomaly detail (flag + `name: message`).
    pub fn detail(&self) -> AnomalyDetail {
        AnomalyDetail {
            kind: self.flag(),
            message: CompactString::from(format!("{}: {}", self.name(), self)),
        }
    }
}

impl fmt::Display for NtfsAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtfsAnomaly::FixupMismatch { mismatched, first } => {
                write!(
                    f,
                    "{mismatched} stride(s) failed the fixup check, first at stride {first}"
                )
            }
            NtfsAnomaly::FixupInvalid {
                usa_offset,
                usa_count,
            } => {
                write!(
                    f,
                    "update sequence array offset {usa_offset:#x} count {usa_count} out of range"
                )
            }
            NtfsAnomaly::BaadSignature => write!(f, "record signature is BAAD"),
            NtfsAnomaly::RecordNumberMismatch { stored, actual } => {
                write!(f, "header says record {stored}, found at position {actual}")
            }
            NtfsAnomaly::AttributeOverrun { offset, length } => {
                write!(
                    f,
                    "attribute at {offset:#x} with length {length} overruns the record"
                )
            }
            NtfsAnomaly::MissingEndMarker => write!(f, "no attribute end marker"),
            NtfsAnomaly::UsedSizeExceedsAllocated { used, allocated } => {
                write!(f, "used size {used} exceeds allocated size {allocated}")
            }
            NtfsAnomaly::AttributeMalformed { type_code, reason } => {
                write!(f, "attribute {type_code:#x}: {reason}")
            }
            NtfsAnomaly::MftFileSizeMismatch {
                length,
                record_size,
            } => {
                write!(
                    f,
                    "$MFT length {length} is not a multiple of record size {record_size}"
                )
            }
            NtfsAnomaly::ExtensionOrphan { base } => {
                write!(f, "base record {base} is not a live base record")
            }
            NtfsAnomaly::ParentStale {
                parent,
                found_sequence,
            } => {
                write!(f, "parent {parent} now has sequence {found_sequence}")
            }
            NtfsAnomaly::ParentNotDirectory { parent } => {
                write!(f, "parent {parent} is not a directory")
            }
            NtfsAnomaly::ParentMissing { parent } => {
                write!(f, "parent {parent} is empty or unreadable")
            }
            NtfsAnomaly::ParentCycle { at } => write!(f, "parent chain loops at entry {at}"),
            NtfsAnomaly::PathTooDeep { depth } => write!(f, "parent chain deeper than {depth}"),
            NtfsAnomaly::SiCreatedBeforeFnCreated {
                si,
                fn_,
                second_sign,
            } => {
                write!(
                    f,
                    "$SI created {si} < $FN created {fn_} (FILETIME), and {second_sign}"
                )
            }
            NtfsAnomaly::RunlistMalformed { reason } => write!(f, "data runs: {reason}"),
            NtfsAnomaly::IndxFixupMismatch { vcn } => {
                write!(f, "INDX record at VCN {vcn} failed the fixup check")
            }
            NtfsAnomaly::IndexEntryStale { reference } => {
                write!(f, "index entry for {reference} does not match the MFT")
            }
            NtfsAnomaly::UsnRecordMalformed { offset, reason } => {
                write!(f, "USN record at {offset:#x}: {reason}")
            }
            NtfsAnomaly::SdsEntryMismatch {
                security_id,
                reason,
            } => {
                write!(f, "security id {security_id}: {reason}")
            }
            NtfsAnomaly::BootBackupUsed => write!(f, "primary boot sector unreadable, backup used"),
            NtfsAnomaly::BootBackupMismatch => write!(f, "primary and backup boot sectors differ"),
            NtfsAnomaly::VolumeTruncated { declared, actual } => {
                write!(
                    f,
                    "boot sector declares {declared} bytes, image has {actual}"
                )
            }
            NtfsAnomaly::MftMirrMismatch { entries } => {
                write!(f, "$MFTMirr differs for entries {entries:?}")
            }
            NtfsAnomaly::ClustersReallocated { clusters } => {
                write!(
                    f,
                    "{clusters} cluster(s) of the deleted file are allocated again"
                )
            }
            NtfsAnomaly::DeletedCrossClaim { other } => {
                write!(f, "clusters also claimed by deleted {other}")
            }
        }
    }
}

/// A weak heuristic worth a look but not a finding on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum NtfsIndicator {
    /// Every `$SI` time is a whole second while `$FN` times are not.
    SiWholeSeconds,
    /// A timestamp is set but outside 1980..2100.
    TimestampOutOfRange,
    /// `$SI` created is earlier than the volume's own `$MFT` creation.
    SiCreatedBeforeVolume,
    /// `$SI` created is earlier than `$FN` created, with no second sign: what installers, image
    /// deployment and copy tools leave on most system files.
    SiCreatedBeforeFn,
}

impl NtfsIndicator {
    pub fn name(self) -> &'static str {
        match self {
            NtfsIndicator::SiWholeSeconds => "si_whole_seconds",
            NtfsIndicator::TimestampOutOfRange => "timestamp_out_of_range",
            NtfsIndicator::SiCreatedBeforeVolume => "si_created_before_volume",
            NtfsIndicator::SiCreatedBeforeFn => "si_created_before_fn",
        }
    }
}

/// Folds a list of anomalies into core [`Anomalies`] plus their names.
pub fn to_core(anomalies: &[NtfsAnomaly]) -> (Vec<Text>, Anomalies) {
    let mut core = Anomalies::empty();
    let mut names = Vec::with_capacity(anomalies.len());
    for a in anomalies {
        core.add_detail(a.detail());
        names.push(Text::Borrowed(a.name()));
    }
    (names, core)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_name_flag_and_explanation() {
        let samples = [
            NtfsAnomaly::FixupMismatch {
                mismatched: 1,
                first: 1,
            },
            NtfsAnomaly::BaadSignature,
            NtfsAnomaly::ParentStale {
                parent: FileRef::new(40, 1),
                found_sequence: 3,
            },
            NtfsAnomaly::ParentCycle { at: 7 },
            NtfsAnomaly::SiCreatedBeforeFnCreated {
                si: 1,
                fn_: 2,
                second_sign: "si_whole_seconds",
            },
            NtfsAnomaly::RecordNumberMismatch {
                stored: 1,
                actual: 2,
            },
        ];
        for a in samples {
            assert!(!a.name().is_empty());
            assert!(!a.flag().is_empty());
            assert!(!a.benign_explanation().is_empty());
            assert!(a.detail().message.starts_with(a.name()));
        }
        let (names, core) = to_core(&[
            NtfsAnomaly::BaadSignature,
            NtfsAnomaly::ParentCycle { at: 1 },
        ]);
        assert_eq!(names.len(), 2);
        assert!(core.has(AnomalyFlags::CHECKSUM_MISMATCH));
        assert!(core.has(AnomalyFlags::REFERENCE_CYCLE));
    }
}
