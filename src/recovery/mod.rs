//! Recovery of deleted and residual metadata.
//!
//! Everything here follows the forensic-rs recovery checklist (`forensic_rs::recovery`):
//! strict validation over recall, no admission on "it decoded", every recovered value carries its
//! `Recovery` mode and a `Locus::Ntfs` address.
//!
//! * Deleted MFT entries are not "recovered" here: their metadata is intact and graded
//!   `Recovery::DeletedMetadata` by the parser. Their resident content (small files, ADS,
//!   `Zone.Identifier`) is still inside the record: [`crate::mft::MftEntry::resident_data`].
//! * Names carved from MFT record slack ([`record_slack`]) and from `$I30` index slack
//!   ([`crate::indx`]) go through [`admit_file_name`] and are graded `Recovery::Slack`.

pub mod record_slack;

use forensic_rs::recovery::RecoveryReport;

use crate::attr::file_name::{FileName, FILE_NAME_HEADER};
use crate::attr::strict_utf16_name;
use crate::reference::FileRef;
use crate::time::plausible;

/// Scan counters, convertible to the core [`RecoveryReport`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryStats {
    pub units_scanned: u64,
    pub candidates_found: u64,
    pub admitted: u64,
    pub rejected: u64,
    pub unreadable: u64,
}

impl RecoveryStats {
    pub fn add(&mut self, other: RecoveryStats) {
        self.units_scanned += other.units_scanned;
        self.candidates_found += other.candidates_found;
        self.admitted += other.admitted;
        self.rejected += other.rejected;
        self.unreadable += other.unreadable;
    }
}

impl From<RecoveryStats> for RecoveryReport {
    fn from(s: RecoveryStats) -> Self {
        RecoveryReport {
            units_scanned: s.units_scanned,
            candidates_found: s.candidates_found,
            admitted: s.admitted,
            rejected: s.rejected,
            unreadable: s.unreadable,
        }
    }
}

/// Structural admission gate for a `$FILE_NAME` value found in slack. All must hold:
///
/// * the value is complete (header + `2 * name_length` bytes present);
/// * the name is non-empty, strict UTF-16 (no unpaired surrogates) with no NUL or control chars;
/// * the namespace is 0..=3;
/// * all four timestamps are set and within 1980..2100;
/// * `real_size <= allocated_size` and `allocated_size` is a multiple of 8;
/// * the parent is not entry 0 (`$MFT` is never a directory).
///
/// The caller adds the context check (expected parent directory).
pub fn admit_file_name(value: &[u8]) -> Option<FileName> {
    let name_len = usize::from(*value.get(64)?);
    let namespace = *value.get(65)?;
    if name_len == 0 || namespace > 3 {
        return None;
    }
    let name_bytes = value.get(FILE_NAME_HEADER..FILE_NAME_HEADER + name_len * 2)?;
    strict_utf16_name(name_bytes)?;
    let f = FileName::parse(value.get(..FILE_NAME_HEADER + name_len * 2)?).ok()?;
    if !f.times.all_plausible() {
        return None;
    }
    if f.real_size > f.allocated_size || f.allocated_size % 8 != 0 {
        return None;
    }
    if f.parent.entry == 0 {
        return None;
    }
    Some(f)
}

/// Whether a carved name's parent reference matches the directory it was found in: same entry,
/// and the same sequence or one less (the directory was deleted and its sequence bumped).
pub fn parent_matches(parent: FileRef, dir: FileRef) -> bool {
    parent.entry == dir.entry
        && (parent.sequence == dir.sequence || parent.sequence.wrapping_add(1) == dir.sequence)
}

/// Whether the timestamps of a `$FILE_NAME` are plausible (exposed for the index parsers).
pub fn times_plausible(f: &FileName) -> bool {
    f.times.all().into_iter().all(plausible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{file_name_value, file_name_value_times, times, FILE_TIME_2020};

    #[test]
    fn gate_accepts_valid_and_rejects_implausible() {
        let good = file_name_value_times(
            FileRef::new(40, 2),
            "report.docx",
            &times(FILE_TIME_2020),
            1,
            4096,
            1000,
        );
        assert_eq!(admit_file_name(&good).unwrap().name, "report.docx");
        // Zero time.
        let zero = file_name_value(FileRef::new(40, 2), "a", 0, 1);
        assert!(admit_file_name(&zero).is_none());
        // real > allocated.
        let bad = file_name_value_times(FileRef::new(40, 2), "a", &times(FILE_TIME_2020), 1, 8, 9);
        assert!(admit_file_name(&bad).is_none());
        // Namespace 4.
        let mut ns = good.clone();
        ns[65] = 4;
        assert!(admit_file_name(&ns).is_none());
        // Control char in name.
        let ctl = file_name_value_times(
            FileRef::new(40, 2),
            "a\u{1}b",
            &times(FILE_TIME_2020),
            1,
            0,
            0,
        );
        assert!(admit_file_name(&ctl).is_none());
        // Parent 0.
        let p0 = file_name_value_times(FileRef::new(0, 0), "a", &times(FILE_TIME_2020), 1, 0, 0);
        assert!(admit_file_name(&p0).is_none());
        // Truncated.
        assert!(admit_file_name(&good[..good.len() - 1]).is_none());
    }

    #[test]
    fn parent_rule() {
        assert!(parent_matches(FileRef::new(40, 2), FileRef::new(40, 2)));
        assert!(parent_matches(FileRef::new(40, 1), FileRef::new(40, 2)));
        assert!(!parent_matches(FileRef::new(40, 3), FileRef::new(40, 2)));
        assert!(!parent_matches(FileRef::new(41, 2), FileRef::new(40, 2)));
    }
}
