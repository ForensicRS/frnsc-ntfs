//! Carves old `$FILE_NAME` attributes from MFT record slack.
//!
//! When a record shrinks (a rename to a shorter name, an attribute removed), the old bytes stay
//! after the end marker. A resident `$FILE_NAME` attribute found there is a name the file (or a
//! previous file in this record) once had.

use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::recovery::Recovered;

use super::{admit_file_name, RecoveryStats};
use crate::attr::FileName;
use crate::mft::index::MftIndex;
use crate::record::attribute::ATTR_FILE_NAME;
use crate::reference::FileRef;

/// A resident attribute header is 24 bytes; `$FILE_NAME` values are 68..=576 bytes.
const HEADER: usize = 24;
const MIN_VALUE: usize = 68;
const MAX_VALUE: usize = 66 + 255 * 2;

/// A name carved from record slack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackName {
    /// Record the slack belongs to.
    pub record: FileRef,
    /// Offset of the carved attribute header inside the record.
    pub offset: usize,
    pub name: FileName,
}

/// Scans a record's slack (`slack`, found at `slack_offset` inside the record) for `$FILE_NAME`
/// attributes, at the record's 8-byte attribute alignment. `live` are the record's current names
/// (exact duplicates are not new evidence and are skipped). `index` validates the parent.
pub fn carve(
    record: FileRef,
    slack: &[u8],
    slack_offset: usize,
    live: &[FileName],
    index: &MftIndex,
    stats: &mut RecoveryStats,
) -> Vec<Recovered<SlackName>> {
    stats.units_scanned += 1;
    let mut out = Vec::new();
    let end = slack.len();
    let mut off = ((slack_offset + 7) & !7) - slack_offset;
    while off + HEADER + MIN_VALUE <= end {
        let rel = off;
        let at = slack_offset + rel;
        off += 8;
        let Some(h) = slack.get(rel..rel + HEADER) else {
            break;
        };
        if u32::from_le_bytes([h[0], h[1], h[2], h[3]]) != ATTR_FILE_NAME {
            continue;
        }
        let length = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        let non_resident = h[8];
        let value_len = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) as usize;
        let value_off = usize::from(u16::from_le_bytes([h[20], h[21]]));
        if non_resident != 0
            || value_off != HEADER
            || !(MIN_VALUE..=MAX_VALUE).contains(&value_len)
            || length < HEADER + value_len
            || !length.is_multiple_of(8)
        {
            continue;
        }
        stats.candidates_found += 1;
        let Some(value) = slack.get(rel + HEADER..rel + HEADER + value_len) else {
            stats.rejected += 1;
            continue;
        };
        let Some(name) = admit_file_name(value) else {
            stats.rejected += 1;
            continue;
        };
        if !parent_is_directory(index, name.parent)
            || live
                .iter()
                .any(|l| l.parent == name.parent && l.name == name.name)
        {
            stats.rejected += 1;
            continue;
        }
        stats.admitted += 1;
        out.push(Recovered::new(
            SlackName {
                record,
                offset: at,
                name,
            },
            Recovery::Slack,
            Locus::Ntfs {
                entry: record.entry,
                sequence: record.sequence,
                attribute: ATTR_FILE_NAME as u16,
                offset: at as u64,
            },
        ));
        off = rel + ((length + 7) & !7);
    }
    out
}

fn parent_is_directory(index: &MftIndex, parent: FileRef) -> bool {
    let slot = index.slot(parent.entry);
    slot.is_directory()
        && !slot.is_extension()
        && slot.sequence().is_some_and(|s| {
            s == parent.sequence || (!slot.in_use() && s == parent.sequence.wrapping_add(1))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        file_name_value_times, times, MftBuilder, RecordBuilder, FILE_TIME_2020 as T,
    };
    use crate::mft::Mft;

    fn old_fn_attr(parent: FileRef, name: &str) -> Vec<u8> {
        let value = file_name_value_times(parent, name, &times(T), 1, 0, 0);
        let len = (HEADER + value.len() + 7) & !7;
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        a[20..22].copy_from_slice(&(HEADER as u16).to_le_bytes());
        a[HEADER..HEADER + value.len()].copy_from_slice(&value);
        a
    }

    #[test]
    fn carves_old_name_and_rejects_noise() {
        let mut slack = vec![0u8; 8];
        slack.extend(old_fn_attr(
            FileRef::new(40, 1),
            "invoice_final_v2_REAL.exe",
        ));
        slack.extend(old_fn_attr(FileRef::new(99, 1), "no_such_parent.txt"));
        slack.extend([0x30, 0, 0, 0, 0xFF, 0xFF, 0, 0]);
        let mut b = MftBuilder::new();
        b.put(
            40,
            RecordBuilder::file(40, 1)
                .directory()
                .std_info(T)
                .file_name(5, 5, "Downloads", T)
                .build(),
        );
        b.put(
            42,
            RecordBuilder::file(42, 1)
                .std_info(T)
                .file_name(40, 1, "a.exe", T)
                .slack(&slack)
                .build(),
        );
        let m = Mft::from_bytes(b.build()).unwrap();
        let e = m.entry(42).unwrap().unwrap();
        let mut stats = RecoveryStats::default();
        let found = carve(
            e.reference,
            &e.slack,
            e.slack_offset,
            &e.names,
            m.index(),
            &mut stats,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value().name.name, "invoice_final_v2_REAL.exe");
        assert_eq!(found[0].recovery(), Recovery::Slack);
        assert_eq!(stats.admitted, 1);
        assert_eq!(stats.rejected, 1);
        assert_eq!(
            m.resolve(found[0].value().name.parent, &found[0].value().name.name)
                .path,
            "\\Downloads\\invoice_final_v2_REAL.exe"
        );
    }
}
