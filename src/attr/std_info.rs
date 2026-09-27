//! `$STANDARD_INFORMATION` (0x10).

use super::{u32_at, u64_at, AttrResult};
use crate::time::NtfsTimes;

/// Decoded `$STANDARD_INFORMATION`. Version 1 (NT4, 48 bytes) lacks the v3 fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdInfo {
    pub times: NtfsTimes,
    /// DOS file attributes (`FILE_ATTRIBUTE_*`), raw.
    pub file_attributes: u32,
    pub max_versions: u32,
    pub version_number: u32,
    pub class_id: u32,
    /// `1` for the 48-byte NT4 layout, `3` for the 72-byte Windows 2000+ layout.
    pub layout: u8,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub quota_charged: Option<u64>,
    pub usn: Option<u64>,
}

impl StdInfo {
    pub fn parse(v: &[u8]) -> AttrResult<Self> {
        if v.len() < 48 {
            return Err("$STANDARD_INFORMATION shorter than 48 bytes");
        }
        let times = NtfsTimes {
            created: u64_at(v, 0)?,
            modified: u64_at(v, 8)?,
            mft_modified: u64_at(v, 16)?,
            accessed: u64_at(v, 24)?,
        };
        let v3 = v.len() >= 72;
        Ok(Self {
            times,
            file_attributes: u32_at(v, 32)?,
            max_versions: u32_at(v, 36)?,
            version_number: u32_at(v, 40)?,
            class_id: u32_at(v, 44)?,
            layout: if v3 { 3 } else { 1 },
            owner_id: if v3 { Some(u32_at(v, 48)?) } else { None },
            security_id: if v3 { Some(u32_at(v, 52)?) } else { None },
            quota_charged: if v3 { Some(u64_at(v, 56)?) } else { None },
            usn: if v3 { Some(u64_at(v, 64)?) } else { None },
        })
    }
}

/// DOS/NTFS file attribute bits, as named in output.
pub const FILE_ATTRIBUTE_NAMES: &[(u32, &str)] = &[
    (0x0000_0001, "readonly"),
    (0x0000_0002, "hidden"),
    (0x0000_0004, "system"),
    (0x0000_0010, "directory"),
    (0x0000_0020, "archive"),
    (0x0000_0040, "device"),
    (0x0000_0080, "normal"),
    (0x0000_0100, "temporary"),
    (0x0000_0200, "sparse_file"),
    (0x0000_0400, "reparse_point"),
    (0x0000_0800, "compressed"),
    (0x0000_1000, "offline"),
    (0x0000_2000, "not_content_indexed"),
    (0x0000_4000, "encrypted"),
    (0x0000_8000, "integrity_stream"),
    (0x0001_0000, "virtual"),
    (0x0002_0000, "no_scrub_data"),
    (0x0004_0000, "recall_on_open"),
    (0x0008_0000, "pinned"),
    (0x0010_0000, "unpinned"),
    (0x0040_0000, "recall_on_data_access"),
    (0x1000_0000, "dup_file_name_index_present"),
    (0x2000_0000, "dup_view_index_present"),
];

/// Lowercase names of the set bits (unknown bits are left to the raw value).
pub fn attribute_names(bits: u32) -> Vec<String> {
    FILE_ATTRIBUTE_NAMES
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| (*n).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_and_v3() {
        let mut v = vec![0u8; 72];
        v[0] = 1;
        v[32] = 0x20;
        v[52] = 0x07;
        let s = StdInfo::parse(&v).unwrap();
        assert_eq!(s.layout, 3);
        assert_eq!(s.security_id, Some(7));
        assert_eq!(s.times.created, 1);
        let s1 = StdInfo::parse(&v[..48]).unwrap();
        assert_eq!(s1.layout, 1);
        assert_eq!(s1.security_id, None);
        assert!(StdInfo::parse(&v[..47]).is_err());
        assert_eq!(attribute_names(0x21), vec!["readonly", "archive"]);
    }
}
