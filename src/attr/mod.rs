//! Decoders for attribute values. Each returns `Err(&'static str)` with the reason on malformed
//! input; the caller records it as an [`crate::anomaly::NtfsAnomaly::AttributeMalformed`].

pub mod attr_list;
pub mod ea;
pub mod file_name;
pub mod object_id;
pub mod reparse;
pub mod std_info;
pub mod volume;

pub use attr_list::AttrListEntry;
pub use ea::{EaEntry, EaInfo};
pub use file_name::{FileName, Namespace};
pub use object_id::ObjectId;
pub use reparse::Reparse;
pub use std_info::StdInfo;
pub use volume::VolumeInfo;

/// Result type of the attribute decoders.
pub type AttrResult<T> = Result<T, &'static str>;

pub(crate) fn u16_at(b: &[u8], at: usize) -> AttrResult<u16> {
    let s = b
        .get(at..at.checked_add(2).ok_or("truncated")?)
        .ok_or("truncated")?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> AttrResult<u32> {
    let s = b
        .get(at..at.checked_add(4).ok_or("truncated")?)
        .ok_or("truncated")?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> AttrResult<u64> {
    let s = b
        .get(at..at.checked_add(8).ok_or("truncated")?)
        .ok_or("truncated")?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// Decodes `len_chars` UTF-16LE code units at `at`. Unpaired surrogates become U+FFFD; the
/// caller keeps the raw bytes where exactness matters.
pub(crate) fn utf16_at(b: &[u8], at: usize, len_chars: usize) -> AttrResult<String> {
    let end = at
        .checked_add(len_chars.checked_mul(2).ok_or("name overflow")?)
        .ok_or("name overflow")?;
    let s = b.get(at..end).ok_or("name truncated")?;
    let units: Vec<u16> = s
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Strict UTF-16 check used by recovery gates: no unpaired surrogates, no NUL, no C0 controls.
pub(crate) fn strict_utf16_name(b: &[u8]) -> Option<String> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16(&units).ok()?;
    (!s.is_empty() && !s.chars().any(|c| c.is_control())).then_some(s)
}

/// Formats a GUID stored little-endian (Windows layout).
pub(crate) fn guid(b: &[u8]) -> AttrResult<String> {
    let s = b.get(..16).ok_or("GUID truncated")?;
    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        u16::from_le_bytes([s[4], s[5]]),
        u16::from_le_bytes([s[6], s[7]]),
        s[8],
        s[9],
        s[10],
        s[11],
        s[12],
        s[13],
        s[14],
        s[15]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_layout() {
        let b = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        assert_eq!(guid(&b).unwrap(), "{00112233-4455-6677-8899-AABBCCDDEEFF}");
        assert!(guid(&b[..15]).is_err());
    }

    #[test]
    fn strict_names() {
        let enc = |s: &str| {
            s.encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>()
        };
        assert_eq!(strict_utf16_name(&enc("a.txt")).as_deref(), Some("a.txt"));
        assert!(strict_utf16_name(&enc("a\0b")).is_none());
        assert!(strict_utf16_name(&[0x00, 0xD8]).is_none());
        assert!(strict_utf16_name(&[]).is_none());
    }
}
