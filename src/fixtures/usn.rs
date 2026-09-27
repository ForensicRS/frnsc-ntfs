//! USN record builders.

use super::utf16;
use crate::reference::FileRef;

/// A `USN_RECORD_V2`.
pub fn usn_v2(
    file: FileRef,
    parent: FileRef,
    usn: u64,
    time: u64,
    reason: u32,
    name: &str,
) -> Vec<u8> {
    let n = utf16(name);
    let len = (60 + n.len() + 7) & !7;
    let mut r = vec![0u8; len];
    r[0..4].copy_from_slice(&(len as u32).to_le_bytes());
    r[4..6].copy_from_slice(&2u16.to_le_bytes());
    r[8..16].copy_from_slice(&file.raw().to_le_bytes());
    r[16..24].copy_from_slice(&parent.raw().to_le_bytes());
    r[24..32].copy_from_slice(&usn.to_le_bytes());
    r[32..40].copy_from_slice(&time.to_le_bytes());
    r[40..44].copy_from_slice(&reason.to_le_bytes());
    r[52..56].copy_from_slice(&0x20u32.to_le_bytes());
    r[56..58].copy_from_slice(&(n.len() as u16).to_le_bytes());
    r[58..60].copy_from_slice(&60u16.to_le_bytes());
    r[60..60 + n.len()].copy_from_slice(&n);
    r
}

/// A `USN_RECORD_V3` (128-bit references).
pub fn usn_v3(
    file: FileRef,
    parent: FileRef,
    usn: u64,
    time: u64,
    reason: u32,
    name: &str,
) -> Vec<u8> {
    let n = utf16(name);
    let len = (76 + n.len() + 7) & !7;
    let mut r = vec![0u8; len];
    r[0..4].copy_from_slice(&(len as u32).to_le_bytes());
    r[4..6].copy_from_slice(&3u16.to_le_bytes());
    r[8..16].copy_from_slice(&file.raw().to_le_bytes());
    r[24..32].copy_from_slice(&parent.raw().to_le_bytes());
    r[40..48].copy_from_slice(&usn.to_le_bytes());
    r[48..56].copy_from_slice(&time.to_le_bytes());
    r[56..60].copy_from_slice(&reason.to_le_bytes());
    r[72..74].copy_from_slice(&(n.len() as u16).to_le_bytes());
    r[74..76].copy_from_slice(&76u16.to_le_bytes());
    r[76..76 + n.len()].copy_from_slice(&n);
    r
}
