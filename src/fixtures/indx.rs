//! `INDX` record and index entry builders.

use crate::fixup::protect;
use crate::reference::FileRef;

/// One `$I30` index entry (16-byte header + `$FILE_NAME` key, 8-aligned).
pub fn index_entry(reference: FileRef, key: &[u8]) -> Vec<u8> {
    let len = (16 + key.len() + 7) & !7;
    let mut e = vec![0u8; len];
    e[0..8].copy_from_slice(&reference.raw().to_le_bytes());
    e[8..10].copy_from_slice(&(len as u16).to_le_bytes());
    e[10..12].copy_from_slice(&(key.len() as u16).to_le_bytes());
    e[16..16 + key.len()].copy_from_slice(key);
    e
}

/// The terminating entry of a node.
pub fn last_entry() -> Vec<u8> {
    let mut e = vec![0u8; 16];
    e[8..10].copy_from_slice(&16u16.to_le_bytes());
    e[12..16].copy_from_slice(&2u32.to_le_bytes());
    e
}

/// An `INDX` record of `size` bytes holding `entries` (the last entry is appended), followed by
/// `slack` bytes after the used length.
pub fn indx_record(vcn: u64, entries: &[Vec<u8>], slack: &[u8], size: usize) -> Vec<u8> {
    let mut r = vec![0u8; size];
    let strides = size / 512;
    r[0..4].copy_from_slice(b"INDX");
    r[4..6].copy_from_slice(&0x28u16.to_le_bytes());
    r[6..8].copy_from_slice(&((strides + 1) as u16).to_le_bytes());
    r[16..24].copy_from_slice(&vcn.to_le_bytes());
    let first = (0x28 + 2 + strides * 2 + 7) & !7;
    let mut off = first;
    for e in entries.iter().chain(std::iter::once(&last_entry())) {
        r[off..off + e.len()].copy_from_slice(e);
        off += e.len();
    }
    r[24..28].copy_from_slice(&((first - 24) as u32).to_le_bytes());
    r[28..32].copy_from_slice(&((off - 24) as u32).to_le_bytes());
    r[32..36].copy_from_slice(&((size - 24) as u32).to_le_bytes());
    let n = slack.len().min(size - off);
    r[off..off + n].copy_from_slice(&slack[..n]);
    protect(&mut r, 0x28, 1);
    r
}
