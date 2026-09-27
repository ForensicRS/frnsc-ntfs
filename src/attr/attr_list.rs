//! `$ATTRIBUTE_LIST` (0x20): where each attribute of a file lives when it spans several records.

use super::{u16_at, u32_at, u64_at, utf16_at, AttrResult};
use crate::reference::FileRef;

/// Cap on the attribute list size read into memory.
pub const MAX_ATTRIBUTE_LIST: usize = 4 * 1024 * 1024;

/// One `$ATTRIBUTE_LIST` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrListEntry {
    pub type_code: u32,
    pub name: String,
    pub starting_vcn: u64,
    /// Record holding this attribute (the base record itself or an extension record).
    pub segment: FileRef,
    pub attribute_id: u16,
}

/// Parses every entry. Stops (with `Err`) at the first malformed entry, after returning what came
/// before it through `out`.
pub fn parse(v: &[u8], out: &mut Vec<AttrListEntry>) -> AttrResult<()> {
    let mut off = 0usize;
    while off < v.len() {
        let type_code = u32_at(v, off)?;
        if type_code == 0 || type_code == crate::record::attribute::ATTR_END {
            break;
        }
        let len = usize::from(u16_at(v, off + 4)?);
        if len < 26 || off + len > v.len() {
            return Err("attribute list entry length out of range");
        }
        let name_len = usize::from(*v.get(off + 6).ok_or("truncated")?);
        let name_off = usize::from(*v.get(off + 7).ok_or("truncated")?);
        let name = if name_len == 0 {
            String::new()
        } else {
            if name_off + name_len * 2 > len {
                return Err("attribute list entry name outside entry");
            }
            utf16_at(v, off + name_off, name_len)?
        };
        out.push(AttrListEntry {
            type_code,
            name,
            starting_vcn: u64_at(v, off + 8)?,
            segment: FileRef::from_raw(u64_at(v, off + 16)?),
            attribute_id: u16_at(v, off + 24)?,
        });
        off += len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(type_code: u32, segment: u64) -> Vec<u8> {
        let mut e = vec![0u8; 32];
        e[..4].copy_from_slice(&type_code.to_le_bytes());
        e[4..6].copy_from_slice(&32u16.to_le_bytes());
        e[7] = 26;
        e[16..24].copy_from_slice(&segment.to_le_bytes());
        e
    }

    #[test]
    fn parses_entries_and_stops_on_garbage() {
        let mut v = entry(0x10, 40);
        v.extend(entry(0x80, 41 | (1 << 48)));
        let mut out = Vec::new();
        parse(&v, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].segment, FileRef::new(41, 1));
        let mut bad = v.clone();
        bad[36] = 3;
        let mut out = Vec::new();
        assert!(parse(&bad, &mut out).is_err());
        assert_eq!(out.len(), 1);
    }
}
