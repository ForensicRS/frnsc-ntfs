//! `$EA_INFORMATION` (0xD0) and `$EA` (0xE0): extended attributes.
//!
//! EAs are rare on Windows outside WSL (`$LXUID`, `$LXMOD`, ...) and are a known place to hide
//! data, so names and sizes are always reported.

use super::{u16_at, u32_at, AttrResult};

/// Cap on EA bytes parsed.
pub const MAX_EA: usize = 64 * 1024;

/// `$EA_INFORMATION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EaInfo {
    pub packed_size: u16,
    pub need_ea_count: u16,
    pub unpacked_size: u32,
}

impl EaInfo {
    pub fn parse(v: &[u8]) -> AttrResult<Self> {
        Ok(Self {
            packed_size: u16_at(v, 0)?,
            need_ea_count: u16_at(v, 2)?,
            unpacked_size: u32_at(v, 4)?,
        })
    }
}

/// One `$EA` entry (name and value size; the value itself is kept raw).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EaEntry {
    pub flags: u8,
    pub name: String,
    pub value: Vec<u8>,
}

/// Parses the `$EA` entries (bounded by [`MAX_EA`]).
pub fn parse_entries(v: &[u8], out: &mut Vec<EaEntry>) -> AttrResult<()> {
    let v = &v[..v.len().min(MAX_EA)];
    let mut off = 0usize;
    while off + 8 <= v.len() {
        let next = u32_at(v, off)? as usize;
        let flags = v[off + 4];
        let name_len = usize::from(v[off + 5]);
        let value_len = usize::from(u16_at(v, off + 6)?);
        let name_start = off + 8;
        let name = v
            .get(name_start..name_start + name_len)
            .ok_or("EA name truncated")?;
        // Name is followed by a NUL terminator, then the value.
        let value_start = name_start + name_len + 1;
        let value = v
            .get(value_start..value_start + value_len)
            .ok_or("EA value truncated")?;
        out.push(EaEntry {
            flags,
            name: String::from_utf8_lossy(name).into_owned(),
            value: value.to_vec(),
        });
        if next == 0 {
            break;
        }
        if next < 8 {
            return Err("EA next-entry offset too small");
        }
        off = off.checked_add(next).ok_or("EA offset overflow")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_entry() {
        let mut v = vec![0u8; 8];
        v[5] = 6;
        v[6] = 2;
        v.extend(b"$LXUID\0");
        v.extend([0xE8, 0x03]);
        let mut out = Vec::new();
        parse_entries(&v, &mut out).unwrap();
        assert_eq!(out[0].name, "$LXUID");
        assert_eq!(out[0].value, vec![0xE8, 0x03]);
        let mut out = Vec::new();
        assert!(parse_entries(&v[..12], &mut out).is_err());
    }
}
