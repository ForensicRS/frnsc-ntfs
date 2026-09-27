//! `$REPARSE_POINT` (0xC0).

use super::{u16_at, u32_at, utf16_at, AttrResult};

pub const TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const TAG_SYMLINK: u32 = 0xA000_000C;
pub const TAG_HSM: u32 = 0xC000_0004;
pub const TAG_DEDUP: u32 = 0x8000_0013;
pub const TAG_WOF: u32 = 0x8000_0017;
pub const TAG_APPEXECLINK: u32 = 0x8000_001B;
pub const TAG_LX_SYMLINK: u32 = 0xA000_001D;
pub const TAG_AF_UNIX: u32 = 0x8000_0023;
pub const TAG_ONEDRIVE: u32 = 0x8000_0021;
/// Cloud files placeholders use `0x9000_x01A` (x = 0..F).
pub const TAG_CLOUD_MASK: u32 = 0xFFFF_0FFF;
pub const TAG_CLOUD: u32 = 0x9000_001A;

/// Cap on reparse data kept.
pub const MAX_REPARSE_DATA: usize = 16 * 1024;

/// Decoded reparse point. Unknown tags keep their raw data only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reparse {
    pub tag: u32,
    pub substitute_name: Option<String>,
    pub print_name: Option<String>,
    /// Symlink flags (1 = relative). `None` for other tags.
    pub symlink_flags: Option<u32>,
    pub data: Vec<u8>,
}

impl Reparse {
    pub fn parse(v: &[u8]) -> AttrResult<Self> {
        let tag = u32_at(v, 0)?;
        let len = usize::from(u16_at(v, 4)?);
        let data = v
            .get(8..8 + len.min(MAX_REPARSE_DATA))
            .ok_or("reparse data truncated")?
            .to_vec();
        let mut out = Self {
            tag,
            substitute_name: None,
            print_name: None,
            symlink_flags: None,
            data,
        };
        let buffer_start = match tag {
            TAG_MOUNT_POINT => Some(8usize),
            TAG_SYMLINK => {
                out.symlink_flags = Some(u32_at(&out.data, 8)?);
                Some(12)
            }
            _ => None,
        };
        if let Some(start) = buffer_start {
            let d = &out.data;
            let sub_off = usize::from(u16_at(d, 0)?);
            let sub_len = usize::from(u16_at(d, 2)?);
            let pr_off = usize::from(u16_at(d, 4)?);
            let pr_len = usize::from(u16_at(d, 6)?);
            if sub_len % 2 != 0 || pr_len % 2 != 0 {
                return Err("reparse name length is odd");
            }
            out.substitute_name = Some(utf16_at(d, start + sub_off, sub_len / 2)?);
            out.print_name = Some(utf16_at(d, start + pr_off, pr_len / 2)?);
        }
        Ok(out)
    }

    /// Where the link points, preferring the print name.
    pub fn target(&self) -> Option<&str> {
        self.print_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(self.substitute_name.as_deref())
    }
}

/// Human name of a reparse tag.
pub fn tag_name(tag: u32) -> &'static str {
    match tag {
        TAG_MOUNT_POINT => "mount_point",
        TAG_SYMLINK => "symlink",
        TAG_HSM => "hsm",
        TAG_DEDUP => "dedup",
        TAG_WOF => "wof",
        TAG_APPEXECLINK => "appexeclink",
        TAG_LX_SYMLINK => "lx_symlink",
        TAG_AF_UNIX => "af_unix",
        TAG_ONEDRIVE => "onedrive",
        t if t & TAG_CLOUD_MASK == TAG_CLOUD => "cloud",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn symlink() {
        let sub = utf16("\\??\\C:\\target");
        let pr = utf16("C:\\target");
        let mut d = Vec::new();
        d.extend(0u16.to_le_bytes());
        d.extend((sub.len() as u16).to_le_bytes());
        d.extend((sub.len() as u16).to_le_bytes());
        d.extend((pr.len() as u16).to_le_bytes());
        d.extend(0u32.to_le_bytes());
        d.extend(&sub);
        d.extend(&pr);
        let mut v = Vec::new();
        v.extend(TAG_SYMLINK.to_le_bytes());
        v.extend((d.len() as u16).to_le_bytes());
        v.extend(0u16.to_le_bytes());
        v.extend(&d);
        let r = Reparse::parse(&v).unwrap();
        assert_eq!(r.target(), Some("C:\\target"));
        assert_eq!(r.symlink_flags, Some(0));
        assert_eq!(tag_name(r.tag), "symlink");
        for len in 0..v.len() {
            assert!(Reparse::parse(&v[..len]).is_err());
        }
        assert_eq!(tag_name(0x9000_601A), "cloud");
    }
}
