//! `$VOLUME_INFORMATION` (0x70) of the `$Volume` metafile.

use super::AttrResult;

/// Volume dirty flag.
pub const VOLUME_DIRTY: u16 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub major: u8,
    pub minor: u8,
    pub flags: u16,
}

impl VolumeInfo {
    pub fn parse(v: &[u8]) -> AttrResult<Self> {
        let b = v.get(8..12).ok_or("$VOLUME_INFORMATION truncated")?;
        Ok(Self {
            major: b[0],
            minor: b[1],
            flags: u16::from_le_bytes([b[2], b[3]]),
        })
    }

    pub fn is_dirty(&self) -> bool {
        self.flags & VOLUME_DIRTY != 0
    }
}
