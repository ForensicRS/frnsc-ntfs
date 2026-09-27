//! `$FILE_NAME` (0x30). Also the key of every `$I30` index entry.

use super::{u32_at, u64_at, utf16_at, AttrResult};
use crate::reference::FileRef;
use crate::time::NtfsTimes;

/// Minimum size of a `$FILE_NAME` value (header without the name).
pub const FILE_NAME_HEADER: usize = 66;

/// Name namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Namespace {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
    Unknown(u8),
}

impl Namespace {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Namespace::Posix,
            1 => Namespace::Win32,
            2 => Namespace::Dos,
            3 => Namespace::Win32AndDos,
            other => Namespace::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Namespace::Posix => "posix",
            Namespace::Win32 => "win32",
            Namespace::Dos => "dos",
            Namespace::Win32AndDos => "win32_and_dos",
            Namespace::Unknown(_) => "unknown",
        }
    }

    /// Preference for the "primary" long name: Win32+DOS, Win32, POSIX, then DOS.
    pub fn rank(self) -> u8 {
        match self {
            Namespace::Win32AndDos => 0,
            Namespace::Win32 => 1,
            Namespace::Posix => 2,
            Namespace::Dos => 3,
            Namespace::Unknown(_) => 4,
        }
    }
}

/// Decoded `$FILE_NAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    pub parent: FileRef,
    pub times: NtfsTimes,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    /// Reparse tag when the file is a reparse point, otherwise the packed EA size.
    pub reparse_or_ea: u32,
    pub namespace: Namespace,
    pub name: String,
}

impl FileName {
    pub fn parse(v: &[u8]) -> AttrResult<Self> {
        if v.len() < FILE_NAME_HEADER {
            return Err("$FILE_NAME shorter than 66 bytes");
        }
        let name_len = usize::from(v[64]);
        if name_len == 0 {
            return Err("$FILE_NAME with an empty name");
        }
        Ok(Self {
            parent: FileRef::from_raw(u64_at(v, 0)?),
            times: NtfsTimes {
                created: u64_at(v, 8)?,
                modified: u64_at(v, 16)?,
                mft_modified: u64_at(v, 24)?,
                accessed: u64_at(v, 32)?,
            },
            allocated_size: u64_at(v, 40)?,
            real_size: u64_at(v, 48)?,
            flags: u32_at(v, 56)?,
            reparse_or_ea: u32_at(v, 60)?,
            namespace: Namespace::from_raw(v[65]),
            name: utf16_at(v, FILE_NAME_HEADER, name_len)?,
        })
    }

    /// Total bytes this value occupies (header + name).
    pub fn value_len(&self) -> usize {
        FILE_NAME_HEADER + self.name.encode_utf16().count() * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::file_name_value;

    #[test]
    fn round_trip() {
        let v = file_name_value(FileRef::new(5, 5), "Ärger.txt", 1, 3);
        let f = FileName::parse(&v).unwrap();
        assert_eq!(f.parent, FileRef::new(5, 5));
        assert_eq!(f.name, "Ärger.txt");
        assert_eq!(f.namespace, Namespace::Win32AndDos);
        assert_eq!(f.times.created, 1);
        for len in 0..v.len() {
            assert!(FileName::parse(&v[..len]).is_err());
        }
    }
}
