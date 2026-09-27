//! NTFS file reference: 48-bit MFT entry number + 16-bit sequence number.

use std::fmt;

/// Well-known MFT entry of the root directory (`.`).
pub const ROOT_ENTRY: u64 = 5;

/// A file reference as stored on disk (`$FILE_NAME` parent, base record, index entry, USN record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileRef {
    pub entry: u64,
    pub sequence: u16,
}

impl FileRef {
    pub const fn new(entry: u64, sequence: u16) -> Self {
        Self { entry, sequence }
    }

    /// Splits the on-disk 64-bit value (low 48 bits entry, high 16 bits sequence).
    pub const fn from_raw(raw: u64) -> Self {
        Self {
            entry: raw & 0x0000_FFFF_FFFF_FFFF,
            sequence: (raw >> 48) as u16,
        }
    }

    /// The on-disk 64-bit value.
    pub const fn raw(self) -> u64 {
        (self.entry & 0x0000_FFFF_FFFF_FFFF) | ((self.sequence as u64) << 48)
    }

    /// All-zero reference: "no reference" in a base-record field.
    pub const fn is_zero(self) -> bool {
        self.entry == 0 && self.sequence == 0
    }
}

impl fmt::Display for FileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.entry, self.sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_joins() {
        let r = FileRef::from_raw(0x0003_0000_0000_0023);
        assert_eq!(r, FileRef::new(0x23, 3));
        assert_eq!(r.raw(), 0x0003_0000_0000_0023);
        assert_eq!(r.to_string(), "35-3");
    }
}
