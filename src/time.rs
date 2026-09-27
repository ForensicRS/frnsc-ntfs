//! FILETIME handling. A zero FILETIME means "not set" and stays `None`.

use forensic_rs::prelude::ForensicTimestamp;

/// 1980-01-01T00:00:00Z as a FILETIME. Earlier values are implausible on NTFS.
pub const FILETIME_1980: u64 = 119_600_064_000_000_000;
/// 2100-01-01T00:00:00Z as a FILETIME. Later values are implausible.
pub const FILETIME_2100: u64 = 157_469_184_000_000_000;
/// FILETIME ticks per second.
pub const TICKS_PER_SECOND: u64 = 10_000_000;

/// Decodes a FILETIME; `0` (never set) is `None`.
pub fn filetime(raw: u64) -> Option<ForensicTimestamp> {
    (raw != 0).then(|| ForensicTimestamp::from_win_filetime(raw))
}

/// Whether a non-zero FILETIME lies in the plausible 1980..2100 window.
pub fn plausible(raw: u64) -> bool {
    (FILETIME_1980..FILETIME_2100).contains(&raw)
}

/// The four MACB FILETIMEs shared by `$STANDARD_INFORMATION`, `$FILE_NAME` and index keys, raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtfsTimes {
    pub created: u64,
    pub modified: u64,
    /// "MFT entry changed" (the `C` in MACB; ECS `file.ctime`).
    pub mft_modified: u64,
    pub accessed: u64,
}

impl NtfsTimes {
    pub fn all(&self) -> [u64; 4] {
        [
            self.created,
            self.modified,
            self.mft_modified,
            self.accessed,
        ]
    }

    /// True when every set value has no sub-second part (typical of tools that write whole
    /// seconds, e.g. older timestomping utilities, FAT/ZIP-sourced times).
    pub fn whole_seconds(&self) -> bool {
        let set: Vec<u64> = self.all().into_iter().filter(|&t| t != 0).collect();
        !set.is_empty() && set.iter().all(|t| t % TICKS_PER_SECOND == 0)
    }

    /// True when any set value is outside the plausible window.
    pub fn any_implausible(&self) -> bool {
        self.all().into_iter().any(|t| t != 0 && !plausible(t))
    }

    /// True when every value is set and plausible.
    pub fn all_plausible(&self) -> bool {
        self.all().into_iter().all(plausible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_none() {
        assert!(filetime(0).is_none());
        assert!(filetime(FILETIME_1980).is_some());
    }

    #[test]
    fn window_bounds() {
        assert!(plausible(FILETIME_1980));
        assert!(!plausible(FILETIME_1980 - 1));
        assert!(!plausible(FILETIME_2100));
    }
}
