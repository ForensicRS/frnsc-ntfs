//! Update sequence array ("fixups") for multi-sector records (`FILE`, `INDX`, `RCRD`).
//!
//! Before a record is written, NTFS copies the last two bytes of every 512-byte stride into the
//! update sequence array and replaces them with the update sequence number (USN). A reader checks
//! that every stride still ends with the USN (the write was complete) and restores the saved bytes.

/// Fixup stride. Always 512 bytes, whatever the physical sector size.
pub const FIXUP_STRIDE: usize = 512;

/// Result of applying the fixups to one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupStatus {
    /// Every stride ended with the USN; saved bytes restored.
    Ok,
    /// Some strides did not end with the USN: the record was torn mid-write (or tampered with).
    /// Those strides are left as read; the others are restored.
    Torn {
        /// Number of strides whose tail did not match.
        mismatched: u16,
        /// Index of the first mismatching stride.
        first: u16,
    },
    /// No stride ends with the USN, but every stride already holds the value saved in the array:
    /// the copy was made with fixups reverted (some collection tools and `ntfscat` do this). The
    /// record is consistent; the status records how it was stored.
    PreApplied,
    /// The update sequence array header itself is out of range; nothing was changed.
    Invalid,
}

impl FixupStatus {
    /// The record content is consistent (fixups valid, or already applied by the collector).
    pub fn is_ok(self) -> bool {
        matches!(self, FixupStatus::Ok | FixupStatus::PreApplied)
    }

    /// Stable lowercase name for output fields.
    pub fn name(self) -> &'static str {
        match self {
            FixupStatus::Ok => "ok",
            FixupStatus::Torn { .. } => "torn",
            FixupStatus::PreApplied => "pre_applied",
            FixupStatus::Invalid => "invalid",
        }
    }
}

/// Applies the fixups to `buf` in place. `usa_count` includes the USN itself, so the record spans
/// `usa_count - 1` strides.
pub fn apply_fixups(buf: &mut [u8], usa_offset: u16, usa_count: u16) -> FixupStatus {
    let usa_offset = usize::from(usa_offset);
    let usa_count = usize::from(usa_count);
    if usa_count < 2 || usa_offset % 2 != 0 {
        return FixupStatus::Invalid;
    }
    let strides = usa_count - 1;
    let usa_end = match usa_offset.checked_add(usa_count * 2) {
        Some(end) => end,
        None => return FixupStatus::Invalid,
    };
    if usa_end > buf.len() || strides * FIXUP_STRIDE > buf.len() || usa_end > FIXUP_STRIDE - 2 {
        return FixupStatus::Invalid;
    }
    let usn = [buf[usa_offset], buf[usa_offset + 1]];
    let mut mismatched = 0u16;
    let mut first = 0u16;
    let mut pre_applied = 0usize;
    for i in 0..strides {
        let tail = (i + 1) * FIXUP_STRIDE - 2;
        let saved = usa_offset + 2 + i * 2;
        if buf[tail] == usn[0] && buf[tail + 1] == usn[1] {
            buf[tail] = buf[saved];
            buf[tail + 1] = buf[saved + 1];
        } else {
            if buf[tail] == buf[saved] && buf[tail + 1] == buf[saved + 1] {
                pre_applied += 1;
            }
            if mismatched == 0 {
                first = i as u16;
            }
            mismatched = mismatched.saturating_add(1);
        }
    }
    if mismatched == 0 {
        FixupStatus::Ok
    } else if pre_applied == strides {
        FixupStatus::PreApplied
    } else {
        FixupStatus::Torn { mismatched, first }
    }
}

/// Inverse of [`apply_fixups`], for fixture builders: saves each stride tail into the array and
/// stamps `usn` in its place.
pub fn protect(buf: &mut [u8], usa_offset: usize, usn: u16) {
    let strides = buf.len() / FIXUP_STRIDE;
    let usn = usn.to_le_bytes();
    if usa_offset + 2 + strides * 2 > buf.len() {
        return;
    }
    buf[usa_offset..usa_offset + 2].copy_from_slice(&usn);
    for i in 0..strides {
        let tail = (i + 1) * FIXUP_STRIDE - 2;
        let saved = usa_offset + 2 + i * 2;
        buf[saved] = buf[tail];
        buf[saved + 1] = buf[tail + 1];
        buf[tail..tail + 2].copy_from_slice(&usn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Vec<u8> {
        let mut buf: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        protect(&mut buf, 0x30, 0x0007);
        buf
    }

    #[test]
    fn round_trip() {
        let original: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let mut buf = record();
        assert_eq!(apply_fixups(&mut buf, 0x30, 3), FixupStatus::Ok);
        assert_eq!(buf[510..512], original[510..512]);
        assert_eq!(buf[1022..1024], original[1022..1024]);
    }

    #[test]
    fn torn_second_sector() {
        let mut buf = record();
        buf[1022] ^= 0xFF;
        assert_eq!(
            apply_fixups(&mut buf, 0x30, 3),
            FixupStatus::Torn {
                mismatched: 1,
                first: 1
            }
        );
    }

    #[test]
    fn invalid_headers_never_panic() {
        let mut buf = record();
        assert_eq!(apply_fixups(&mut buf, 0x31, 3), FixupStatus::Invalid);
        assert_eq!(apply_fixups(&mut buf, 0x30, 0), FixupStatus::Invalid);
        assert_eq!(apply_fixups(&mut buf, 0x30, 200), FixupStatus::Invalid);
        assert_eq!(apply_fixups(&mut buf, 0xFFFE, 0xFFFF), FixupStatus::Invalid);
        let mut short = vec![0u8; 100];
        assert_eq!(apply_fixups(&mut short, 0x30, 3), FixupStatus::Invalid);
    }

    #[test]
    fn already_applied_copies_are_recognised() {
        let mut buf = record();
        assert_eq!(apply_fixups(&mut buf, 0x30, 3), FixupStatus::Ok);
        // Applying again: tails now hold the saved values, not the USN.
        assert_eq!(apply_fixups(&mut buf, 0x30, 3), FixupStatus::PreApplied);
        assert!(FixupStatus::PreApplied.is_ok());
    }

    #[test]
    fn works_on_4k_records() {
        let mut buf = vec![0xABu8; 4096];
        protect(&mut buf, 0x30, 2);
        assert_eq!(apply_fixups(&mut buf, 0x30, 9), FixupStatus::Ok);
        assert!(buf.iter().skip(0x30 + 18).all(|&b| b == 0xAB));
    }
}
