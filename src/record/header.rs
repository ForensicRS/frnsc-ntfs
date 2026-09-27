//! `FILE` record header.

use forensic_rs::prelude::*;

use crate::reference::FileRef;

/// Size of the header up to and including the record number field (XP+ layout).
pub const HEADER_SIZE: usize = 48;

/// Record header flag: record in use (allocated). Clear = deleted / free.
pub const FLAG_IN_USE: u16 = 0x0001;
/// Record header flag: record is a directory (has a `$I30` index).
pub const FLAG_DIRECTORY: u16 = 0x0002;
/// Record header flag: record is in `$Extend`.
pub const FLAG_IN_EXTEND: u16 = 0x0004;
/// Record header flag: record has a view index other than `$I30`.
pub const FLAG_VIEW_INDEX: u16 = 0x0008;

/// Record signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    File,
    Baad,
}

/// Decoded record header. All values are raw as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    pub signature: Signature,
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub sequence: u16,
    pub link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,
    pub used_size: u32,
    pub allocated_size: u32,
    /// Non-zero for an extension record: the base record it belongs to.
    pub base_reference: FileRef,
    pub next_attribute_id: u16,
    /// Record number stored in the header (XP+ layout only, i.e. `usa_offset >= 0x30`).
    pub record_number: Option<u32>,
}

impl RecordHeader {
    /// Parses the header. The caller has already checked the signature is `FILE` or `BAAD`.
    pub fn parse(buf: &[u8]) -> ForensicResult<Self> {
        let mut r = ByteReader::new(buf);
        let sig: [u8; 4] = r.read_fixed()?;
        let signature = match &sig {
            b"FILE" => Signature::File,
            b"BAAD" => Signature::Baad,
            _ => {
                return Err(crate::error::invalid(
                    "record signature is neither FILE nor BAAD",
                ))
            }
        };
        let usa_offset = r.read_u16_le()?;
        let usa_count = r.read_u16_le()?;
        let lsn = r.read_u64_le()?;
        let sequence = r.read_u16_le()?;
        let link_count = r.read_u16_le()?;
        let first_attribute_offset = r.read_u16_le()?;
        let flags = r.read_u16_le()?;
        let used_size = r.read_u32_le()?;
        let allocated_size = r.read_u32_le()?;
        let base_reference = FileRef::from_raw(r.read_u64_le()?);
        let next_attribute_id = r.read_u16_le()?;
        let record_number = if usa_offset >= 0x30 {
            r.seek_to(44)?;
            Some(r.read_u32_le()?)
        } else {
            None
        };
        Ok(Self {
            signature,
            usa_offset,
            usa_count,
            lsn,
            sequence,
            link_count,
            first_attribute_offset,
            flags,
            used_size,
            allocated_size,
            base_reference,
            next_attribute_id,
            record_number,
        })
    }

    pub fn in_use(&self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    pub fn is_directory(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    pub fn is_extension(&self) -> bool {
        !self.base_reference.is_zero()
    }

    /// Lowercase names of the set flags, raw value kept separately.
    pub fn flag_names(&self) -> Vec<Text> {
        let mut out = Vec::new();
        for (bit, name) in [
            (FLAG_IN_USE, "in_use"),
            (FLAG_DIRECTORY, "directory"),
            (FLAG_IN_EXTEND, "in_extend"),
            (FLAG_VIEW_INDEX, "view_index"),
        ] {
            if self.flags & bit != 0 {
                out.push(Text::Borrowed(name));
            }
        }
        out
    }
}
