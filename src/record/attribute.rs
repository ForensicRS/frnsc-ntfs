//! Attribute headers (resident and non-resident) and the bounded attribute iterator.

use forensic_rs::prelude::*;

use crate::anomaly::NtfsAnomaly;

pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_OBJECT_ID: u32 = 0x40;
pub const ATTR_SECURITY_DESCRIPTOR: u32 = 0x50;
pub const ATTR_VOLUME_NAME: u32 = 0x60;
pub const ATTR_VOLUME_INFORMATION: u32 = 0x70;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_INDEX_ROOT: u32 = 0x90;
pub const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
pub const ATTR_BITMAP: u32 = 0xB0;
pub const ATTR_REPARSE_POINT: u32 = 0xC0;
pub const ATTR_EA_INFORMATION: u32 = 0xD0;
pub const ATTR_EA: u32 = 0xE0;
pub const ATTR_LOGGED_UTILITY_STREAM: u32 = 0x100;
pub const ATTR_END: u32 = 0xFFFF_FFFF;

/// Attribute flag bits.
pub const ATTR_FLAG_COMPRESSED_MASK: u16 = 0x00FF;
pub const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
pub const ATTR_FLAG_SPARSE: u16 = 0x8000;

/// `$DATA`/`$STANDARD_INFORMATION` type name for display (`$DATA`, ...).
pub fn type_name(type_code: u32) -> &'static str {
    match type_code {
        ATTR_STANDARD_INFORMATION => "$STANDARD_INFORMATION",
        ATTR_ATTRIBUTE_LIST => "$ATTRIBUTE_LIST",
        ATTR_FILE_NAME => "$FILE_NAME",
        ATTR_OBJECT_ID => "$OBJECT_ID",
        ATTR_SECURITY_DESCRIPTOR => "$SECURITY_DESCRIPTOR",
        ATTR_VOLUME_NAME => "$VOLUME_NAME",
        ATTR_VOLUME_INFORMATION => "$VOLUME_INFORMATION",
        ATTR_DATA => "$DATA",
        ATTR_INDEX_ROOT => "$INDEX_ROOT",
        ATTR_INDEX_ALLOCATION => "$INDEX_ALLOCATION",
        ATTR_BITMAP => "$BITMAP",
        ATTR_REPARSE_POINT => "$REPARSE_POINT",
        ATTR_EA_INFORMATION => "$EA_INFORMATION",
        ATTR_EA => "$EA",
        ATTR_LOGGED_UTILITY_STREAM => "$LOGGED_UTILITY_STREAM",
        _ => "unknown",
    }
}

/// Non-resident attribute header (the content lives in clusters described by data runs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonResident {
    pub starting_vcn: u64,
    pub last_vcn: u64,
    /// log2 of the compression unit in clusters (0 = not compressed; 4 = 16 clusters).
    pub compression_unit: u16,
    pub allocated_size: u64,
    pub data_size: u64,
    pub initialized_size: u64,
    /// Present on compressed/sparse attributes (header of 72 bytes).
    pub total_allocated: Option<u64>,
    /// Raw data run bytes; decode with [`crate::runlist::decode`].
    pub runlist: Vec<u8>,
}

/// Attribute content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrBody {
    Resident { value: Vec<u8>, indexed: bool },
    NonResident(NonResident),
}

/// One attribute of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub type_code: u32,
    /// Attribute name (empty for the unnamed stream). Decoded lossily from UTF-16.
    pub name: String,
    pub flags: u16,
    pub id: u16,
    /// Offset of the attribute header inside its record.
    pub offset: usize,
    pub body: AttrBody,
}

impl Attribute {
    pub fn is_resident(&self) -> bool {
        matches!(self.body, AttrBody::Resident { .. })
    }

    pub fn resident_value(&self) -> Option<&[u8]> {
        match &self.body {
            AttrBody::Resident { value, .. } => Some(value),
            AttrBody::NonResident(_) => None,
        }
    }

    pub fn non_resident(&self) -> Option<&NonResident> {
        match &self.body {
            AttrBody::NonResident(nr) => Some(nr),
            AttrBody::Resident { .. } => None,
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & ATTR_FLAG_COMPRESSED_MASK != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & ATTR_FLAG_ENCRYPTED != 0
    }

    pub fn is_sparse(&self) -> bool {
        self.flags & ATTR_FLAG_SPARSE != 0
    }

    /// Logical content size (resident value length or non-resident data size).
    pub fn data_size(&self) -> u64 {
        match &self.body {
            AttrBody::Resident { value, .. } => value.len() as u64,
            AttrBody::NonResident(nr) => nr.data_size,
        }
    }
}

/// Parses every attribute in `record[start..end]` (the used area of a fixed-up record).
///
/// Stops at the end marker. A malformed header stops the walk with an anomaly rather than
/// failing the record: the attributes before it are still evidence.
pub fn parse_attributes(
    record: &[u8],
    start: usize,
    end: usize,
    anomalies: &mut Vec<NtfsAnomaly>,
) -> Vec<Attribute> {
    let end = end.min(record.len());
    let mut out = Vec::new();
    let mut offset = start;
    let mut saw_end = false;
    while offset + 4 <= end {
        let Some(type_code) = u32_at(record, offset) else {
            break;
        };
        if type_code == ATTR_END {
            saw_end = true;
            break;
        }
        let Some(length) = u32_at(record, offset + 4) else {
            anomalies.push(NtfsAnomaly::AttributeOverrun { offset, length: 0 });
            break;
        };
        let length_usize = length as usize;
        if length < 16
            || length % 8 != 0
            || offset.checked_add(length_usize).is_none_or(|e| e > end)
        {
            anomalies.push(NtfsAnomaly::AttributeOverrun { offset, length });
            break;
        }
        let bytes = &record[offset..offset + length_usize];
        match parse_one(type_code, bytes, offset) {
            Ok(attr) => out.push(attr),
            Err(reason) => anomalies.push(NtfsAnomaly::AttributeMalformed { type_code, reason }),
        }
        offset += length_usize;
    }
    if !saw_end
        && !anomalies
            .iter()
            .any(|a| matches!(a, NtfsAnomaly::AttributeOverrun { .. }))
    {
        anomalies.push(NtfsAnomaly::MissingEndMarker);
    }
    out
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn parse_one(type_code: u32, bytes: &[u8], offset: usize) -> Result<Attribute, &'static str> {
    let mut r = ByteReader::new(bytes);
    let err = |_| "header truncated";
    r.skip(8).map_err(err)?;
    let non_resident = r.read_u8().map_err(err)?;
    let name_length = usize::from(r.read_u8().map_err(err)?);
    let name_offset = usize::from(r.read_u16_le().map_err(err)?);
    let flags = r.read_u16_le().map_err(err)?;
    let id = r.read_u16_le().map_err(err)?;
    let name = if name_length == 0 {
        String::new()
    } else {
        let start = name_offset;
        let stop = start.checked_add(name_length * 2).ok_or("name overflow")?;
        let raw = bytes.get(start..stop).ok_or("name outside attribute")?;
        ByteReader::new(raw)
            .read_utf16le_string(raw.len())
            .map_err(|_| "name not UTF-16")?
    };
    let body = match non_resident {
        0 => {
            let value_length = r.read_u32_le().map_err(err)? as usize;
            let value_offset = usize::from(r.read_u16_le().map_err(err)?);
            let indexed = r.read_u8().map_err(err)? != 0;
            let stop = value_offset
                .checked_add(value_length)
                .ok_or("value overflow")?;
            let value = bytes
                .get(value_offset..stop)
                .ok_or("resident value outside attribute")?;
            AttrBody::Resident {
                value: value.to_vec(),
                indexed,
            }
        }
        1 => {
            let starting_vcn = r.read_u64_le().map_err(err)?;
            let last_vcn = r.read_u64_le().map_err(err)?;
            let runlist_offset = usize::from(r.read_u16_le().map_err(err)?);
            let compression_unit = r.read_u16_le().map_err(err)?;
            r.skip(4).map_err(err)?;
            let allocated_size = r.read_u64_le().map_err(err)?;
            let data_size = r.read_u64_le().map_err(err)?;
            let initialized_size = r.read_u64_le().map_err(err)?;
            let total_allocated = if runlist_offset >= 72 && bytes.len() >= 72 {
                Some(r.read_u64_le().map_err(err)?)
            } else {
                None
            };
            let runlist = bytes
                .get(runlist_offset..)
                .ok_or("run list outside attribute")?
                .to_vec();
            AttrBody::NonResident(NonResident {
                starting_vcn,
                last_vcn,
                compression_unit,
                allocated_size,
                data_size,
                initialized_size,
                total_allocated,
                runlist,
            })
        }
        _ => return Err("non-resident flag is neither 0 nor 1"),
    };
    Ok(Attribute {
        type_code,
        name,
        flags,
        id,
        offset,
        body,
    })
}
