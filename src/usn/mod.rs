//! `$UsnJrnl:$J` change journal.
//!
//! The `$J` stream is sparse at the front (the journal is trimmed from the start) and pads the end
//! of each 4 KiB page with zeros, so an exported `$J` is mostly zeros followed by records. The
//! [`UsnReader`] streams the file in chunks, skips zeros without allocating them, and decodes
//! `USN_RECORD_V2`/`V3`/`V4`. Anything else at a record boundary is a malformed stretch: it is
//! reported once (one `Err` item with its offset and length) and the reader re-synchronises on the
//! next 8-byte boundary that holds a plausible record.

use forensic_rs::prelude::*;

use crate::error;
use crate::reference::FileRef;
use crate::source::RecordSource;

/// Largest record accepted.
pub const MAX_RECORD: usize = 64 * 1024;
const CHUNK: usize = 1 << 20;

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    /// Offset of the record in the `$J` stream.
    pub offset: u64,
    pub major: u16,
    pub minor: u16,
    pub file_reference: FileRef,
    pub parent_reference: FileRef,
    /// The 128-bit references of V3/V4 records, raw (`None` for V2).
    pub file_reference_128: Option<u128>,
    pub parent_reference_128: Option<u128>,
    pub usn: i64,
    /// Raw FILETIME (V2/V3 only).
    pub timestamp: Option<u64>,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: Option<u32>,
    pub file_attributes: Option<u32>,
    pub name: Option<String>,
    /// V4 range-tracking extents `(offset, length)`.
    pub extents: Vec<(i64, i64)>,
}

/// USN reason bits and their names.
pub const REASONS: &[(u32, &str)] = &[
    (0x0000_0001, "data_overwrite"),
    (0x0000_0002, "data_extend"),
    (0x0000_0004, "data_truncation"),
    (0x0000_0010, "named_data_overwrite"),
    (0x0000_0020, "named_data_extend"),
    (0x0000_0040, "named_data_truncation"),
    (0x0000_0100, "file_create"),
    (0x0000_0200, "file_delete"),
    (0x0000_0400, "ea_change"),
    (0x0000_0800, "security_change"),
    (0x0000_1000, "rename_old_name"),
    (0x0000_2000, "rename_new_name"),
    (0x0000_4000, "indexable_change"),
    (0x0000_8000, "basic_info_change"),
    (0x0001_0000, "hard_link_change"),
    (0x0002_0000, "compression_change"),
    (0x0004_0000, "encryption_change"),
    (0x0008_0000, "object_id_change"),
    (0x0010_0000, "reparse_point_change"),
    (0x0020_0000, "stream_change"),
    (0x0040_0000, "transacted_change"),
    (0x0080_0000, "integrity_change"),
    (0x0100_0000, "desired_storage_class_change"),
    (0x8000_0000, "close"),
];

/// Names of the set reason bits (unknown bits stay in the raw value).
pub fn reason_names(reason: u32) -> Vec<&'static str> {
    REASONS
        .iter()
        .filter(|(b, _)| reason & b != 0)
        .map(|(_, n)| *n)
        .collect()
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}
fn u128_at(b: &[u8], at: usize) -> Option<u128> {
    Some(u128::from_le_bytes(b.get(at..at + 16)?.try_into().ok()?))
}

/// Cheap header plausibility check at a candidate boundary: length and version.
fn plausible_header(b: &[u8]) -> Option<(usize, u16)> {
    let len = u32_at(b, 0)? as usize;
    let major = u16_at(b, 4)?;
    let min = match major {
        2 => 60,
        3 => 76,
        4 => 64,
        _ => return None,
    };
    (len >= min && len <= MAX_RECORD && len.is_multiple_of(8)).then_some((len, major))
}

impl UsnRecord {
    /// Decodes one record from exactly its bytes.
    pub fn parse(offset: u64, b: &[u8]) -> Result<Self, &'static str> {
        let (len, major) = plausible_header(b).ok_or("bad record length or version")?;
        let b = b.get(..len).ok_or("record truncated")?;
        let minor = u16_at(b, 6).ok_or("truncated")?;
        let name_at = |len_off: usize, off_off: usize| -> Result<String, &'static str> {
            let nlen = usize::from(u16_at(b, len_off).ok_or("truncated")?);
            let noff = usize::from(u16_at(b, off_off).ok_or("truncated")?);
            if nlen % 2 != 0 || noff < off_off + 2 {
                return Err("file name length or offset invalid");
            }
            let raw = b
                .get(noff..noff + nlen)
                .ok_or("file name outside the record")?;
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&units))
        };
        let t = |v: Option<u64>| v.ok_or("truncated");
        match major {
            2 => Ok(Self {
                offset,
                major,
                minor,
                file_reference: FileRef::from_raw(t(u64_at(b, 8))?),
                parent_reference: FileRef::from_raw(t(u64_at(b, 16))?),
                file_reference_128: None,
                parent_reference_128: None,
                usn: t(u64_at(b, 24))? as i64,
                timestamp: Some(t(u64_at(b, 32))?),
                reason: u32_at(b, 40).ok_or("truncated")?,
                source_info: u32_at(b, 44).ok_or("truncated")?,
                security_id: u32_at(b, 48),
                file_attributes: u32_at(b, 52),
                name: Some(name_at(56, 58)?),
                extents: Vec::new(),
            }),
            3 => {
                let fr = u128_at(b, 8).ok_or("truncated")?;
                let pr = u128_at(b, 24).ok_or("truncated")?;
                Ok(Self {
                    offset,
                    major,
                    minor,
                    file_reference: FileRef::from_raw(fr as u64),
                    parent_reference: FileRef::from_raw(pr as u64),
                    file_reference_128: Some(fr),
                    parent_reference_128: Some(pr),
                    usn: t(u64_at(b, 40))? as i64,
                    timestamp: Some(t(u64_at(b, 48))?),
                    reason: u32_at(b, 56).ok_or("truncated")?,
                    source_info: u32_at(b, 60).ok_or("truncated")?,
                    security_id: u32_at(b, 64),
                    file_attributes: u32_at(b, 68),
                    name: Some(name_at(72, 74)?),
                    extents: Vec::new(),
                })
            }
            _ => {
                let fr = u128_at(b, 8).ok_or("truncated")?;
                let pr = u128_at(b, 24).ok_or("truncated")?;
                let count = usize::from(u16_at(b, 60).ok_or("truncated")?);
                let size = usize::from(u16_at(b, 62).ok_or("truncated")?);
                let mut extents = Vec::new();
                if size >= 16 {
                    for i in 0..count {
                        let at = 64 + i * size;
                        let (Some(o), Some(l)) = (u64_at(b, at), u64_at(b, at + 8)) else {
                            return Err("extent outside the record");
                        };
                        extents.push((o as i64, l as i64));
                    }
                }
                Ok(Self {
                    offset,
                    major,
                    minor,
                    file_reference: FileRef::from_raw(fr as u64),
                    parent_reference: FileRef::from_raw(pr as u64),
                    file_reference_128: Some(fr),
                    parent_reference_128: Some(pr),
                    usn: t(u64_at(b, 40))? as i64,
                    timestamp: None,
                    reason: u32_at(b, 48).ok_or("truncated")?,
                    source_info: u32_at(b, 52).ok_or("truncated")?,
                    security_id: None,
                    file_attributes: None,
                    name: None,
                    extents,
                })
            }
        }
    }
}

/// Streaming reader over a `$J` stream.
pub struct UsnReader<'a> {
    src: &'a dyn RecordSource,
    buf: Vec<u8>,
    buf_start: u64,
    pos: u64,
    len: u64,
    /// Start of the current malformed stretch.
    bad_since: Option<u64>,
    /// Number of whole zero bytes skipped (sparse prefix and page padding).
    pub zero_bytes_skipped: u64,
}

impl<'a> UsnReader<'a> {
    pub fn new(src: &'a dyn RecordSource) -> Self {
        Self {
            src,
            buf: Vec::new(),
            buf_start: 0,
            pos: 0,
            len: src.len(),
            bad_since: None,
            zero_bytes_skipped: 0,
        }
    }

    /// Makes `[pos, pos + need)` available in the buffer (or as much as the file has).
    fn fill(&mut self, need: usize) -> ForensicResult<()> {
        let buf_end = self.buf_start + self.buf.len() as u64;
        let short = self.pos + need as u64 > buf_end && buf_end < self.len;
        if self.pos < self.buf_start || self.pos >= buf_end || short {
            let want = CHUNK.max(need);
            let mut buf = vec![0u8; want];
            let n = self.src.read_at(self.pos, &mut buf)?;
            buf.truncate(n);
            self.buf = buf;
            self.buf_start = self.pos;
        }
        Ok(())
    }

    fn window(&self) -> &[u8] {
        let start = usize::try_from(self.pos - self.buf_start).unwrap_or(usize::MAX);
        self.buf.get(start..).unwrap_or(&[])
    }

    fn close_bad(&mut self) -> Option<ForensicError> {
        let since = self.bad_since.take()?;
        Some(error::corrupted(
            since,
            format!(
                "malformed USN data: skipped {} bytes to the next valid record",
                self.pos - since
            ),
        ))
    }
}

impl Iterator for UsnReader<'_> {
    type Item = ForensicResult<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos + 8 > self.len {
                return self.close_bad().map(Err);
            }
            if let Err(e) = self.fill(MAX_RECORD) {
                self.pos = self.len;
                return Some(Err(e));
            }
            // Skip zero words fast (sparse prefix, page padding).
            let zeros = self
                .window()
                .as_chunks::<8>()
                .0
                .iter()
                .take_while(|w| w.iter().all(|&b| b == 0))
                .count()
                * 8;
            if zeros > 0 {
                self.pos += zeros as u64;
                if self.bad_since.is_none() {
                    self.zero_bytes_skipped += zeros as u64;
                }
                if let Some(e) = self.close_bad() {
                    return Some(Err(e));
                }
                continue;
            }
            let at = self.pos;
            let window = self.window();
            if window.len() < 8 {
                self.pos = self.len;
                continue;
            }
            let parsed = match plausible_header(window) {
                Some((len, _)) if window.len() >= len => {
                    Some(UsnRecord::parse(at, &window[..len]).map(|r| (r, len)))
                }
                _ => None,
            };
            match parsed {
                Some(Ok((rec, len))) => {
                    if let Some(e) = self.close_bad() {
                        // Report the stretch first; the record is read again on the next call.
                        return Some(Err(e));
                    }
                    self.pos += len as u64;
                    return Some(Ok(rec));
                }
                Some(Err(_)) | None => {
                    self.bad_since.get_or_insert(at);
                    self.pos += 8;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
