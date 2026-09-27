//! One MFT record (`FILE`): header, fixups, attributes, slack.

pub mod attribute;
pub mod header;

use forensic_rs::prelude::*;

pub use attribute::{AttrBody, Attribute, NonResident};
pub use header::{RecordHeader, Signature};

use crate::anomaly::NtfsAnomaly;
use crate::error;
use crate::fixup::{apply_fixups, FixupStatus};
use crate::reference::FileRef;

/// A parsed MFT record.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// Position of the record in the MFT (its entry number).
    pub entry: u64,
    pub header: RecordHeader,
    pub fixup: FixupStatus,
    pub attributes: Vec<Attribute>,
    /// Byte range `[used_size, allocated_size)` inside [`Self::bytes`]: record slack.
    pub slack: std::ops::Range<usize>,
    pub anomalies: Vec<NtfsAnomaly>,
    /// Fixed-up record bytes (fixups applied where they matched).
    pub bytes: Vec<u8>,
}

impl MftRecord {
    /// Parses the record at MFT position `entry` from its raw bytes.
    ///
    /// Returns `Ok(None)` for a never-initialised (all-zero) record, and `Err` when the bytes are
    /// not a `FILE`/`BAAD` record at all.
    pub fn parse(entry: u64, raw: &[u8]) -> ForensicResult<Option<Self>> {
        if raw.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        let mut bytes = raw.to_vec();
        let header = RecordHeader::parse(&bytes)
            .map_err(|e| error::invalid(format!("MFT entry {entry}: {e}")))?;
        let mut anomalies = Vec::new();
        let fixup = apply_fixups(&mut bytes, header.usa_offset, header.usa_count);
        match fixup {
            FixupStatus::Ok | FixupStatus::PreApplied => {}
            FixupStatus::Torn { mismatched, first } => {
                anomalies.push(NtfsAnomaly::FixupMismatch { mismatched, first })
            }
            FixupStatus::Invalid => anomalies.push(NtfsAnomaly::FixupInvalid {
                usa_offset: header.usa_offset,
                usa_count: header.usa_count,
            }),
        }
        if header.signature == Signature::Baad {
            anomalies.push(NtfsAnomaly::BaadSignature);
        }
        if let Some(stored) = header.record_number {
            if u64::from(stored) != entry & 0xFFFF_FFFF {
                anomalies.push(NtfsAnomaly::RecordNumberMismatch {
                    stored,
                    actual: entry,
                });
            }
        }
        let allocated = (header.allocated_size as usize).min(bytes.len());
        let mut used = header.used_size as usize;
        if used > allocated {
            anomalies.push(NtfsAnomaly::UsedSizeExceedsAllocated {
                used: header.used_size,
                allocated: header.allocated_size,
            });
            used = allocated;
        }
        let first = usize::from(header.first_attribute_offset);
        let attributes = if header.signature == Signature::Baad {
            Vec::new()
        } else if first < 0x2A || first >= used {
            anomalies.push(NtfsAnomaly::AttributeOverrun {
                offset: first,
                length: 0,
            });
            Vec::new()
        } else {
            attribute::parse_attributes(&bytes, first, used, &mut anomalies)
        };
        Ok(Some(Self {
            entry,
            header,
            fixup,
            attributes,
            slack: used..allocated,
            anomalies,
            bytes,
        }))
    }

    /// This record's file reference (entry + header sequence).
    pub fn reference(&self) -> FileRef {
        FileRef::new(self.entry, self.header.sequence)
    }

    pub fn slack_bytes(&self) -> &[u8] {
        self.bytes.get(self.slack.clone()).unwrap_or(&[])
    }

    /// Attributes of a given type.
    pub fn attributes_of(&self, type_code: u32) -> impl Iterator<Item = &Attribute> {
        self.attributes
            .iter()
            .filter(move |a| a.type_code == type_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{RecordBuilder, FILE_TIME_2020};

    #[test]
    fn empty_record_is_none() {
        assert!(MftRecord::parse(3, &[0u8; 1024]).unwrap().is_none());
    }

    #[test]
    fn garbage_is_error() {
        assert!(MftRecord::parse(3, &[0x41u8; 1024]).is_err());
    }

    #[test]
    fn parses_built_record() {
        let raw = RecordBuilder::file(40, 2)
            .std_info(FILE_TIME_2020)
            .file_name(5, 5, "hello.txt", FILE_TIME_2020)
            .resident_data("", b"hi there")
            .build();
        let rec = MftRecord::parse(40, &raw).unwrap().unwrap();
        assert!(rec.fixup.is_ok());
        assert!(rec.anomalies.is_empty(), "{:?}", rec.anomalies);
        assert_eq!(rec.attributes.len(), 3);
        assert_eq!(rec.reference(), FileRef::new(40, 2));
        assert!(!rec.slack.is_empty());
    }

    #[test]
    fn torn_and_mismatched_number_are_anomalies() {
        let mut raw = RecordBuilder::file(40, 2).std_info(FILE_TIME_2020).build();
        raw[1022] ^= 0x55;
        let rec = MftRecord::parse(41, &raw).unwrap().unwrap();
        let names: Vec<_> = rec.anomalies.iter().map(|a| a.name()).collect();
        assert!(names.contains(&"fixup_mismatch"));
        assert!(names.contains(&"record_number_mismatch"));
    }

    #[test]
    fn baad_record_keeps_header() {
        let mut raw = RecordBuilder::file(9, 1).std_info(FILE_TIME_2020).build();
        raw[..4].copy_from_slice(b"BAAD");
        let rec = MftRecord::parse(9, &raw).unwrap().unwrap();
        assert!(rec.attributes.is_empty());
        assert!(rec.anomalies.contains(&NtfsAnomaly::BaadSignature));
    }

    #[test]
    fn every_prefix_and_bitflip_is_safe() {
        let raw = RecordBuilder::file(40, 2)
            .std_info(FILE_TIME_2020)
            .file_name(5, 5, "a.txt", FILE_TIME_2020)
            .resident_data("", b"x")
            .build();
        for len in 0..raw.len() {
            let _ = MftRecord::parse(40, &raw[..len]);
        }
        for i in 0..raw.len() {
            for bit in [0x01u8, 0x80] {
                let mut m = raw.clone();
                m[i] ^= bit;
                let _ = MftRecord::parse(40, &m);
            }
        }
    }
}
