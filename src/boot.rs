//! NTFS boot sector (`$Boot`, first sector of the volume; a backup lives in the last sector).

use forensic_rs::prelude::*;

use crate::error;

/// OEM ID of an NTFS boot sector.
pub const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
/// Size of the parsed boot sector.
pub const BOOT_SECTOR_SIZE: usize = 512;
/// Largest cluster size Windows formats (2 MiB).
pub const MAX_CLUSTER_SIZE: u64 = 2 * 1024 * 1024;
/// Bounds for MFT/index record sizes.
pub const MIN_RECORD_SIZE: u32 = 256;
pub const MAX_RECORD_SIZE: u32 = 64 * 1024;

/// Decoded NTFS boot sector (BIOS parameter block). Raw bytes are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSector {
    pub bytes_per_sector: u32,
    /// Raw sectors-per-cluster byte (values above 0x80 are a power-of-two exponent).
    pub sectors_per_cluster_raw: u8,
    pub cluster_size: u64,
    pub media_descriptor: u8,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    /// Raw signed `clusters per MFT record` byte.
    pub clusters_per_mft_record_raw: i8,
    pub mft_record_size: u32,
    /// Raw signed `clusters per index record` byte.
    pub clusters_per_index_record_raw: i8,
    pub index_record_size: u32,
    pub serial: u64,
    /// Whether the sector ends with `55 AA`.
    pub end_marker: bool,
    pub raw: Vec<u8>,
}

impl BootSector {
    /// Parses the first 512 bytes of `data` (a `$Boot` file or the volume's first sector).
    pub fn parse(data: &[u8]) -> ForensicResult<Self> {
        let sector = data.get(..BOOT_SECTOR_SIZE).ok_or_else(|| {
            ForensicError::buffer_too_small(BOOT_SECTOR_SIZE, data.len(), "ntfs boot sector")
        })?;
        let mut r = ByteReader::new(sector);
        r.skip(3)?;
        let oem: [u8; 8] = r.read_fixed()?;
        if &oem != NTFS_OEM_ID {
            return Err(error::invalid("boot sector OEM ID is not 'NTFS    '"));
        }
        let bytes_per_sector = u32::from(r.read_u16_le()?);
        if !(256..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
            return Err(error::invalid(format!(
                "bytes per sector {bytes_per_sector} is not a power of two in 256..=4096"
            )));
        }
        let spc = r.read_u8()?;
        let sectors_per_cluster: u64 = if spc > 0x80 {
            let shift = 256 - u32::from(spc);
            if shift > 31 {
                return Err(error::invalid(format!(
                    "sectors per cluster exponent {shift} out of range"
                )));
            }
            1u64 << shift
        } else {
            u64::from(spc)
        };
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(error::invalid(format!(
                "sectors per cluster {spc:#x} is not a power of two"
            )));
        }
        let cluster_size = sectors_per_cluster * u64::from(bytes_per_sector);
        if cluster_size > MAX_CLUSTER_SIZE {
            return Err(error::invalid(format!(
                "cluster size {cluster_size} exceeds 2 MiB"
            )));
        }
        r.seek_to(21)?;
        let media_descriptor = r.read_u8()?;
        r.seek_to(40)?;
        let total_sectors = r.read_u64_le()?;
        let mft_lcn = r.read_u64_le()?;
        let mftmirr_lcn = r.read_u64_le()?;
        let clusters_per_mft_record_raw = r.read_i8()?;
        r.skip(3)?;
        let clusters_per_index_record_raw = r.read_i8()?;
        r.skip(3)?;
        let serial = r.read_u64_le()?;
        let mft_record_size =
            record_size(clusters_per_mft_record_raw, cluster_size).ok_or_else(|| {
                error::invalid(format!(
                    "MFT record size encoding {clusters_per_mft_record_raw} out of range"
                ))
            })?;
        let index_record_size = record_size(clusters_per_index_record_raw, cluster_size)
            .ok_or_else(|| {
                error::invalid(format!(
                    "index record size encoding {clusters_per_index_record_raw} out of range"
                ))
            })?;
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster_raw: spc,
            cluster_size,
            media_descriptor,
            total_sectors,
            mft_lcn,
            mftmirr_lcn,
            clusters_per_mft_record_raw,
            mft_record_size,
            clusters_per_index_record_raw,
            index_record_size,
            serial,
            end_marker: sector[510] == 0x55 && sector[511] == 0xAA,
            raw: sector.to_vec(),
        })
    }

    /// Volume size in bytes as declared by the boot sector.
    pub fn volume_size(&self) -> u64 {
        self.total_sectors
            .saturating_mul(u64::from(self.bytes_per_sector))
    }

    /// Number of clusters in the volume.
    pub fn total_clusters(&self) -> u64 {
        self.volume_size() / self.cluster_size
    }

    /// Volume serial number as Windows prints it (`XXXX-XXXX`, low 32 bits).
    pub fn serial_short(&self) -> String {
        let low = self.serial as u32;
        format!("{:04X}-{:04X}", low >> 16, low & 0xFFFF)
    }
}

/// Decodes the signed "clusters per record" encoding: positive = clusters, negative = 2^-v bytes.
fn record_size(raw: i8, cluster_size: u64) -> Option<u32> {
    let size: u64 = if raw > 0 {
        u64::from(raw as u8).checked_mul(cluster_size)?
    } else if raw < 0 {
        let shift = u32::from(raw.unsigned_abs());
        if shift > 31 {
            return None;
        }
        1u64 << shift
    } else {
        return None;
    };
    let size = u32::try_from(size).ok()?;
    ((MIN_RECORD_SIZE..=MAX_RECORD_SIZE).contains(&size) && size.is_power_of_two()).then_some(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::boot_sector;

    #[test]
    fn parses_typical_4k_cluster_volume() {
        let raw = boot_sector(512, 8, 0x10_0000, 4, -10, 1);
        let b = BootSector::parse(&raw).unwrap();
        assert_eq!(b.cluster_size, 4096);
        assert_eq!(b.mft_record_size, 1024);
        assert_eq!(b.index_record_size, 4096);
        assert_eq!(b.mft_lcn, 4);
        assert!(b.end_marker);
        assert_eq!(b.total_clusters(), 0x10_0000 * 512 / 4096);
    }

    #[test]
    fn negative_spc_exponent_and_4k_sectors() {
        // 0xF4 => 2^12 sectors per cluster; with 4K sectors that exceeds 2 MiB.
        let mut raw = boot_sector(4096, 1, 1000, 4, -12, 1);
        raw[13] = 0xF4;
        assert!(BootSector::parse(&raw).is_err());
        // 0xF9 => 2^7 = 128 sectors * 512 = 64 KiB clusters.
        let mut raw = boot_sector(512, 1, 1 << 20, 4, -10, 1);
        raw[13] = 0xF9;
        let b = BootSector::parse(&raw).unwrap();
        assert_eq!(b.cluster_size, 64 * 1024);
    }

    #[test]
    fn rejects_non_ntfs_and_truncation() {
        let mut raw = boot_sector(512, 8, 1000, 4, -10, 1);
        raw[3] = b'X';
        assert!(BootSector::parse(&raw).is_err());
        let raw = boot_sector(512, 8, 1000, 4, -10, 1);
        for len in 0..BOOT_SECTOR_SIZE {
            assert!(BootSector::parse(&raw[..len]).is_err());
        }
    }

    #[test]
    fn record_size_encodings() {
        assert_eq!(record_size(-10, 4096), Some(1024));
        assert_eq!(record_size(-12, 4096), Some(4096));
        assert_eq!(record_size(1, 4096), Some(4096));
        assert_eq!(record_size(2, 512), Some(1024));
        assert_eq!(record_size(0, 4096), None);
        assert_eq!(record_size(-128, 4096), None);
        assert_eq!(record_size(127, 2 * 1024 * 1024), None);
    }
}
