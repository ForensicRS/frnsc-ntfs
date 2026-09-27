//! `NtfsFormatFactory`: probes and mounts an NTFS volume (a partition window from a volume
//! system, a bare partition image, or a `media` file flagged `VOLUME`).

use std::io::SeekFrom;
use std::sync::Arc;

use forensic_rs::prelude::*;

use super::fs::NtfsFs;
use super::Volume;
use crate::boot::{BootSector, BOOT_SECTOR_SIZE};
use crate::error;
use crate::fixup::apply_fixups;
use crate::source::RecordSource;

/// Adapts a forensic-rs `ReadAt` to this crate's [`RecordSource`].
pub struct ReadAtSource(pub Arc<dyn ReadAt>);

impl RecordSource for ReadAtSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        let len = self.0.size();
        if offset >= len {
            return Ok(0);
        }
        let n = buf.len().min((len - offset) as usize);
        self.0
            .read_exact_at(offset, &mut buf[..n])
            .map_err(|e| error::io(e, "reading the NTFS volume"))?;
        Ok(n)
    }

    fn len(&self) -> u64 {
        self.0.size()
    }
}

/// Mounts NTFS volumes as [`NtfsFs`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NtfsFormatFactory;

fn read_at(file: &mut dyn VirtualFile, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    file.seek(SeekFrom::Start(offset))?;
    let mut done = 0;
    while done < buf.len() {
        match file.read(&mut buf[done..])? {
            0 => break,
            n => done += n,
        }
    }
    Ok(done)
}

fn sniff(file: &mut dyn VirtualFile) -> ProbeScore {
    let mut sector = [0u8; BOOT_SECTOR_SIZE];
    let primary = match read_at(file, 0, &mut sector) {
        Ok(BOOT_SECTOR_SIZE) => BootSector::parse(&sector).ok(),
        _ => None,
    };
    if let Some(boot) = primary {
        let mut rec = vec![0u8; boot.mft_record_size as usize];
        let at = boot.mft_lcn.saturating_mul(boot.cluster_size);
        let ok = matches!(read_at(file, at, &mut rec), Ok(n) if n == rec.len())
            && &rec[..4] == b"FILE"
            && {
                let usa_off = u16::from_le_bytes([rec[4], rec[5]]);
                let usa_cnt = u16::from_le_bytes([rec[6], rec[7]]);
                apply_fixups(&mut rec, usa_off, usa_cnt).is_ok()
            };
        return if ok {
            ProbeScore::Exact
        } else {
            ProbeScore::Strong
        };
    }
    let Ok(len) = file.seek(SeekFrom::End(0)) else {
        return ProbeScore::No;
    };
    match len.checked_sub(BOOT_SECTOR_SIZE as u64) {
        Some(at)
            if matches!(read_at(file, at, &mut sector), Ok(BOOT_SECTOR_SIZE))
                && BootSector::parse(&sector).is_ok() =>
        {
            ProbeScore::Weak
        }
        _ => ProbeScore::No,
    }
}

impl FormatFactory for NtfsFormatFactory {
    fn name(&self) -> &'static str {
        "ntfs"
    }

    fn yields(&self) -> MountKind {
        MountKind::FileSystem
    }

    fn probe(
        &self,
        file: &mut dyn VirtualFile,
        _ctx: &MountContext<'_>,
    ) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let score = sniff(file);
        file.seek(SeekFrom::Start(start))?;
        Ok(score)
    }

    fn mount(&self, file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let media: Arc<dyn RecordSource> = Arc::new(ReadAtSource(into_read_at(file)?));
        let cancelled = || ctx.is_cancelled();
        let vol = Volume::open(media, &cancelled)?;
        Ok(Mounted::FileSystem(Arc::new(NtfsFs::new(
            Arc::new(vol),
            ctx.locator().clone(),
            ctx.fs().source(),
        ))))
    }

    /// Bare partition images. Partitions of a disk are reached through `FileAttributes::VOLUME`.
    fn extensions(&self) -> &[&'static str] {
        &["ntfs", "dd", "img", "raw"]
    }

    fn hop_cost(&self) -> HopCost {
        HopCost::View
    }
}
