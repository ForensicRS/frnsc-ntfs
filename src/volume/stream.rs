//! Reading attribute content from a volume: non-resident (data runs, sparse, valid data length),
//! compressed (LZNT1 compression units) and plain windows of the volume.
//!
//! Every read is exact or an error: a read past the end of a truncated image is
//! `UnexpectedEof`, never silently zero-filled. Zeros are returned only where NTFS itself defines
//! them (sparse runs, bytes past the valid data length, the tail of a compression unit).

use std::sync::{Arc, Mutex};

use forensic_rs::prelude::*;
use forensic_rs::traits::vfs::VMetadata;
use forensic_rs::utils::win::decompress::lznt1;

use crate::error;
use crate::runlist::{Run, Runlist};
use crate::source::RecordSource;

/// Largest compression unit supported (16 clusters of 4 KiB).
pub const MAX_COMPRESSION_UNIT: u64 = 64 * 1024;

fn eof(what: &str, offset: u64) -> ForensicError {
    error::io(
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("{what} at volume offset {offset}"),
        ),
        "reading the NTFS volume",
    )
}

/// Reads exactly `buf.len()` bytes of the volume at `offset`.
pub(crate) fn read_exact(
    media: &dyn RecordSource,
    offset: u64,
    buf: &mut [u8],
) -> ForensicResult<()> {
    let n = media.read_at(offset, buf)?;
    if n != buf.len() {
        return Err(eof("image ends", offset + n as u64));
    }
    Ok(())
}

/// A non-resident, uncompressed attribute.
pub struct NonResidentStream {
    media: Arc<dyn RecordSource>,
    cluster_size: u64,
    runs: Vec<Run>,
    data_size: u64,
    initialized_size: u64,
}

impl NonResidentStream {
    pub fn new(
        media: Arc<dyn RecordSource>,
        cluster_size: u64,
        runlist: &Runlist,
        data_size: u64,
        initialized_size: u64,
    ) -> Self {
        Self {
            media,
            cluster_size,
            runs: runlist.runs.clone(),
            data_size,
            initialized_size: initialized_size.min(data_size),
        }
    }

    fn locate(&self, vcn: u64) -> Option<&Run> {
        let idx = self
            .runs
            .partition_point(|r| r.vcn.saturating_add(r.length) <= vcn);
        self.runs.get(idx).filter(|r| r.vcn <= vcn)
    }

    /// Volume byte offset holding stream byte `offset`, if it is stored (not sparse, not past the
    /// valid data length).
    pub fn map(&self, offset: u64) -> Option<u64> {
        if offset >= self.initialized_size {
            return None;
        }
        let vcn = offset / self.cluster_size;
        let run = self.locate(vcn)?;
        let lcn = run.lcn?;
        (lcn + (vcn - run.vcn))
            .checked_mul(self.cluster_size)?
            .checked_add(offset % self.cluster_size)
    }
}

impl RecordSource for NonResidentStream {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        if offset >= self.data_size {
            return Ok(0);
        }
        let total = buf.len().min((self.data_size - offset) as usize);
        let mut done = 0usize;
        while done < total {
            let pos = offset + done as u64;
            let want = total - done;
            if pos >= self.initialized_size {
                buf[done..total].fill(0);
                break;
            }
            let vcn = pos / self.cluster_size;
            let within = pos % self.cluster_size;
            let run = *self
                .locate(vcn)
                .ok_or_else(|| error::corrupted(pos, "no data run maps this part of the stream"))?;
            let run_end = (run.vcn + run.length) * self.cluster_size;
            let span = want
                .min((run_end - pos) as usize)
                .min((self.initialized_size - pos) as usize);
            match run.lcn {
                None => buf[done..done + span].fill(0),
                Some(lcn) => {
                    let at = (lcn + (vcn - run.vcn)) * self.cluster_size + within;
                    read_exact(self.media.as_ref(), at, &mut buf[done..done + span])?;
                }
            }
            done += span;
        }
        Ok(total)
    }

    fn len(&self) -> u64 {
        self.data_size
    }
}

/// A compressed attribute (LZNT1 in compression units of `2^cu` clusters).
pub struct CompressedStream {
    media: Arc<dyn RecordSource>,
    cluster_size: u64,
    unit_clusters: u64,
    runs: Vec<Run>,
    data_size: u64,
    cache: Mutex<Option<(u64, Arc<Vec<u8>>)>>,
}

impl CompressedStream {
    pub fn new(
        media: Arc<dyn RecordSource>,
        cluster_size: u64,
        compression_unit: u16,
        runlist: &Runlist,
        data_size: u64,
    ) -> ForensicResult<Self> {
        let unit_clusters = 1u64.checked_shl(u32::from(compression_unit)).unwrap_or(0);
        if unit_clusters == 0 || unit_clusters.saturating_mul(cluster_size) > MAX_COMPRESSION_UNIT {
            return Err(error::invalid(format!(
                "compression unit of {unit_clusters} clusters of {cluster_size} bytes is not supported"
            )));
        }
        Ok(Self {
            media,
            cluster_size,
            unit_clusters,
            runs: runlist.runs.clone(),
            data_size,
            cache: Mutex::new(None),
        })
    }

    fn unit_bytes(&self) -> u64 {
        self.unit_clusters * self.cluster_size
    }

    /// Decodes compression unit `u`.
    fn unit(&self, u: u64) -> ForensicResult<Arc<Vec<u8>>> {
        if let Ok(guard) = self.cache.lock() {
            if let Some((cu, data)) = guard.as_ref() {
                if *cu == u {
                    return Ok(Arc::clone(data));
                }
            }
        }
        let first = u * self.unit_clusters;
        let last = first + self.unit_clusters;
        // Allocated clusters of this unit, in VCN order.
        let mut stored: Vec<u64> = Vec::new();
        for r in &self.runs {
            let (s, e) = (r.vcn.max(first), (r.vcn + r.length).min(last));
            if s >= e {
                continue;
            }
            if let Some(lcn) = r.lcn {
                stored.extend((s..e).map(|v| lcn + (v - r.vcn)));
            }
        }
        let unit_bytes = self.unit_bytes() as usize;
        let data = if stored.is_empty() {
            vec![0u8; unit_bytes]
        } else {
            let mut raw = vec![0u8; stored.len() * self.cluster_size as usize];
            for (i, lcn) in stored.iter().enumerate() {
                let at = lcn * self.cluster_size;
                let cs = self.cluster_size as usize;
                read_exact(self.media.as_ref(), at, &mut raw[i * cs..(i + 1) * cs])?;
            }
            if stored.len() as u64 == self.unit_clusters {
                // Fully allocated unit: stored uncompressed.
                raw
            } else {
                let mut out = Vec::with_capacity(unit_bytes);
                lznt1::decompress_bounded(&raw, &mut out, unit_bytes).map_err(|e| {
                    error::corrupted(
                        first * self.cluster_size,
                        format!("compression unit {u}: {e}"),
                    )
                })?;
                out.resize(unit_bytes, 0);
                out
            }
        };
        let data = Arc::new(data);
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some((u, Arc::clone(&data)));
        }
        Ok(data)
    }
}

impl RecordSource for CompressedStream {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        if offset >= self.data_size {
            return Ok(0);
        }
        let total = buf.len().min((self.data_size - offset) as usize);
        let unit_bytes = self.unit_bytes();
        let mut done = 0usize;
        while done < total {
            let pos = offset + done as u64;
            let unit = self.unit(pos / unit_bytes)?;
            let within = (pos % unit_bytes) as usize;
            let span = (total - done).min(unit.len() - within);
            buf[done..done + span].copy_from_slice(&unit[within..within + span]);
            done += span;
        }
        Ok(total)
    }

    fn len(&self) -> u64 {
        self.data_size
    }
}

/// A byte window of another source.
pub struct WindowSource {
    pub inner: Arc<dyn RecordSource>,
    pub start: u64,
    pub length: u64,
}

impl RecordSource for WindowSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        if offset >= self.length {
            return Ok(0);
        }
        let n = buf.len().min((self.length - offset) as usize);
        read_exact(self.inner.as_ref(), self.start + offset, &mut buf[..n])?;
        Ok(n)
    }

    fn len(&self) -> u64 {
        self.length
    }
}

/// A `VirtualFile` over any source.
pub struct SourceFile {
    src: Arc<dyn RecordSource>,
    pos: u64,
    meta: VMetadata,
}

impl SourceFile {
    pub fn new(src: Arc<dyn RecordSource>, meta: VMetadata) -> Self {
        Self { src, pos: 0, meta }
    }
}

impl std::io::Read for SourceFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self
            .src
            .read_at(self.pos, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl std::io::Seek for SourceFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let len = self.src.len() as i128;
        let next = match pos {
            std::io::SeekFrom::Start(p) => p as i128,
            std::io::SeekFrom::End(d) => len + d as i128,
            std::io::SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

impl VirtualFile for SourceFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(self.meta.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runlist::{decode, encode};
    use crate::source::BytesSource;

    fn media() -> Arc<dyn RecordSource> {
        let mut v = vec![0u8; 64 * 512];
        for (i, c) in v.chunks_mut(512).enumerate() {
            c.fill(i as u8);
        }
        Arc::new(BytesSource(v))
    }

    #[test]
    fn fragmented_sparse_and_vdl() {
        let rl = decode(
            &encode(&[(2, Some(10)), (1, None), (1, Some(3))]),
            0,
            Some(64),
        );
        let s = NonResidentStream::new(media(), 512, &rl, 4 * 512 - 100, 3 * 512 + 10);
        let mut out = vec![0xEEu8; 4 * 512];
        let n = s.read_at(0, &mut out).unwrap();
        assert_eq!(n, 4 * 512 - 100);
        assert!(out[..512].iter().all(|&b| b == 10));
        assert!(out[512..1024].iter().all(|&b| b == 11));
        assert!(out[1024..1536].iter().all(|&b| b == 0), "sparse");
        assert!(out[1536..1546].iter().all(|&b| b == 3));
        assert!(
            out[1546..n].iter().all(|&b| b == 0),
            "past valid data length"
        );
        assert_eq!(s.map(600), Some(11 * 512 + 88));
        assert_eq!(s.map(1100), None);
    }

    #[test]
    fn truncated_image_is_an_error() {
        let rl = decode(&encode(&[(2, Some(63))]), 0, None);
        let s = NonResidentStream::new(media(), 512, &rl, 1024, 1024);
        let mut out = vec![0u8; 1024];
        assert!(s.read_at(0, &mut out).is_err());
    }

    #[test]
    fn compressed_units() {
        // Unit of 4 clusters (512 B): unit 0 compressed into 1 cluster, unit 1 sparse.
        let mut v = vec![0u8; 16 * 512];
        let chunk = [0x03u8, 0x80, 0x02, 0x41, 0xfc, 0x0f]; // 4096 x 'A'
        v[5 * 512..5 * 512 + 6].copy_from_slice(&chunk);
        v[5 * 1024..5 * 1024 + 6].copy_from_slice(&chunk);
        let media: Arc<dyn RecordSource> = Arc::new(BytesSource(v));
        let rl = decode(&encode(&[(1, Some(5)), (3, None), (4, None)]), 0, Some(16));
        // 4 clusters of 512 = 2048-byte units: 'A' * 2048 fits in the bound; chunk yields 4096 -> error.
        let s = CompressedStream::new(media.clone(), 512, 2, &rl, 4096).unwrap();
        let mut out = vec![0u8; 16];
        assert!(
            s.read_at(0, &mut out).is_err(),
            "unit overflow must be refused"
        );
        let s = CompressedStream::new(media, 1024, 2, &rl, 8192).unwrap();
        let mut out = vec![0u8; 8192];
        s.read_at(0, &mut out).unwrap();
        assert!(out[..4096].iter().all(|&b| b == b'A'));
        assert!(out[4096..].iter().all(|&b| b == 0));
    }
}
