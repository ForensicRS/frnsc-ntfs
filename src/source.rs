//! Positioned, read-only byte access to evidence.
//!
//! The parsers only need "read N bytes at offset X" and "how long is it". [`RecordSource`] is
//! that contract; it has implementations for an in-memory buffer and for any `Read + Seek`
//! (including a forensic-rs `VirtualFile`), so a loose file needs nothing else.

use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use forensic_rs::prelude::*;

use crate::error;

/// Read-only positioned access.
pub trait RecordSource: Send + Sync {
    /// Reads up to `buf.len()` bytes at `offset`; returns how many were read (short at the end).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize>;
    /// Total length in bytes.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads exactly `len` bytes at `offset`, or fails with a truncation error.
    fn read_vec(&self, offset: u64, len: usize) -> ForensicResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_at(offset, &mut buf)?;
        if n != len {
            return Err(ForensicError::buffer_too_small(len, n, "ntfs source read"));
        }
        Ok(buf)
    }
}

/// An in-memory buffer.
pub struct BytesSource(pub Vec<u8>);

impl RecordSource for BytesSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        let Some(avail) = self.0.get(start..) else {
            return Ok(0);
        };
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }

    fn len(&self) -> u64 {
        self.0.len() as u64
    }
}

/// Any `Read + Seek` stream (a `std::fs::File`, a forensic-rs `VirtualFile`, a `Cursor`).
pub struct StreamSource<R> {
    inner: Mutex<R>,
    len: u64,
}

impl<R: Read + Seek + Send> StreamSource<R> {
    pub fn new(mut inner: R) -> ForensicResult<Self> {
        let len = inner
            .seek(SeekFrom::End(0))
            .map_err(|e| error::io(e, "seeking to the end of the NTFS source"))?;
        Ok(Self {
            inner: Mutex::new(inner),
            len,
        })
    }
}

impl<R: Read + Seek + Send> RecordSource for StreamSource<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ForensicError::other("ntfs", "source lock poisoned".into()))?;
        inner
            .seek(SeekFrom::Start(offset))
            .map_err(|e| error::io(e, "seeking in the NTFS source"))?;
        let mut done = 0;
        while done < buf.len() {
            match inner.read(&mut buf[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(error::io(e, "reading the NTFS source")),
            }
        }
        Ok(done)
    }

    fn len(&self) -> u64 {
        self.len
    }
}

/// Opens a forensic-rs `VirtualFile` as a source.
pub fn from_virtual_file(
    file: Box<dyn VirtualFile>,
) -> ForensicResult<StreamSource<Box<dyn VirtualFile>>> {
    StreamSource::new(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_stream_agree() {
        let data: Vec<u8> = (0..=255).collect();
        let a = BytesSource(data.clone());
        let b = StreamSource::new(std::io::Cursor::new(data)).unwrap();
        for (off, len) in [(0u64, 10usize), (250, 10), (256, 4), (1000, 1)] {
            let mut x = vec![0; len];
            let mut y = vec![0; len];
            assert_eq!(
                a.read_at(off, &mut x).unwrap(),
                b.read_at(off, &mut y).unwrap()
            );
            assert_eq!(x, y);
        }
        assert!(a.read_vec(250, 10).is_err());
        assert_eq!(a.read_vec(0, 4).unwrap(), vec![0, 1, 2, 3]);
    }
}
