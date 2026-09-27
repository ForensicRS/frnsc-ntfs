//! `NtfsFs`: a mounted NTFS volume as a read-only forensic-rs `FileSystem`.

use std::collections::BTreeMap;
use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::traits::vfs::VMetadata;

use super::stream::{SourceFile, WindowSource};
use super::Volume;
use crate::attr::reparse::{tag_name, TAG_MOUNT_POINT, TAG_SYMLINK};
use crate::fields as f;
use crate::mft::MftEntry;
use crate::reference::FileRef;
use crate::time::{filetime, NtfsTimes};

/// A mounted NTFS volume. Paths are volume-relative (`Windows/System32/cmd.exe`), matched
/// case-insensitively. Metafiles (`$MFT`, `$Bitmap`, ...) are listed in the root like on disk.
pub struct NtfsFs {
    vol: Arc<Volume>,
    parent: EvidenceLocator,
    source: SourceKind,
}

impl NtfsFs {
    pub fn new(vol: Arc<Volume>, parent: EvidenceLocator, source: SourceKind) -> Self {
        Self {
            vol,
            parent,
            source,
        }
    }

    /// Opens an image without the pipeline (library use).
    pub fn from_volume(vol: Volume) -> Self {
        Self::new(Arc::new(vol), EvidenceLocator::root(), SourceKind::Image)
    }

    pub fn volume(&self) -> &Arc<Volume> {
        &self.vol
    }

    fn entry_at(&self, path: &FPath) -> ForensicResult<MftEntry> {
        let r = self.vol.lookup(path)?;
        self.vol.entry(r).map_err(|e| e.with_path(path))
    }
}

fn macb(t: &NtfsTimes) -> MacbTimes {
    MacbTimes {
        modified: filetime(t.modified),
        accessed: filetime(t.accessed),
        changed: filetime(t.mft_modified),
        created: filetime(t.created),
        filename_times: None,
    }
}

/// Maps NTFS file attribute bits onto the core evidence bits.
fn attributes(bits: u32, is_dir: bool) -> FileAttributes {
    let map = [
        (0x1, FileAttributes::READONLY),
        (0x2, FileAttributes::HIDDEN),
        (0x4, FileAttributes::SYSTEM),
        (0x200, FileAttributes::SPARSE),
        (0x400, FileAttributes::REPARSE_POINT),
        (0x800, FileAttributes::COMPRESSED),
        (0x4000, FileAttributes::ENCRYPTED),
    ];
    let a = map
        .into_iter()
        .filter(|(ntfs, _)| bits & ntfs != 0)
        .fold(FileAttributes::empty(), |a, (_, core)| a | core);
    if is_dir {
        a | FileAttributes::DIRECTORY
    } else {
        a
    }
}

/// `VMetadata` of an entry: `$SI` times, `$FN` times beside them, unnamed `$DATA` size.
pub fn metadata_of(e: &MftEntry) -> VMetadata {
    let is_link = e
        .reparse
        .as_ref()
        .is_some_and(|r| r.tag == TAG_SYMLINK || r.tag == TAG_MOUNT_POINT);
    let file_type = if is_link {
        VFileType::Symlink
    } else if e.is_directory() {
        VFileType::Directory
    } else {
        VFileType::File
    };
    let mut times = e
        .std_info
        .as_ref()
        .map(|s| macb(&s.times))
        .unwrap_or_default();
    if let Some(n) = e.primary_name() {
        times.filename_times = Some(Box::new(macb(&n.times)));
    }
    let data = e.data();
    VMetadata {
        file_type,
        size: if e.is_directory() {
            0
        } else {
            data.map_or(0, |d| d.size())
        },
        allocated_size: data
            .and_then(|d| d.non_resident.as_ref())
            .map(|nr| nr.allocated_size),
        times,
        id: Some(FileId::from_raw(u128::from(e.reference.raw()))),
        attributes: attributes(
            e.std_info.as_ref().map_or(0, |s| s.file_attributes),
            e.is_directory(),
        ),
    }
}

fn join(dir: &FPath, name: &str) -> FPathBuf {
    if dir.as_str().is_empty() || dir.as_str() == "/" || dir.as_str() == "\\" {
        FPathBuf::from(name)
    } else {
        dir.join(name)
    }
}

impl FileSystem for NtfsFs {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        let e = self.entry_at(path)?;
        if e.is_directory() {
            return Err(ForensicError::access_denied(
                path.as_str(),
                "is a directory",
            ));
        }
        let meta = metadata_of(&e);
        let src = if e.data().is_some() {
            self.vol
                .open_data(&e, "")
                .map_err(|err| err.with_path(path))?
        } else {
            Arc::new(crate::source::BytesSource(Vec::new()))
        };
        Ok(Box::new(SourceFile::new(src, meta)))
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        Ok(metadata_of(&self.entry_at(path)?))
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        let r = self.vol.lookup(path)?;
        let slot = self.vol.mft.index().slot(r.entry);
        if !slot.is_directory() {
            return Err(ForensicError::other(
                "ntfs",
                format!("{} is not a directory", path.as_str()),
            ));
        }
        let kids = self
            .vol
            .tree()
            .children
            .get(&r.entry)
            .cloned()
            .unwrap_or_default();
        let dir = path.to_owned();
        Ok(Box::new(kids.into_iter().map(move |c| {
            let p = join(dir.as_path(), &c.name);
            let e = self
                .vol
                .entry(c.reference)
                .map_err(|err| err.with_path(p.as_path()))?;
            let meta = metadata_of(&e);
            Ok(DirEntry {
                path: p,
                file_type: meta.file_type,
                metadata: Some(meta),
            })
        })))
    }

    fn source(&self) -> SourceKind {
        self.source
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        CaseSensitivity::Insensitive
    }

    fn as_streams(&self) -> Option<&dyn AlternateStreams> {
        Some(self)
    }

    fn as_unallocated(&self) -> Option<&dyn Unallocated> {
        Some(self)
    }

    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        Some(self)
    }

    fn as_media_map(&self) -> Option<&dyn MediaMap> {
        Some(self)
    }
}

impl AlternateStreams for NtfsFs {
    fn streams(&self, path: &FPath) -> ForensicResult<Vec<StreamInfo>> {
        let e = self.entry_at(path)?;
        Ok(e.alternate_streams()
            .map(|s| StreamInfo {
                name: s.name.clone(),
                size: s.size(),
            })
            .collect())
    }

    fn open_stream(&self, path: &FPath, stream: &str) -> ForensicResult<Box<dyn VirtualFile>> {
        let e = self.entry_at(path)?;
        let src = self
            .vol
            .open_data(&e, stream)
            .map_err(|err| err.with_path(path))?;
        let mut meta = metadata_of(&e);
        meta.size = src.len();
        meta.file_type = VFileType::File;
        Ok(Box::new(SourceFile::new(src, meta)))
    }
}

impl Unallocated for NtfsFs {
    /// Free clusters according to `$Bitmap`, as volume byte ranges.
    fn unallocated_regions(&self) -> ForensicResult<Vec<Region>> {
        let cs = self.vol.cluster_size();
        Ok(self
            .vol
            .bitmap()?
            .free_runs()
            .into_iter()
            .map(|(lcn, len)| Region {
                offset: lcn * cs,
                length: len * cs,
            })
            .collect())
    }

    fn open_unallocated(&self, region: &Region) -> ForensicResult<Box<dyn VirtualFile>> {
        let end = region.offset.checked_add(region.length);
        if end.is_none_or(|end| end > self.vol.media.len()) {
            return Err(ForensicError::other(
                "ntfs",
                "region outside the volume".into(),
            ));
        }
        let src = Arc::new(WindowSource {
            inner: Arc::clone(&self.vol.media),
            start: region.offset,
            length: region.length,
        });
        let meta = VMetadata {
            file_type: VFileType::File,
            size: region.length,
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        };
        Ok(Box::new(SourceFile::new(src, meta)))
    }
}

fn text(s: impl Into<String>) -> Field {
    Field::Text(Text::Owned(s.into()))
}

impl PathAttributes for NtfsFs {
    /// Root: volume geometry and volume-level anomalies. A path: MFT identity, raw `$SI`/`$FN`
    /// FILETIMEs, streams, reparse target and object id. Unknown values are omitted.
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
        let mut a = BTreeMap::new();
        let mut put = |k: &'static str, v: Field| {
            a.insert(Text::Borrowed(k), v);
        };
        if path.as_str().is_empty() || path.as_str() == "/" {
            let b = &self.vol.boot;
            put("ntfs.serial", text(b.serial_short()));
            put("ntfs.cluster_size", Field::U64(b.cluster_size));
            put(
                "ntfs.bytes_per_sector",
                Field::U64(u64::from(b.bytes_per_sector)),
            );
            put(f::MFT_RECORD_SIZE, Field::U64(u64::from(b.mft_record_size)));
            put(f::MFT_ENTRIES, Field::U64(self.vol.mft.entry_count()));
            put(f::MFT_INVALID, Field::U64(self.vol.mft.index().invalid));
            put(
                "ntfs.mft.fragments",
                Field::U64(self.vol.mft_runs.runs.len() as u64),
            );
            if let Ok(Some(v)) = self.vol.mft.entry(3) {
                if let Some(n) = &v.volume_name {
                    put(f::VOLUME_NAME, text(n.clone()));
                }
                if let Some(i) = &v.volume_info {
                    put(f::VOLUME_VERSION, text(format!("{}.{}", i.major, i.minor)));
                    put(f::VOLUME_DIRTY, Field::from(i.is_dirty()));
                }
            }
            if !self.vol.anomalies.is_empty() {
                put(
                    f::ANOMALIES,
                    Field::Array(
                        self.vol
                            .anomalies
                            .iter()
                            .map(|x| Text::Owned(format!("{}: {x}", x.name())))
                            .collect(),
                    ),
                );
            }
            return Ok(a);
        }
        let e = self.entry_at(path)?;
        put(f::ENTRY, Field::U64(e.reference.entry));
        put(f::SEQUENCE, Field::U64(u64::from(e.reference.sequence)));
        if let Some(si) = &e.std_info {
            for (k, v) in [
                (f::SI_CREATED_RAW, si.times.created),
                (f::SI_MODIFIED_RAW, si.times.modified),
                (f::SI_MFT_MODIFIED_RAW, si.times.mft_modified),
                (f::SI_ACCESSED_RAW, si.times.accessed),
            ] {
                put(k, Field::U64(v));
            }
            put(f::SI_ATTRIBUTES, Field::U64(u64::from(si.file_attributes)));
        }
        if let Some(n) = e.primary_name() {
            for (k, v) in [
                (f::FN_CREATED_RAW, n.times.created),
                (f::FN_MODIFIED_RAW, n.times.modified),
                (f::FN_MFT_MODIFIED_RAW, n.times.mft_modified),
                (f::FN_ACCESSED_RAW, n.times.accessed),
            ] {
                put(k, Field::U64(v));
            }
        }
        let ads: Vec<Text> = e
            .alternate_streams()
            .map(|s| Text::Owned(format!("{}:{}", s.name, s.size())))
            .collect();
        if !ads.is_empty() {
            put(f::STREAMS, Field::Array(ads));
        }
        if let Some(r) = &e.reparse {
            put(f::REPARSE_TAG, Field::U64(u64::from(r.tag)));
            put(f::REPARSE_TAG_NAME, text(tag_name(r.tag)));
            if let Some(t) = r.target() {
                put(f::REPARSE_TARGET, text(t));
            }
        }
        if let Some(o) = &e.object_id {
            put(f::OBJECT_ID, text(o.object_id.clone()));
        }
        Ok(a)
    }
}

impl MediaMap for NtfsFs {
    /// Stream byte -> volume byte, for non-resident, uncompressed, stored bytes. `None` for sparse
    /// ranges, bytes past the valid data length, compressed and resident data.
    fn to_parent(&self, path: &FPath, offset: u64) -> ForensicResult<Option<MediaOffset>> {
        let e = self.entry_at(path)?;
        let Some(d) = e.data() else { return Ok(None) };
        let Some(nr) = d.non_resident.as_ref() else {
            return Ok(None);
        };
        if d.is_compressed() {
            return Ok(None);
        }
        let rl = self.vol.decode_segments(&d.segments)?;
        let s = super::stream::NonResidentStream::new(
            Arc::clone(&self.vol.media),
            self.vol.cluster_size(),
            &rl,
            nr.data_size,
            nr.initialized_size,
        );
        Ok(s.map(offset).map(|at| MediaOffset {
            locator: self.parent.clone(),
            offset: at,
        }))
    }
}

/// Reference of a path's entry (for callers that need MFT identity).
pub fn reference_of(fs: &NtfsFs, path: &FPath) -> ForensicResult<FileRef> {
    fs.vol.lookup(path)
}
