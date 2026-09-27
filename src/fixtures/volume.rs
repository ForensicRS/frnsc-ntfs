//! A whole synthetic NTFS volume: boot sectors, a (optionally fragmented) `$MFT` with its
//! attribute list, `$MFTMirr`, `$Bitmap`, `$Volume`, and user files and directories.

use std::collections::BTreeMap;

use super::{
    attr_list_entry, boot_sector, times, NonResidentSpec, RecordBuilder, FILE_TIME_2020 as T,
};
use crate::record::attribute::{
    ATTR_ATTRIBUTE_LIST, ATTR_DATA, ATTR_FILE_NAME, ATTR_STANDARD_INFORMATION,
    ATTR_VOLUME_INFORMATION, ATTR_VOLUME_NAME,
};
use crate::reference::FileRef;

pub const CLUSTER: u64 = 4096;
pub const RECORD: usize = 1024;
/// The root directory reference.
pub const ROOT: FileRef = FileRef::new(5, 5);

enum Data {
    None,
    Resident(Vec<u8>),
    NonResident {
        runs: Vec<(u64, Option<u64>)>,
        size: u64,
        compressed: bool,
    },
}

struct Spec {
    reference: FileRef,
    parent: FileRef,
    name: String,
    dir: bool,
    deleted: bool,
    data: Data,
    ads: Vec<(String, Vec<u8>)>,
}

/// Builder for a synthetic NTFS volume image.
pub struct VolumeBuilder {
    clusters: u64,
    mft_records: u64,
    fragmented: bool,
    image: Vec<u8>,
    allocated: Vec<bool>,
    next_lcn: u64,
    next_entry: u64,
    files: BTreeMap<u64, Spec>,
}

impl VolumeBuilder {
    /// 2 MiB volume, 4 KiB clusters, 1 KiB records, 128 MFT records. With `fragmented`, the second
    /// half of the `$MFT` lives elsewhere and is found through an extension record.
    pub fn new(fragmented: bool) -> Self {
        let clusters = 512;
        let mut b = Self {
            clusters,
            mft_records: 128,
            fragmented,
            image: vec![0u8; (clusters * CLUSTER) as usize],
            allocated: vec![false; clusters as usize],
            next_lcn: 64,
            next_entry: 24,
            files: BTreeMap::new(),
        };
        for lcn in [0, 2, 4, clusters - 1] {
            b.allocated[lcn as usize] = true;
        }
        for (lcn, n) in b.mft_extents() {
            for l in lcn..lcn + n {
                b.allocated[l as usize] = true;
            }
        }
        b
    }

    fn mft_extents(&self) -> Vec<(u64, u64)> {
        let total = self.mft_records * RECORD as u64 / CLUSTER;
        if self.fragmented {
            vec![(16, total / 2), (300, total - total / 2)]
        } else {
            vec![(16, total)]
        }
    }

    fn total_clusters(&self) -> u64 {
        self.clusters - 1
    }

    fn alloc(&mut self, n: u64) -> u64 {
        let lcn = self.next_lcn;
        self.next_lcn += n;
        for l in lcn..lcn + n {
            self.allocated[l as usize] = true;
        }
        lcn
    }

    fn write(&mut self, lcn: u64, bytes: &[u8]) {
        let at = (lcn * CLUSTER) as usize;
        self.image[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn add(&mut self, parent: FileRef, name: &str, dir: bool, data: Data) -> FileRef {
        let reference = FileRef::new(self.next_entry, 1);
        self.next_entry += 1;
        self.files.insert(
            reference.entry,
            Spec {
                reference,
                parent,
                name: name.to_string(),
                dir,
                deleted: false,
                data,
                ads: Vec::new(),
            },
        );
        reference
    }

    pub fn dir(&mut self, parent: FileRef, name: &str) -> FileRef {
        self.add(parent, name, true, Data::None)
    }

    /// A file: resident up to 400 bytes, otherwise contiguous clusters.
    pub fn file(&mut self, parent: FileRef, name: &str, content: &[u8]) -> FileRef {
        if content.len() <= 400 {
            return self.add(parent, name, false, Data::Resident(content.to_vec()));
        }
        let n = (content.len() as u64).div_ceil(CLUSTER);
        let lcn = self.alloc(n);
        self.write(lcn, content);
        self.add(
            parent,
            name,
            false,
            Data::NonResident {
                runs: vec![(n, Some(lcn))],
                size: content.len() as u64,
                compressed: false,
            },
        )
    }

    /// A file of `content` split over two non-adjacent extents.
    pub fn fragmented_file(&mut self, parent: FileRef, name: &str, content: &[u8]) -> FileRef {
        let n = (content.len() as u64).div_ceil(CLUSTER).max(2);
        let first = n / 2;
        let a = self.alloc(first);
        self.alloc(3); // gap owned by nobody but marked used
        let b = self.alloc(n - first);
        let split = (first * CLUSTER) as usize;
        self.write(a, &content[..split.min(content.len())]);
        if split < content.len() {
            self.write(b, &content[split..]);
        }
        self.add(
            parent,
            name,
            false,
            Data::NonResident {
                runs: vec![(first, Some(a)), (n - first, Some(b))],
                size: content.len() as u64,
                compressed: false,
            },
        )
    }

    /// A sparse file: `size` bytes, `data` stored at cluster `vcn`, everything else sparse.
    pub fn sparse_file(
        &mut self,
        parent: FileRef,
        name: &str,
        size: u64,
        vcn: u64,
        data: &[u8],
    ) -> FileRef {
        let total = size.div_ceil(CLUSTER);
        let lcn = self.alloc(1);
        self.write(lcn, data);
        let mut runs = Vec::new();
        if vcn > 0 {
            runs.push((vcn, None));
        }
        runs.push((1, Some(lcn)));
        if total > vcn + 1 {
            runs.push((total - vcn - 1, None));
        }
        self.add(
            parent,
            name,
            false,
            Data::NonResident {
                runs,
                size,
                compressed: false,
            },
        )
    }

    /// An LZNT1-compressed file of `units` 64 KiB compression units filled with `byte`: each unit
    /// is one stored cluster (16 RLE chunks) and 15 sparse clusters.
    pub fn compressed_file(
        &mut self,
        parent: FileRef,
        name: &str,
        byte: u8,
        units: u64,
    ) -> FileRef {
        let chunk = [0x03u8, 0x80, 0x02, byte, 0xfc, 0x0f];
        let mut runs = Vec::new();
        for _ in 0..units {
            let lcn = self.alloc(1);
            let unit: Vec<u8> = chunk
                .iter()
                .copied()
                .cycle()
                .take(chunk.len() * 16)
                .collect();
            self.write(lcn, &unit);
            runs.push((1, Some(lcn)));
            runs.push((15, None));
        }
        self.add(
            parent,
            name,
            false,
            Data::NonResident {
                runs,
                size: units * 65536,
                compressed: true,
            },
        )
    }

    pub fn ads(&mut self, file: FileRef, name: &str, content: &[u8]) {
        if let Some(s) = self.files.get_mut(&file.entry) {
            s.ads.push((name.to_string(), content.to_vec()));
        }
    }

    /// Deletes a file: record freed (sequence bumped), clusters freed in `$Bitmap`.
    pub fn delete(&mut self, file: FileRef) -> FileRef {
        let clusters = self.clusters_of(file);
        for l in clusters {
            self.allocated[l as usize] = false;
        }
        let s = self.files.get_mut(&file.entry).expect("fixture file");
        s.deleted = true;
        s.reference.sequence += 1;
        file
    }

    /// Marks a deleted file's clusters allocated again (another file reused them).
    pub fn reuse_clusters(&mut self, file: FileRef) {
        for l in self.clusters_of(file) {
            self.allocated[l as usize] = true;
        }
    }

    /// Overwrites the start of a file's first stored cluster.
    pub fn overwrite(&mut self, file: FileRef, bytes: &[u8]) {
        if let Some(&l) = self.clusters_of(file).first() {
            self.write(l, bytes);
        }
    }

    fn clusters_of(&self, file: FileRef) -> Vec<u64> {
        match self.files.get(&file.entry).map(|s| &s.data) {
            Some(Data::NonResident { runs, .. }) => runs
                .iter()
                .filter_map(|(n, l)| l.map(|l| (l, *n)))
                .flat_map(|(l, n)| l..l + n)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn record(&self, s: &Spec) -> Vec<u8> {
        let mut r = RecordBuilder::file(s.reference.entry, s.reference.sequence)
            .std_info_times(&times(T), 0x20, 0)
            .file_name(s.parent.entry, s.parent.sequence, &s.name, T);
        if s.dir {
            r = r.directory();
        }
        if s.deleted {
            r = r.deleted();
        }
        match &s.data {
            Data::None => {}
            Data::Resident(v) => r = r.resident_data("", v),
            Data::NonResident {
                runs,
                size,
                compressed,
            } => {
                let clusters: u64 = runs.iter().map(|x| x.0).sum();
                r = r.non_resident_full(NonResidentSpec {
                    type_code: ATTR_DATA,
                    name: "",
                    starting_vcn: 0,
                    runs,
                    allocated_size: clusters * CLUSTER,
                    data_size: *size,
                    flags: if *compressed { 0x0001 } else { 0 },
                    compression_unit: if *compressed { 4 } else { 0 },
                })
            }
        }
        for (n, v) in &s.ads {
            r = r.resident_data(n, v);
        }
        r.build()
    }

    fn metafile(entry: u64, seq: u16, name: &str, dir: bool) -> RecordBuilder {
        let r = RecordBuilder::file(entry, seq)
            .std_info(T)
            .file_name(5, 5, name, T);
        if dir {
            r.directory()
        } else {
            r
        }
    }

    /// Serialises the image.
    pub fn build(&self) -> Vec<u8> {
        let mut img = self.image.clone();
        let extents = self.mft_extents();
        let mft_size = self.mft_records * RECORD as u64;
        let mut records: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

        // $MFT (entry 0), possibly with its second extent in extension record 15.
        let first: Vec<(u64, Option<u64>)> = vec![(extents[0].1, Some(extents[0].0))];
        let mut rec0 = Self::metafile(0, 1, "$MFT", false);
        if self.fragmented {
            let list: Vec<u8> = [
                attr_list_entry(ATTR_STANDARD_INFORMATION, 0, FileRef::new(0, 1), 0),
                attr_list_entry(ATTR_FILE_NAME, 0, FileRef::new(0, 1), 1),
                attr_list_entry(ATTR_DATA, 0, FileRef::new(0, 1), 3),
                attr_list_entry(ATTR_DATA, extents[0].1, FileRef::new(15, 1), 0),
            ]
            .concat();
            rec0 = rec0.resident(ATTR_ATTRIBUTE_LIST, "", &list);
            let second: Vec<(u64, Option<u64>)> = vec![(extents[1].1, Some(extents[1].0))];
            let ext = RecordBuilder::file(15, 1)
                .base(FileRef::new(0, 1))
                .non_resident_full(NonResidentSpec {
                    type_code: ATTR_DATA,
                    name: "",
                    starting_vcn: extents[0].1,
                    runs: &second,
                    allocated_size: mft_size,
                    data_size: mft_size,
                    flags: 0,
                    compression_unit: 0,
                })
                .build();
            records.insert(15, ext);
        }
        let total_mft_clusters: u64 = extents.iter().map(|e| e.1).sum();
        rec0 = rec0.non_resident_full(NonResidentSpec {
            type_code: ATTR_DATA,
            name: "",
            starting_vcn: 0,
            runs: &first,
            allocated_size: total_mft_clusters * CLUSTER,
            data_size: mft_size,
            flags: 0,
            compression_unit: 0,
        });
        records.insert(0, rec0.build());
        records.insert(
            1,
            Self::metafile(1, 1, "$MFTMirr", false)
                .non_resident(ATTR_DATA, "", &[(1, Some(2))], 4096, CLUSTER)
                .build(),
        );
        let mut volinfo = vec![0u8; 12];
        volinfo[8] = 3;
        volinfo[9] = 1;
        records.insert(
            3,
            Self::metafile(3, 3, "$Volume", false)
                .resident(ATTR_VOLUME_NAME, "", &super::utf16("TESTVOL"))
                .resident(ATTR_VOLUME_INFORMATION, "", &volinfo)
                .build(),
        );
        records.insert(5, Self::metafile(5, 5, ".", true).build());
        let bitmap_len = self.total_clusters().div_ceil(8);
        records.insert(
            6,
            Self::metafile(6, 6, "$Bitmap", false)
                .non_resident(ATTR_DATA, "", &[(1, Some(4))], bitmap_len, CLUSTER)
                .build(),
        );
        records.insert(11, Self::metafile(11, 11, "$Extend", true).build());
        for s in self.files.values() {
            records.insert(s.reference.entry, self.record(s));
        }

        // Lay the MFT stream out over its extents.
        let mut mft = vec![0u8; mft_size as usize];
        for (e, r) in &records {
            let at = *e as usize * RECORD;
            mft[at..at + RECORD].copy_from_slice(&r[..RECORD]);
        }
        let mut off = 0usize;
        for (lcn, n) in &extents {
            let len = (*n * CLUSTER) as usize;
            let at = (*lcn * CLUSTER) as usize;
            img[at..at + len].copy_from_slice(&mft[off..off + len]);
            off += len;
        }
        // $MFTMirr: first 4 records.
        img[(2 * CLUSTER) as usize..(2 * CLUSTER) as usize + 4 * RECORD]
            .copy_from_slice(&mft[..4 * RECORD]);
        // $Bitmap.
        let mut bits = vec![0u8; bitmap_len as usize];
        for (l, &a) in self
            .allocated
            .iter()
            .enumerate()
            .take(self.total_clusters() as usize)
        {
            if a {
                bits[l / 8] |= 1 << (l % 8);
            }
        }
        img[(4 * CLUSTER) as usize..(4 * CLUSTER) as usize + bits.len()].copy_from_slice(&bits);
        // Boot sectors: total_sectors excludes the backup sector at the very end.
        let boot = boot_sector(512, 8, self.clusters * 8 - 1, extents[0].0, -10, 1);
        img[..512].copy_from_slice(&boot);
        let n = img.len();
        img[n - 512..].copy_from_slice(&boot);
        img
    }
}
