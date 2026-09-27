//! The shared forensic-rs `FileSystem` conformance battery against a mounted NTFS volume.

#![cfg(feature = "volume")]

use std::sync::Arc;

use forensic_rs::prelude::*;
use frnsc_ntfs::fixtures::volume::{VolumeBuilder, ROOT};
use frnsc_ntfs::source::BytesSource;
use frnsc_ntfs::volume::{NtfsFs, Volume};

fn ntfs_fixture() -> Arc<dyn FileSystem> {
    let mut b = VolumeBuilder::new(true);
    b.file(ROOT, "a.txt", b"hello");
    let dir = b.dir(ROOT, "dir");
    b.file(dir, "b.txt", b"world");
    b.dir(dir, "empty_dir");
    b.file(ROOT, "empty.txt", b"");
    let vol = Volume::open(Arc::new(BytesSource(b.build())), &|| false).unwrap();
    Arc::new(NtfsFs::from_volume(vol))
}

forensic_rs::fs_conformance_battery!(ntfs, ntfs_fixture());
