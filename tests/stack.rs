//! Disk image -> GPT partition (frnsc-vsys) -> NTFS, walked transparently by `ContainerFs`.

#![cfg(feature = "volume")]

use std::sync::Arc;

use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_ntfs::fixtures::volume::{VolumeBuilder, ROOT};
use frnsc_ntfs::volume::NtfsFormatFactory;
use frnsc_vsys::fixtures::{gpt_disk, GptPart, BASIC_DATA};
use frnsc_vsys::VolumeSystemFactory;

const FIRST_LBA: u64 = 2048;

fn disk(ntfs: &[u8]) -> Vec<u8> {
    let sectors = ntfs.len() as u64 / 512;
    let total = FIRST_LBA + sectors + 64;
    let mut d = gpt_disk(
        512,
        total,
        &[GptPart {
            type_guid: BASIC_DATA,
            first_lba: FIRST_LBA,
            last_lba: FIRST_LBA + sectors - 1,
            name: "Windows",
        }],
    );
    let at = (FIRST_LBA * 512) as usize;
    d[at..at + ntfs.len()].copy_from_slice(ntfs);
    d
}

fn mounted() -> Arc<dyn FileSystem> {
    let mut b = VolumeBuilder::new(false);
    let w = b.dir(ROOT, "Windows");
    b.file(w, "notes.txt", b"inside ntfs inside gpt");
    let gone = b.file(w, "gone.txt", b"deleted inside ntfs inside gpt");
    b.delete(gone);
    let img = disk(&b.build());
    let base: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("disk.raw", img));
    let resolver = Arc::new(
        MountResolver::builder()
            .factory(Arc::new(VolumeSystemFactory))
            .factory(Arc::new(NtfsFormatFactory))
            .build(),
    );
    Arc::new(ContainerFs::new(base, resolver))
}

#[test]
fn reads_a_file_through_disk_partition_and_ntfs() {
    let fs = mounted();
    let data = fs
        .read_all(FPath::new("disk.raw/p1/Windows/notes.txt"))
        .unwrap();
    assert_eq!(data, b"inside ntfs inside gpt");
}

#[test]
fn deleted_files_are_reachable_through_the_container_path() {
    let fs = mounted();
    let deleted = fs.as_deleted().expect("ContainerFs forwards deleted files");
    let scope = FPath::new("disk.raw/p1");
    let (entries, report) = deleted.deleted_entries(scope).unwrap();
    assert_eq!(report.admitted, 1);
    let gone = entries
        .iter()
        .map(|r| r.value())
        .find(|e| e.name.as_deref() == Some("gone.txt"))
        .expect("the deleted file");
    // Named in the outer namespace, so the path works against `fs` like any other.
    assert_eq!(
        gone.path.as_ref().map(|p| p.as_str()),
        Some("disk.raw/p1/Windows/gone.txt")
    );
    let mut buf = Vec::new();
    std::io::Read::read_to_end(
        &mut deleted.open_deleted(scope, gone.id).unwrap().into_value(),
        &mut buf,
    )
    .unwrap();
    assert_eq!(buf, b"deleted inside ntfs inside gpt");
}

#[test]
fn probe_restores_position_and_scores() {
    let mut b = VolumeBuilder::new(false);
    b.file(ROOT, "x", b"x");
    let img = b.build();
    let fs: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("vol.ntfs", img.clone()));
    let resolver = MountResolver::builder()
        .factory(Arc::new(NtfsFormatFactory))
        .build();
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("vol.ntfs")));
    let file = fs.open(FPath::new("vol.ntfs")).unwrap();
    let mounted = resolver
        .resolve(&fs, &locator, file, None, &Default::default())
        .unwrap();
    let ntfs = mounted.as_file_system().unwrap();
    assert_eq!(ntfs.read_all(FPath::new("x")).unwrap(), b"x");
    // Not NTFS: no mount.
    let other: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("junk.img", vec![0x42; 8192]));
    let file = other.open(FPath::new("junk.img")).unwrap();
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("junk.img")));
    assert!(resolver
        .resolve(&other, &locator, file, None, &Default::default())
        .is_err());
}
