use super::*;
use crate::fixtures::volume::{VolumeBuilder, ROOT};
use crate::source::BytesSource;

fn open(img: Vec<u8>) -> NtfsFs {
    NtfsFs::from_volume(Volume::open(Arc::new(BytesSource(img)), &|| false).unwrap())
}

fn read(fs: &NtfsFs, path: &str) -> Vec<u8> {
    fs.read_all(FPath::new(path)).unwrap()
}

fn big(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn fragmented_mft_and_file_reads() {
    let mut b = VolumeBuilder::new(true);
    let users = b.dir(ROOT, "Users");
    let bob = b.dir(users, "bob");
    b.file(bob, "small.txt", b"hello ntfs");
    b.file(bob, "big.bin", &big(10_000, 1));
    b.fragmented_file(bob, "frag.bin", &big(20_000, 7));
    b.sparse_file(bob, "sparse.dat", 5 * 4096, 2, b"middle");
    b.compressed_file(bob, "comp.bin", b'Z', 2);
    let doc = b.file(bob, "doc.pdf", &big(5000, 3));
    b.ads(doc, "Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n");
    let fs = open(b.build());
    let vol = fs.volume();
    assert!(vol.anomalies.is_empty(), "{:?}", vol.anomalies);
    assert_eq!(
        vol.mft_runs.runs.len(),
        2,
        "both $MFT extents found through the attribute list"
    );
    assert_eq!(read(&fs, "Users/bob/small.txt"), b"hello ntfs");
    assert_eq!(read(&fs, "users/BOB/big.bin"), big(10_000, 1));
    assert_eq!(read(&fs, "Users/bob/frag.bin"), big(20_000, 7));
    let sparse = read(&fs, "Users/bob/sparse.dat");
    assert_eq!(sparse.len(), 5 * 4096);
    assert!(sparse[..8192].iter().all(|&b| b == 0));
    assert_eq!(&sparse[8192..8198], b"middle");
    let comp = read(&fs, "Users/bob/comp.bin");
    assert_eq!(comp.len(), 2 * 65536);
    assert!(comp.iter().all(|&b| b == b'Z'));
    let streams = fs.streams(FPath::new("Users/bob/doc.pdf")).unwrap();
    assert_eq!(streams[0].name, "Zone.Identifier");
    let mut z = String::new();
    std::io::Read::read_to_string(
        &mut fs
            .open_stream(FPath::new("Users/bob/doc.pdf"), "Zone.Identifier")
            .unwrap(),
        &mut z,
    )
    .unwrap();
    assert!(z.contains("ZoneId=3"));
    let md = fs.metadata(FPath::new("Users/bob/doc.pdf")).unwrap();
    assert_eq!(md.size, 5000);
    assert!(md.created_opt().is_some());
    assert!(md.times.filename_times.is_some());
    let at = fs
        .to_parent(FPath::new("Users/bob/big.bin"), 4097)
        .unwrap()
        .unwrap();
    assert_eq!(at.offset % 4096, 1);
    assert!(fs
        .to_parent(FPath::new("Users/bob/sparse.dat"), 10)
        .unwrap()
        .is_none());
}

#[test]
fn walk_lists_everything_once() {
    let mut b = VolumeBuilder::new(false);
    let d = b.dir(ROOT, "d");
    b.file(d, "a.txt", b"a");
    b.file(ROOT, "b.txt", b"b");
    let fs = open(b.build());
    let mut paths: Vec<String> = fs
        .walk(FPath::new(""), &Default::default())
        .map(|e| e.unwrap().path.as_str().to_string())
        .collect();
    paths.sort();
    for p in ["$MFT", "$Bitmap", "$Volume", "d", "d/a.txt", "b.txt"] {
        assert!(paths.iter().any(|x| x == p), "{p} missing from {paths:?}");
    }
    assert!(fs.open(FPath::new("nope.txt")).is_err());
    assert!(fs.read_dir(FPath::new("b.txt")).is_err());
    let root = fs.attributes(FPath::new("")).unwrap();
    assert_eq!(
        root.get(crate::fields::VOLUME_NAME),
        Some(&Field::Text("TESTVOL".into()))
    );
}

#[test]
fn deleted_content_gate() {
    let mut b = VolumeBuilder::new(false);
    let t = b.dir(ROOT, "Temp");
    let kept = b.file(t, "kept.bin", &big(9000, 1));
    let gone = b.file(t, "payload.exe", &big(9000, 2));
    let small = b.file(t, "note.txt", b"small secret");
    let reused = b.file(t, "old.log", &big(9000, 3));
    let comp = b.compressed_file(t, "packed.bin", b'Q', 1);
    b.delete(gone);
    b.delete(small);
    b.delete(reused);
    b.reuse_clusters(reused);
    b.delete(comp);
    let _ = kept;
    let fs = open(b.build());
    let (files, report) = fs.deleted_files().unwrap();
    let by_name = |n: &str| {
        files
            .iter()
            .find(|f| f.value().path.path.ends_with(n))
            .unwrap_or_else(|| panic!("{n}"))
    };
    let p = by_name("payload.exe");
    assert_eq!(p.value().content, deleted::ContentStatus::Recoverable);
    assert_eq!(
        p.recovery(),
        forensic_rs::provenance::Recovery::DeletedMetadata
    );
    assert_eq!(p.value().path.path, "\\Temp\\payload.exe");
    let mut buf = Vec::new();
    std::io::Read::read_to_end(
        &mut fs.open_deleted(p.value()).unwrap().into_value(),
        &mut buf,
    )
    .unwrap();
    assert_eq!(buf, big(9000, 2));
    assert_eq!(
        by_name("note.txt").value().content,
        deleted::ContentStatus::Resident
    );
    let r = by_name("old.log");
    assert!(matches!(
        r.value().content,
        deleted::ContentStatus::Reallocated { clusters: 3 }
    ));
    assert!(fs.open_deleted(r.value()).is_err());
    let c = by_name("packed.bin");
    assert_eq!(c.value().content, deleted::ContentStatus::Recoverable);
    let mut buf = Vec::new();
    std::io::Read::read_to_end(
        &mut fs.open_deleted(c.value()).unwrap().into_value(),
        &mut buf,
    )
    .unwrap();
    assert!(buf.iter().all(|&x| x == b'Q'));
    assert_eq!(report.admitted, 3);
    assert!(report.rejected >= 1);
}

#[test]
fn damaged_volumes() {
    let mut b = VolumeBuilder::new(false);
    b.file(ROOT, "x.txt", b"x");
    let clean = b.build();
    // Primary boot sector destroyed: backup used.
    let mut img = clean.clone();
    img[3] = b'X';
    let fs = open(img);
    assert!(fs.volume().anomalies.contains(&NtfsAnomaly::BootBackupUsed));
    assert_eq!(read(&fs, "x.txt"), b"x");
    // $MFTMirr tampered.
    let mut img = clean.clone();
    img[2 * 4096 + 100] ^= 0xFF;
    let fs = open(img);
    assert!(fs
        .volume()
        .anomalies
        .iter()
        .any(|a| matches!(a, NtfsAnomaly::MftMirrMismatch { .. })));
    // Truncated image.
    let img = clean[..clean.len() - 8192].to_vec();
    if let Ok(v) = Volume::open(Arc::new(BytesSource(img)), &|| false) {
        assert!(v
            .anomalies
            .iter()
            .any(|a| matches!(a, NtfsAnomaly::VolumeTruncated { .. })));
    }
    // Garbage never panics.
    let mut seed = 0xC0FFEEu32;
    for _ in 0..150 {
        let mut m = clean.clone();
        for _ in 0..64 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let i = (seed as usize) % (160 * 4096);
            m[i] = (seed >> 8) as u8;
        }
        if let Ok(v) = Volume::open(Arc::new(BytesSource(m)), &|| false) {
            let fs = NtfsFs::from_volume(v);
            for e in fs.walk(FPath::new(""), &Default::default()).flatten() {
                if e.file_type == VFileType::File {
                    let _ = fs.read_all(e.path.as_path());
                }
            }
            let _ = fs.deleted_files();
        }
    }
}
