//! Ground-truth checks against a real NTFS volume made by mkntfs + ntfs-3g
//! (`forensic-testenv/generators/ntfs_mkntfs.sh`). Skipped when the artifacts are not fetched.

mod common;

use std::sync::Arc;

use common::{by_field, one, run};
use forensic_rs::dictionary;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use forensic_testdata::artifact_or_skip;
use frnsc_ntfs::boot::BootSector;
use frnsc_ntfs::fields as f;
use frnsc_ntfs::fixup::FixupStatus;
use frnsc_ntfs::mft::mirror::MIRRORED_RECORDS;
use frnsc_ntfs::mft::{Mft, MftMirr, MirrorVerdict};
use frnsc_ntfs::parser::{MftParserFactory, SdsParserFactory};
use frnsc_ntfs::source::BytesSource;

/// Expected content, rebuilt from the generator's inputs.
fn expected(path: &str) -> Vec<u8> {
    match path {
        "Users/bob/Documents/small.txt" => b"hello ntfs".to_vec(),
        "Users/bob/Documents/big.bin" => b"0123456789abcdef".repeat(1250),
        "Users/bob/comp/zeros.bin" => vec![b'A'; 262144],
        "Users/bob/gone.bin" => b"deleted-content!".repeat(750),
        "Users/bob/gone_small.txt" => b"deleted but resident".to_vec(),
        other => panic!("no expectation for {other}"),
    }
}

/// Every truth row's size matches the rebuilt expectation (guards the test itself).
#[test]
fn truth_file_agrees_with_expectations() {
    let truth = artifact_or_skip!("ntfs-mkntfs-truth");
    let text = std::fs::read_to_string(truth).unwrap();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        let path = cols[0].trim_start_matches("deleted:");
        assert_eq!(expected(path).len().to_string(), cols[1], "{path}");
    }
}

#[test]
fn loose_mft_boot_and_sds_through_the_pipeline() {
    let mft = artifact_or_skip!("ntfs-mkntfs-mft");
    let boot = artifact_or_skip!("ntfs-mkntfs-boot");
    let sds = artifact_or_skip!("ntfs-mkntfs-sds");
    let fs: Arc<dyn FileSystem> = Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("C/$MFT", std::fs::read(mft).unwrap())
            .with_file("C/$Boot", std::fs::read(boot).unwrap())
            .with_file("C/$Secure%3A$SDS", std::fs::read(sds).unwrap()),
    );
    let r = run(
        fs,
        vec![
            Arc::new(MftParserFactory::default()),
            Arc::new(SdsParserFactory::default()),
        ],
    );
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);

    let big = one(
        &r.records,
        dictionary::FILE_PATH,
        "\\Users\\bob\\Documents\\big.bin",
    );
    assert_eq!(big.field_as_u64(dictionary::FILE_SIZE), Some(20000));
    assert_eq!(
        big.field(f::STREAMS),
        Some(&Field::Array(vec!["Zone.Identifier:26:resident".into()]))
    );
    assert_eq!(big.field_as_str(f::RECORD_FIXUP), Some("pre_applied"));
    assert!(
        big.anomalies().flags().is_empty(),
        "no false anomalies on a clean volume"
    );
    assert!(big
        .field_as_str(dictionary::FILE_UID)
        .is_some_and(|s| s.starts_with("S-1-")));

    let gone = one(&r.records, dictionary::FILE_PATH, "\\Users\\bob\\gone.bin");
    assert_eq!(gone.field_as_str(f::RECOVERY), Some("deleted_metadata"));
    let small = one(
        &r.records,
        dictionary::FILE_PATH,
        "\\Users\\bob\\gone_small.txt",
    );
    assert_eq!(
        small.field_as_str(f::DATA_RESIDENT_HEX),
        Some(
            b"deleted but resident"
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .as_str()
        )
    );

    let descriptors = by_field(
        &r.records,
        f::RECORD_TYPE,
        f::RECORD_TYPE_SECURITY_DESCRIPTOR,
    );
    assert!(!descriptors.is_empty());
    for d in descriptors {
        assert!(
            d.anomalies().flags().is_empty(),
            "hash/mirror check fails on a real $SDS: {d}"
        );
    }
}

/// The real `$MFTMirr` of `ntfs-mkntfs-volume`, read out of the volume image at the LCN its own
/// `$Boot` declares. `MIRRORED_RECORDS` records, so offsets below are relative to that file.
///
/// There is no loose `ntfs-mkntfs-mftmirr` artifact yet (the generator does not extract one, see
/// FINDINGS.md), so it is cut from the registered volume instead of being invented.
fn real_mirror() -> Option<(BootSector, Vec<u8>)> {
    let boot = BootSector::parse(
        &std::fs::read(forensic_testdata::artifact("ntfs-mkntfs-boot")?).unwrap(),
    )
    .unwrap();
    let volume = std::fs::read(forensic_testdata::artifact("ntfs-mkntfs-volume")?).unwrap();
    let at = (boot.mftmirr_lcn * boot.cluster_size) as usize;
    let len = MIRRORED_RECORDS as usize * boot.mft_record_size as usize;
    let bytes = volume
        .get(at..at + len)
        .expect("mirror is inside the image");
    Some((boot, bytes.to_vec()))
}

#[test]
fn real_mftmirr_agrees_with_the_real_mft() {
    let mft_path = artifact_or_skip!("ntfs-mkntfs-mft");
    let Some((boot, mirror)) = real_mirror() else {
        return;
    };
    let mft = Mft::from_reader(std::fs::File::open(mft_path).unwrap()).unwrap();

    // Ground truth from the volume itself: $MFTMirr (entry 1) is exactly four records long.
    let entry = mft.entry(1).unwrap().expect("$MFTMirr has a record");
    assert_eq!(
        entry.primary_name().map(|n| n.name.as_str()),
        Some("$MFTMirr")
    );
    assert_eq!(
        entry.data().map(|d| d.size()),
        Some(MIRRORED_RECORDS * u64::from(boot.mft_record_size))
    );

    let mirr = MftMirr::open(Box::new(BytesSource(mirror)), Some(&boot)).unwrap();
    assert!(mirr.anomalies.is_empty(), "{:?}", mirr.anomalies);
    assert_eq!(mirr.record_count(), MIRRORED_RECORDS);
    let names: Vec<String> = mirr
        .records()
        .map(|r| {
            let r = r.expect("every mirrored record parses");
            let name = r
                .attributes_of(0x30)
                .filter_map(|a| a.resident_value())
                .filter_map(|v| frnsc_ntfs::attr::FileName::parse(v).ok())
                .map(|n| n.name)
                .next();
            name.unwrap_or_default()
        })
        .collect();
    assert_eq!(names, ["$MFT", "$MFTMirr", "$LogFile", "$Volume"]);

    let c = mirr.compare_with(&mft);
    assert!(
        c.agrees(),
        "$MFT and $MFTMirr disagree on this volume: {}",
        c.disagreements()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    );
    // ntfscat writes the loose $MFT with the fixups already reverted, while the mirror was read
    // straight out of the image: the content agrees, the multi-sector protection does not.
    let counts = c.counts();
    assert_eq!(
        (counts.compared, counts.divergent, counts.unreadable),
        (MIRRORED_RECORDS, 0, 0)
    );
    // Both sides' protection verifies (`PreApplied` and `Ok`), which is what makes looking past
    // the raw byte difference safe here. A side that did not verify would be `FixupTorn`.
    assert_eq!(counts.fixup_only, MIRRORED_RECORDS);
    assert_eq!(counts.fixup_torn, 0);
    assert!(!c.is_not_a_mirror());
    for check in &c.checks {
        assert_eq!(check.verdict, MirrorVerdict::FixupOnly);
        assert!(check.primary.fixup_verifies() && check.mirror.fixup_verifies());
        assert_eq!(check.primary.fixup, Some(FixupStatus::PreApplied));
        assert_eq!(check.mirror.fixup, Some(FixupStatus::Ok));
        assert_eq!(check.primary.sequence, check.mirror.sequence);
        assert_eq!(
            check.primary.raw.as_deref().map(<[u8]>::len),
            Some(boot.mft_record_size as usize)
        );
    }
    assert_eq!(c.anomalies(), Vec::new());
}

#[test]
fn real_mftmirr_through_the_pipeline() {
    let mft = artifact_or_skip!("ntfs-mkntfs-mft");
    let boot_path = artifact_or_skip!("ntfs-mkntfs-boot");
    let Some((_, mirror)) = real_mirror() else {
        return;
    };
    let fs: Arc<dyn FileSystem> = Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("C/$MFT", std::fs::read(mft).unwrap())
            .with_file("C/$Boot", std::fs::read(boot_path).unwrap())
            .with_file("C/$MFTMirr", mirror),
    );
    let r = run(fs, vec![Arc::new(MftParserFactory::default())]);
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);

    let entries = by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY);
    assert_eq!(entries.len(), MIRRORED_RECORDS as usize);
    assert!(by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK).is_empty());

    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(
        summary.field_as_u64(f::MIRROR_COMPARED),
        Some(MIRRORED_RECORDS)
    );
    assert_eq!(summary.field_as_u64(f::MIRROR_DIVERGENT), Some(0));
    assert_eq!(
        summary.field_as_u64(f::MIRROR_FIXUP_ONLY),
        Some(MIRRORED_RECORDS)
    );
    assert!(
        summary.anomalies().flags().is_empty(),
        "no false $MFTMirr finding on a clean volume: {summary}"
    );
}

#[test]
fn loose_mft_library_api() {
    let mft = artifact_or_skip!("ntfs-mkntfs-mft");
    let m = Mft::from_reader(std::fs::File::open(mft).unwrap()).unwrap();
    let mut deleted = Vec::new();
    for e in m.entries() {
        let e = e.unwrap();
        assert!(e.anomalies.is_empty(), "{}: {:?}", e.reference, e.anomalies);
        if !e.in_use() {
            deleted.push(m.path_of(&e).path);
        }
    }
    deleted.sort();
    assert_eq!(
        deleted,
        vec!["\\Users\\bob\\gone.bin", "\\Users\\bob\\gone_small.txt"]
    );
}

#[cfg(feature = "volume")]
mod volume {
    use super::*;
    use frnsc_ntfs::volume::deleted::ContentStatus;
    use frnsc_ntfs::volume::{NtfsFs, Volume};
    use frnsc_ntfs::NtfsAnomaly;

    fn open() -> Option<NtfsFs> {
        let path = forensic_testdata::artifact("ntfs-mkntfs-volume")?;
        let vol = Volume::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        assert!(vol.anomalies.is_empty(), "{:?}", vol.anomalies);
        Some(NtfsFs::from_volume(vol))
    }

    /// Both copies read out of the same image still carry their fixups, so a faithful mirror is
    /// identical byte for byte here, not just after the fixups are applied.
    #[test]
    fn real_volume_mftmirr_agrees_byte_for_byte() {
        let Some(path) = forensic_testdata::artifact("ntfs-mkntfs-volume") else {
            return;
        };
        let vol = Volume::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        let c = vol.mirror.as_ref().expect("the $MFTMirr check ran");
        assert_eq!(c.counts().compared, MIRRORED_RECORDS);
        assert!(
            c.agrees(),
            "{}",
            c.disagreements()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
        assert_eq!(c.counts().identical, MIRRORED_RECORDS);
        for check in &c.checks {
            assert_eq!(check.primary.raw, check.mirror.raw);
            assert_eq!(check.primary.fixup, Some(FixupStatus::Ok));
        }
        assert_eq!(c.anomalies(), Vec::new());
        // A real, complete volume: the mirror was reachable where its boot sector said, so the
        // "could not be read" anomaly must not fire either.
        assert!(
            !vol.anomalies
                .iter()
                .any(|a| matches!(a, NtfsAnomaly::MftMirrUnreadable { .. })),
            "{:?}",
            vol.anomalies
        );
    }

    #[test]
    fn allocated_files_match_ground_truth() {
        let Some(fs) = open() else { return };
        for p in [
            "Users/bob/Documents/small.txt",
            "Users/bob/Documents/big.bin",
            "Users/bob/comp/zeros.bin",
        ] {
            assert_eq!(fs.read_all(FPath::new(p)).unwrap(), expected(p), "{p}");
        }
        assert_eq!(
            fs.read_all(FPath::new("Users/bob/hardlink.txt")).unwrap(),
            b"hello ntfs"
        );
        let sparse = fs.read_all(FPath::new("Users/bob/sparse.dat")).unwrap();
        assert_eq!(sparse.len(), 1 << 20);
        assert_eq!(&sparse[524288..524288 + 11], b"SPARSE-DATA");
        assert!(sparse[..524288].iter().all(|&b| b == 0));
        let mut zone = String::new();
        std::io::Read::read_to_string(
            &mut fs
                .open_stream(FPath::new("Users/bob/Documents/big.bin"), "Zone.Identifier")
                .unwrap(),
            &mut zone,
        )
        .unwrap();
        assert!(zone.contains("ZoneId=3"));
        let zeros = fs.metadata(FPath::new("Users/bob/comp/zeros.bin")).unwrap();
        assert!(zeros.attributes.contains(FileAttributes::COMPRESSED));
    }

    #[test]
    fn deleted_files_are_recovered_byte_exact() {
        let Some(fs) = open() else { return };
        let (files, report) = fs.deleted_files().unwrap();
        assert_eq!(report.admitted, 2);
        for f in &files {
            let v = f.value();
            let rel = v.path.path.trim_start_matches('\\').replace('\\', "/");
            assert!(
                matches!(
                    v.content,
                    ContentStatus::Recoverable | ContentStatus::Resident
                ),
                "{rel}: {:?}",
                v.content
            );
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut fs.open_deleted(v).unwrap().into_value(), &mut bytes)
                .unwrap();
            assert_eq!(bytes, expected(&rel), "{rel}");
        }
    }

    #[test]
    fn deleted_files_through_the_core_capability_are_byte_exact() {
        let Some(fs) = open() else { return };
        let deleted = fs.as_deleted().unwrap();
        let (entries, report) = deleted.deleted_entries(FPath::new("")).unwrap();
        assert_eq!(report.admitted, 2);
        for e in entries.iter().map(|r| r.value()) {
            let rel = e
                .path
                .as_ref()
                .expect("mkntfs sample paths resolve")
                .to_string();
            assert!(e.content_readable, "{rel}: {}", e.content_status);
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut deleted
                    .open_deleted(FPath::new(""), e.id)
                    .unwrap()
                    .into_value(),
                &mut bytes,
            )
            .unwrap();
            assert_eq!(bytes, expected(&rel), "{rel}");
        }
    }
}
