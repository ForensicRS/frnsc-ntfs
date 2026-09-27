//! `MftParserFactory` end to end over an in-memory VFS holding a loose `$MFT`.

mod common;

use std::sync::Arc;

use common::{one, run};
use forensic_rs::dictionary;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use forensic_rs::provenance::{AnomalyFlags, Confidence};
use frnsc_ntfs::fields as f;
use frnsc_ntfs::fixtures::{times, MftBuilder, RecordBuilder, DAY, FILE_TIME_2020 as T};
use frnsc_ntfs::parser::MftParserFactory;

fn sample_mft() -> Vec<u8> {
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(5, 5, "Users", T)
            .build(),
    );
    b.put(
        41,
        RecordBuilder::file(41, 1)
            .std_info(T)
            .file_name(40, 1, "report.pdf", T)
            .non_resident(
                0x80,
                "",
                &[(4, Some(1000)), (2, None), (8, Some(900))],
                50_000,
                4096,
            )
            .resident_data(
                "Zone.Identifier",
                b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.example/r.pdf\r\n",
            )
            .build(),
    );
    // Deleted small file: content still resident in the record.
    b.put(
        42,
        RecordBuilder::file(42, 2)
            .deleted()
            .std_info(T + DAY)
            .file_name(40, 1, "pass.txt", T)
            .resident_data("", b"hunter2")
            .build(),
    );
    // Timestomped executable.
    b.put(
        43,
        RecordBuilder::file(43, 1)
            .std_info_times(&times(T - 900 * DAY), 0x20, 0)
            .file_name(40, 1, "svch0st.exe", T)
            .build(),
    );
    // Unreadable record.
    b.put(44, vec![0x5A; 1024]);
    b.build()
}

fn fs_with(mft: Vec<u8>) -> Arc<dyn FileSystem> {
    Arc::new(InMemoryVirtualFileSystem::new().with_file("evidence/C/$MFT", mft))
}

#[test]
fn loose_mft_end_to_end() {
    let r = run(
        fs_with(sample_mft()),
        vec![Arc::new(MftParserFactory::default())],
    );

    // One Err item for the unreadable record, the rest of the stream intact.
    assert_eq!(r.result.errors.len(), 1, "{:?}", r.result.errors);

    let report = one(&r.records, dictionary::FILE_NAME, "report.pdf");
    assert_eq!(
        report.field_as_str(dictionary::FILE_PATH),
        Some("\\Users\\report.pdf")
    );
    assert_eq!(
        report.field_as_str(dictionary::FILE_DIRECTORY),
        Some("\\Users")
    );
    assert_eq!(report.field_as_str(dictionary::FILE_EXTENSION), Some("pdf"));
    assert_eq!(report.field_as_u64(dictionary::FILE_SIZE), Some(50_000));
    assert_eq!(report.field_as_str(f::ZONE_ID), Some("3"));
    assert_eq!(
        report.field_as_str(f::ZONE_HOST_URL),
        Some("https://evil.example/r.pdf")
    );
    assert_eq!(report.field_as_str(f::RECOVERY), Some("allocated"));
    assert_eq!(report.field_as_u64(f::DATA_RUN_COUNT), Some(3));
    assert!(report.get_date(dictionary::FILE_CREATED).is_some());
    assert!(
        report.field("@timestamp").is_none(),
        "an MFT entry is not an event"
    );

    let deleted = one(&r.records, dictionary::FILE_NAME, "pass.txt");
    assert_eq!(deleted.field_as_str(f::RECOVERY), Some("deleted_metadata"));
    assert_eq!(
        deleted.field_as_str(f::DATA_RESIDENT_HEX),
        Some("68756e74657232")
    );
    assert_eq!(
        deleted.field_as_str(dictionary::FILE_PATH),
        Some("\\Users\\pass.txt")
    );
    assert!(
        deleted.confidence(&r.store) < report.confidence(&r.store),
        "deleted metadata must grade below an allocated read"
    );

    let stomped = one(&r.records, dictionary::FILE_NAME, "svch0st.exe");
    assert!(stomped.anomalies().has(AnomalyFlags::TIMESTAMP_DIVERGENCE));
    assert!(
        r.findings
            .iter()
            .any(|x| x.title.to_lowercase().contains("timestamp")),
        "{:?}",
        r.findings.iter().map(|x| &x.title).collect::<Vec<_>>()
    );

    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFT_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MFT_INVALID), Some(1));
    assert_eq!(summary.field_as_u64(f::MFT_DELETED), Some(1));

    for d in &r.records {
        assert_ne!(d.confidence(&r.store), Confidence::Unknown);
    }
}

#[test]
fn output_is_deterministic() {
    let a = run(
        fs_with(sample_mft()),
        vec![Arc::new(MftParserFactory::default())],
    );
    let b = run(
        fs_with(sample_mft()),
        vec![Arc::new(MftParserFactory::default())],
    );
    let render = |r: &common::Run| r.records.iter().map(|d| d.to_string()).collect::<Vec<_>>();
    assert_eq!(render(&a), render(&b));
}

#[test]
fn nothing_to_do_without_an_mft() {
    let fs: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("a.txt", b"x".to_vec()));
    let r = run(fs, vec![Arc::new(MftParserFactory::default())]);
    assert!(r.records.is_empty());
    assert!(r.result.errors.is_empty());
}
