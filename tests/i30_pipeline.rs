//! `I30ParserFactory` over a loose `$I30` export with its `$MFT` alongside.

mod common;

use std::sync::Arc;

use common::{by_field, one, run};
use forensic_rs::dictionary;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use forensic_rs::provenance::AnomalyFlags;
use frnsc_ntfs::fields as f;
use frnsc_ntfs::fixtures::indx::{index_entry, indx_record};
use frnsc_ntfs::fixtures::{
    file_name_value_times, times, MftBuilder, RecordBuilder, FILE_TIME_2020 as T,
};
use frnsc_ntfs::parser::{I30ParserFactory, MftParserFactory};
use frnsc_ntfs::FileRef;

const DIR: FileRef = FileRef::new(40, 1);

fn key(name: &str) -> Vec<u8> {
    file_name_value_times(DIR, name, &times(T), 1, 4096, 10)
}

fn evidence() -> Arc<dyn FileSystem> {
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(5, 5, "Temp", T)
            .build(),
    );
    b.put(
        60,
        RecordBuilder::file(60, 1)
            .std_info(T)
            .file_name(40, 1, "a.txt", T)
            .build(),
    );
    // 61 was dropper.exe (sequence 2); deleting it bumped the record to 3.
    b.put(
        61,
        RecordBuilder::file(61, 3)
            .deleted()
            .std_info(T)
            .file_name(40, 1, "dropper.exe", T)
            .build(),
    );
    // 62 is listed live in the index but its record was freed: stale index entry.
    b.put(
        62,
        RecordBuilder::file(62, 2)
            .deleted()
            .std_info(T)
            .file_name(40, 1, "stale.txt", T)
            .build(),
    );
    let live = vec![
        index_entry(FileRef::new(60, 1), &key("a.txt")),
        index_entry(FileRef::new(62, 1), &key("stale.txt")),
    ];
    let slack = index_entry(FileRef::new(61, 2), &key("dropper.exe"));
    let i30 = indx_record(0, &live, &slack, 4096);
    Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("C/$MFT", b.build())
            .with_file("C/Temp/$I30", i30),
    )
}

#[test]
fn live_and_slack_entries_with_mft_cross_check() {
    let r = run(evidence(), vec![Arc::new(I30ParserFactory::default())]);
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);
    let live = by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_INDEX_ENTRY);
    assert_eq!(live.len(), 2);
    let a = one(&r.records, dictionary::FILE_NAME, "a.txt");
    assert_eq!(a.field_as_str(dictionary::FILE_PATH), Some("\\Temp\\a.txt"));
    assert_eq!(a.field_as_str(f::INDEX_MFT_STATUS), Some("live"));
    let stale = one(&r.records, dictionary::FILE_NAME, "stale.txt");
    assert!(stale.anomalies().has(AnomalyFlags::STALE_REFERENCE));

    let carved = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_INDEX_SLACK);
    assert_eq!(
        carved.field_as_str(dictionary::FILE_NAME),
        Some("dropper.exe")
    );
    assert_eq!(carved.field_as_str(f::RECOVERY), Some("slack"));
    assert_eq!(carved.field_as_str(f::INDEX_MFT_STATUS), Some("deleted"));
    assert_eq!(
        carved.field_as_str(dictionary::FILE_PATH),
        Some("\\Temp\\dropper.exe")
    );
    assert!(carved.confidence(&r.store) < a.confidence(&r.store));
}

#[test]
fn index_root_slack_from_the_mft_alone() {
    // A small directory: its index lives in $INDEX_ROOT, and a deleted child's entry is in its slack.
    let e = index_entry(FileRef::new(60, 1), &key("kept.txt"));
    let gone = index_entry(FileRef::new(61, 2), &key("wiped.log"));
    let last = frnsc_ntfs::fixtures::indx::last_entry();
    let used = 16 + e.len() + last.len();
    let mut root = vec![0u8; 32];
    root[0..4].copy_from_slice(&0x30u32.to_le_bytes());
    root[8..12].copy_from_slice(&4096u32.to_le_bytes());
    root[16..20].copy_from_slice(&16u32.to_le_bytes());
    root[20..24].copy_from_slice(&(used as u32).to_le_bytes());
    root[24..28].copy_from_slice(&((used + gone.len()) as u32).to_le_bytes());
    root.extend(&e);
    root.extend(&last);
    root.extend(&gone);
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(5, 5, "Logs", T)
            .resident(0x90, "$I30", &root)
            .build(),
    );
    b.put(
        60,
        RecordBuilder::file(60, 1)
            .std_info(T)
            .file_name(40, 1, "kept.txt", T)
            .build(),
    );
    let fs: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("$MFT", b.build()));
    let r = run(fs, vec![Arc::new(MftParserFactory::default())]);
    let carved = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_INDEX_SLACK);
    assert_eq!(
        carved.field_as_str(dictionary::FILE_PATH),
        Some("\\Logs\\wiped.log")
    );
}
