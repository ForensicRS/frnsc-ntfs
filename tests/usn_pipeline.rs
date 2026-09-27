//! `UsnParserFactory` over a KAPE-style export: `$Extend/$UsnJrnl%3A$J` next to `$MFT`.

mod common;

use std::sync::Arc;

use common::{by_field, run};
use forensic_rs::dictionary;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_ntfs::fields as f;
use frnsc_ntfs::fixtures::usn::usn_v2;
use frnsc_ntfs::fixtures::{MftBuilder, RecordBuilder, FILE_TIME_2020 as T};
use frnsc_ntfs::parser::UsnParserFactory;
use frnsc_ntfs::FileRef;

#[test]
fn journal_events_with_paths() {
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(5, 5, "Temp", T)
            .build(),
    );
    let mut j = vec![0u8; 8192];
    j.extend(usn_v2(
        FileRef::new(60, 1),
        FileRef::new(40, 1),
        0x2000,
        T,
        0x100,
        "x.ps1",
    ));
    j.extend(usn_v2(
        FileRef::new(60, 1),
        FileRef::new(40, 1),
        0x2050,
        T + 10,
        0x8000_0200,
        "x.ps1",
    ));
    // A directory since deleted and reused: history does not match the current MFT.
    j.extend(usn_v2(
        FileRef::new(61, 1),
        FileRef::new(40, 9),
        0x2100,
        T + 20,
        0x100,
        "old.txt",
    ));
    let fs: Arc<dyn FileSystem> = Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("C/$MFT", b.build())
            .with_file("C/$Extend/$UsnJrnl%3A$J", j),
    );
    let r = run(fs, vec![Arc::new(UsnParserFactory::default())]);
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);
    let recs = by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_USN);
    assert_eq!(recs.len(), 3);
    assert!(recs[0].get_date("@timestamp").is_some());
    assert_eq!(
        recs[0].field_as_str(dictionary::FILE_PATH),
        Some("\\Temp\\x.ps1")
    );
    assert_eq!(
        recs[0].field_as_str(dictionary::EVENT_ACTION),
        Some("file_create")
    );
    assert_eq!(
        recs[1].field_as_str(dictionary::EVENT_ACTION),
        Some("file_delete|close")
    );
    assert_eq!(recs[2].field_as_str(f::PATH_STATUS), Some("stale_parent"));
}
