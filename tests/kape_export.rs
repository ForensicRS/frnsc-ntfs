//! All four loose-file parsers over one KAPE-style `C/` export, with no disk image.

mod common;

use std::sync::Arc;

use common::{by_field, one, run};
use forensic_rs::dictionary;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_ntfs::fields as f;
use frnsc_ntfs::fixtures::sds::{sds_entry, security_descriptor};
use frnsc_ntfs::fixtures::usn::usn_v2;
use frnsc_ntfs::fixtures::{boot_sector, times, MftBuilder, RecordBuilder, FILE_TIME_2020 as T};
use frnsc_ntfs::parser::{I30ParserFactory, MftParserFactory, SdsParserFactory, UsnParserFactory};
use frnsc_ntfs::FileRef;

fn export() -> Arc<dyn FileSystem> {
    let mut b = MftBuilder::new();
    b.put(
        60,
        RecordBuilder::file(60, 1)
            .std_info_times(&times(T), 0x20, 256)
            .file_name(5, 5, "owned.txt", T)
            .build(),
    );
    let mut sds = vec![0u8; 512 * 1024];
    let e = sds_entry(256, 0, &security_descriptor("S-1-5-21-11-22-33-1104"));
    sds[..e.len()].copy_from_slice(&e);
    sds[256 * 1024..256 * 1024 + e.len()].copy_from_slice(&e);
    let mut j = vec![0u8; 4096];
    j.extend(usn_v2(
        FileRef::new(60, 1),
        FileRef::new(5, 5),
        1,
        T,
        0x100,
        "owned.txt",
    ));
    Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("C/$MFT", b.build())
            .with_file("C/$Boot", boot_sector(512, 8, 1 << 20, 4, -10, 1))
            .with_file("C/$Secure%3A$SDS", sds)
            .with_file("C/$Extend/$UsnJrnl%3A$J", j),
    )
}

#[test]
fn whole_export_without_a_disk() {
    let r = run(
        export(),
        vec![
            Arc::new(MftParserFactory::default()),
            Arc::new(I30ParserFactory::default()),
            Arc::new(UsnParserFactory::default()),
            Arc::new(SdsParserFactory::default()),
        ],
    );
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);
    let owned = by_field(&r.records, dictionary::FILE_NAME, "owned.txt");
    let mft_rec = owned
        .iter()
        .find(|d| d.field_as_str(f::RECORD_TYPE) == Some(f::RECORD_TYPE_MFT_ENTRY))
        .unwrap();
    assert_eq!(
        mft_rec.field_as_str(dictionary::FILE_UID),
        Some("S-1-5-21-11-22-33-1104")
    );
    let usn = owned
        .iter()
        .find(|d| d.field_as_str(f::RECORD_TYPE) == Some(f::RECORD_TYPE_USN))
        .unwrap();
    assert_eq!(usn.field_as_str(dictionary::FILE_PATH), Some("\\owned.txt"));
    let sd = one(
        &r.records,
        f::RECORD_TYPE,
        f::RECORD_TYPE_SECURITY_DESCRIPTOR,
    );
    assert_eq!(sd.field_as_u64(f::SDS_SECURITY_ID), Some(256));
    assert!(sd.anomalies().flags().is_empty());
}
