//! `$MFTMirr` end to end: the copy's own records, and the cross-check against the `$MFT` it sits
//! next to.

mod common;

use std::sync::Arc;

use common::{by_field, one, run};
use forensic_rs::dictionary;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use forensic_rs::provenance::{AnomalyFlags, DerivedFrom, MergeReason, SourceKey};
use frnsc_ntfs::fields as f;
use frnsc_ntfs::fixtures::{MftBuilder, RecordBuilder, FILE_TIME_2020 as T};
use frnsc_ntfs::mft::mirror::{MIRRORED_RECORDS, STREAM_MFT, STREAM_MFTMIRR};
use frnsc_ntfs::parser::MftParserFactory;

const RS: usize = 1024;

fn sample_mft() -> Vec<u8> {
    let mut b = MftBuilder::new();
    for (entry, name) in [(1u64, "$MFTMirr"), (2, "$LogFile"), (3, "$Volume")] {
        b.put(
            entry,
            RecordBuilder::file(entry, entry as u16)
                .std_info(T)
                .file_name(5, 5, name, T)
                .build(),
        );
    }
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .std_info(T)
            .file_name(5, 5, "report.pdf", T)
            .build(),
    );
    b.build()
}

fn mirror_of(mft: &[u8]) -> Vec<u8> {
    mft[..RS * MIRRORED_RECORDS as usize].to_vec()
}

fn fs_with(mft: Vec<u8>, mirror: Option<Vec<u8>>) -> Arc<dyn FileSystem> {
    let mut fs = InMemoryVirtualFileSystem::new().with_file("evidence/C/$MFT", mft);
    if let Some(m) = mirror {
        fs = fs.with_file("evidence/C/$MFTMirr", m);
    }
    Arc::new(fs)
}

#[test]
fn a_faithful_mirror_is_parsed_and_reported_as_checked_and_clean() {
    let mft = sample_mft();
    let r = run(
        fs_with(mft.clone(), Some(mirror_of(&mft))),
        vec![Arc::new(MftParserFactory::default())],
    );
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);

    let entries = by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY);
    assert_eq!(entries.len(), MIRRORED_RECORDS as usize);
    // The copy's records are tagged as the copy, never mixed with the $MFT's own entries.
    for (i, d) in entries.iter().enumerate() {
        assert_eq!(d.field_as_u64(f::ENTRY), Some(i as u64));
        assert_eq!(
            d.field_as_str(f::MIRROR_SOURCE_PATH),
            Some("evidence/C/$MFTMirr")
        );
        assert_eq!(d.field_as_u64(f::RECORD_OFFSET), Some((i * RS) as u64));
        assert!(d.anomalies().flags().is_empty());
    }
    assert_eq!(
        entries[1].field_as_str(dictionary::FILE_NAME),
        Some("$MFTMirr")
    );

    // No disagreement records, but a summary that says the check ran.
    assert!(by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK).is_empty());
    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_COMPARED), Some(4));
    assert_eq!(summary.field_as_u64(f::MIRROR_IDENTICAL), Some(4));
    assert_eq!(summary.field_as_u64(f::MIRROR_DIVERGENT), Some(0));
    assert_eq!(summary.field_as_u64(f::MIRROR_RECORDS), Some(4));
    assert_eq!(summary.field_as_u64(f::MIRROR_RECORD_SIZE), Some(RS as u64));
    assert_eq!(
        summary.field_as_str(dictionary::FILE_PATH),
        Some("evidence/C/$MFT")
    );
    assert!(summary.anomalies().flags().is_empty());
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

#[test]
fn a_tampered_mirror_record_reaches_the_analyst_with_both_sides() {
    let mft = sample_mft();
    let mut mirror = mirror_of(&mft);
    // Record 3 ($Volume): rewrite the sequence number and one byte of the body in the copy.
    mirror[3 * RS + 16..3 * RS + 18].copy_from_slice(&0x0042u16.to_le_bytes());
    mirror[3 * RS + 300] ^= 0xFF;
    let r = run(
        fs_with(mft, Some(mirror)),
        vec![Arc::new(MftParserFactory::default())],
    );
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);

    let check = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK);
    assert_eq!(check.field_as_u64(f::ENTRY), Some(3));
    assert_eq!(check.field_as_str(f::MIRROR_VERDICT), Some("divergent"));
    assert_eq!(
        check.field(f::MIRROR_DIFFERING_FIELDS),
        Some(&Field::Array(vec!["sequence".into(), "body".into()]))
    );
    assert_eq!(check.field_as_u64(f::MIRROR_FIRST_DIFFERENCE), Some(16));

    // Both sides, raw as stored, each with the stream its offset belongs to.
    assert_eq!(
        check.field_as_str(f::MIRROR_PRIMARY_STREAM),
        Some(STREAM_MFT)
    );
    assert_eq!(
        check.field_as_str(f::MIRROR_COPY_STREAM),
        Some(STREAM_MFTMIRR)
    );
    assert_eq!(check.field_as_u64(f::MIRROR_PRIMARY_OFFSET), Some(3 * 1024));
    assert_eq!(check.field_as_u64(f::MIRROR_COPY_OFFSET), Some(3 * 1024));
    let primary = check
        .field_as_str(f::MIRROR_PRIMARY_HEX)
        .expect("$MFT side");
    let copy = check.field_as_str(f::MIRROR_COPY_HEX).expect("mirror side");
    assert_eq!(primary.len(), RS * 2, "the whole record, not a prefix");
    assert_eq!(copy.len(), RS * 2);
    assert_ne!(primary, copy);
    assert_eq!(check.field_as_u64(f::MIRROR_PRIMARY_SEQUENCE), Some(3));
    assert_eq!(check.field_as_u64(f::MIRROR_COPY_SEQUENCE), Some(0x42));
    assert!(check.anomalies().has(AnomalyFlags::SOURCE_DIVERGENCE));

    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_DIVERGENT), Some(1));
    assert_eq!(summary.field_as_u64(f::MIRROR_IDENTICAL), Some(3));
    assert_eq!(
        summary.field(f::MIRROR_DISAGREEMENTS),
        Some(&Field::Array(vec!["3".into()]))
    );
    assert!(summary.anomalies().has(AnomalyFlags::SOURCE_DIVERGENCE));
}

#[test]
fn a_mirror_without_its_mft_is_parsed_and_says_the_check_did_not_run() {
    let mirror = mirror_of(&sample_mft());
    let fs: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("evidence/C/$MFTMirr", mirror));
    let r = run(fs, vec![Arc::new(MftParserFactory::default())]);
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);
    assert_eq!(
        by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY).len(),
        MIRRORED_RECORDS as usize
    );
    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_COMPARED), Some(0));
    assert_eq!(summary.field_as_u64(f::MIRROR_IDENTICAL), None);
    assert!(summary.anomalies().flags().is_empty());
}

#[test]
fn a_truncated_mirror_is_an_err_item_and_the_run_goes_on() {
    let mft = sample_mft();
    let mut mirror = mirror_of(&mft);
    mirror.truncate(3 * RS + 100);
    let r = run(
        fs_with(mft, Some(mirror)),
        vec![Arc::new(MftParserFactory::default())],
    );
    // One Err for the cut record; the three whole ones are still emitted.
    assert_eq!(r.result.errors.len(), 1, "{:?}", r.result.errors);
    assert_eq!(
        by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY).len(),
        3
    );
    let check = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK);
    assert_eq!(check.field_as_str(f::MIRROR_VERDICT), Some("unreadable"));
    assert!(check.field_as_str(f::MIRROR_COPY_ERROR).is_some());
    // The $MFT side of the same record is still readable, and is kept.
    assert!(check.field_as_str(f::MIRROR_PRIMARY_HEX).is_some());
    assert!(check.field_as_str(f::MIRROR_COPY_HEX).is_none());
    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_UNREADABLE), Some(1));
    assert!(summary.anomalies().has(AnomalyFlags::TRUNCATED));
}

#[test]
fn a_mirror_in_a_shared_ancestor_is_not_paired_with_every_mft() {
    // A multi-volume export where only volume C's mirror was collected and landed in the case
    // root. Pairing it with D's `$MFT` would declare a clean volume tampered with, and would emit
    // the mirror's records once per `$MFT`.
    let mft = sample_mft();
    let fs: Arc<dyn FileSystem> = Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("case/$MFTMirr", mirror_of(&mft))
            .with_file("case/C/$MFT", mft.clone())
            .with_file("case/D/$MFT", mft),
    );
    let r = run(fs, vec![Arc::new(MftParserFactory::default())]);
    assert!(r.result.errors.is_empty(), "{:?}", r.result.errors);

    // The mirror is still parsed — on its own, exactly once.
    let entries = by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY);
    assert_eq!(entries.len(), MIRRORED_RECORDS as usize);
    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_COMPARED), Some(0));
    assert_eq!(summary.field_as_str(dictionary::FILE_PATH), None);
    // ...and nothing is claimed about either volume's integrity.
    assert!(by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK).is_empty());
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

#[test]
fn one_mirror_is_cross_checked_against_one_mft() {
    // Two `$MFT`s in one directory (`$MFT` and an exported `$MFT.bin`). The mirror belongs to one
    // of them; cross-checking it against both would double every record it emits.
    let mft = sample_mft();
    let fs: Arc<dyn FileSystem> = Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("evidence/C/$MFT", mft.clone())
            .with_file("evidence/C/$MFT.bin", mft.clone())
            .with_file("evidence/C/$MFTMirr", mirror_of(&mft)),
    );
    let r = run(fs, vec![Arc::new(MftParserFactory::default())]);
    assert_eq!(
        by_field(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_ENTRY).len(),
        MIRRORED_RECORDS as usize
    );
    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_COMPARED), Some(4));
}

#[test]
fn a_cross_check_record_names_both_files_it_was_read_from() {
    let mft = sample_mft();
    let mut mirror = mirror_of(&mft);
    mirror[3 * RS + 300] ^= 0xFF;
    let r = run(
        fs_with(mft, Some(mirror)),
        vec![Arc::new(MftParserFactory::default())],
    );
    let check = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK);
    // Half of what this record carries is `$MFT` bytes, so the `$MFT` has to be retained as a
    // source: a chain of custody for the finding that named only the mirror would be wrong.
    let snapshot = r
        .store
        .get(check.provenance())
        .expect("the check record's provenance resolves");
    let DerivedFrom::Merged(parents, reason) = &snapshot.derived_from else {
        panic!("expected a merge, got {:?}", snapshot.derived_from);
    };
    assert_eq!(*reason, MergeReason::Reconciliation);
    let sources: Vec<SourceKey> = parents
        .iter()
        .map(|p| r.store.get(*p).expect("parent resolves").source)
        .collect();
    assert!(sources.contains(&SourceKey::Path("evidence/C/$MFTMirr".into())));
    assert!(sources.contains(&SourceKey::Path("evidence/C/$MFT".into())));
}

#[test]
fn a_torn_primary_record_reaches_the_analyst_instead_of_passing_as_fixup_only() {
    // Half-revert stride 1 of `$MFT` record 0: the fixed-up bytes still equal the mirror's, so
    // only the fixup status tells the analyst the record was torn — and that status only ever
    // reaches output on a check record.
    let mut mft = sample_mft();
    let mirror = mirror_of(&mft);
    let saved = [mft[0x34], mft[0x35]];
    mft[1022..1024].copy_from_slice(&saved);
    let r = run(
        fs_with(mft, Some(mirror)),
        vec![Arc::new(MftParserFactory::default())],
    );

    let check = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_CHECK);
    assert_eq!(check.field_as_u64(f::ENTRY), Some(0));
    assert_eq!(check.field_as_str(f::MIRROR_VERDICT), Some("fixup_torn"));
    assert_eq!(check.field_as_str(f::MIRROR_PRIMARY_FIXUP), Some("torn"));
    assert_eq!(check.field_as_str(f::MIRROR_COPY_FIXUP), Some("ok"));
    assert!(check.field_as_str(f::MIRROR_PRIMARY_HEX).is_some());
    assert!(check.field_as_str(f::MIRROR_COPY_HEX).is_some());
    // A torn write is a failed integrity check, not "the two copies hold different records".
    assert!(check.anomalies().has(AnomalyFlags::CHECKSUM_MISMATCH));
    assert!(!check.anomalies().has(AnomalyFlags::SOURCE_DIVERGENCE));

    let summary = one(&r.records, f::RECORD_TYPE, f::RECORD_TYPE_MFTMIRR_SUMMARY);
    assert_eq!(summary.field_as_u64(f::MIRROR_FIXUP_TORN), Some(1));
    assert_eq!(summary.field_as_u64(f::MIRROR_FIXUP_ONLY), Some(0));
    assert_eq!(summary.field_as_u64(f::MIRROR_DIVERGENT), Some(0));
    assert!(summary.anomalies().has(AnomalyFlags::CHECKSUM_MISMATCH));
}

#[test]
fn output_is_deterministic() {
    let mft = sample_mft();
    let render = || {
        run(
            fs_with(mft.clone(), Some(mirror_of(&mft))),
            vec![Arc::new(MftParserFactory::default())],
        )
        .records
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
    };
    assert_eq!(render(), render());
}
