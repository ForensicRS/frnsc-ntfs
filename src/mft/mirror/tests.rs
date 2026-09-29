use super::*;
use crate::fixtures::{MftBuilder, RecordBuilder, FILE_TIME_2020};
use crate::fixup::FIXUP_STRIDE;
use crate::source::BytesSource;

const RS: usize = 1024;

/// A loose `$MFT` whose first four records are the metafiles NTFS mirrors.
fn mft_bytes() -> Vec<u8> {
    let mut b = MftBuilder::new();
    for (entry, name) in [(1u64, "$MFTMirr"), (2, "$LogFile"), (3, "$Volume")] {
        b.put(
            entry,
            RecordBuilder::file(entry, entry as u16)
                .std_info(FILE_TIME_2020)
                .file_name(5, 5, name, FILE_TIME_2020)
                .build(),
        );
    }
    b.build()
}

/// The first [`MIRRORED_RECORDS`] records, byte for byte: what NTFS writes to `$MFTMirr`.
fn mirror_of(mft: &[u8]) -> Vec<u8> {
    mft[..RS * MIRRORED_RECORDS as usize].to_vec()
}

fn compare(mft: &[u8], mirror: Vec<u8>) -> MirrorComparison {
    let primary = Mft::from_bytes(mft.to_vec()).expect("fixture $MFT opens");
    let mirr = MftMirr::from_bytes(mirror).expect("fixture $MFTMirr opens");
    mirr.compare_with(&primary)
}

#[test]
fn a_faithful_copy_agrees_and_raises_nothing() {
    let mft = mft_bytes();
    let c = compare(&mft, mirror_of(&mft));
    assert_eq!(c.record_size, RS as u32);
    assert_eq!(c.checks.len(), MIRRORED_RECORDS as usize);
    assert!(c.agrees());
    assert_eq!(c.anomalies(), Vec::new());
    assert_eq!(c.counts().identical, MIRRORED_RECORDS);
    for (i, check) in c.checks.iter().enumerate() {
        assert_eq!(check.entry, i as u64);
        assert_eq!(check.verdict, MirrorVerdict::Identical);
        // Both sides are kept even when they agree, each with the stream its offset belongs to.
        assert_eq!(check.primary.stream, STREAM_MFT);
        assert_eq!(check.mirror.stream, STREAM_MFTMIRR);
        assert_eq!(check.primary.offset, (i * RS) as u64);
        assert_eq!(check.mirror.offset, (i * RS) as u64);
        assert_eq!(check.primary.raw.as_deref().map(<[u8]>::len), Some(RS));
        assert_eq!(check.primary.raw, check.mirror.raw);
        // Sequence numbers of the fixture metafiles: $MFT is 0-1, then 1-1, 2-2, 3-3.
        assert_eq!(check.primary.sequence, Some([1u16, 1, 2, 3][i]));
        assert_eq!(check.primary.sequence, check.mirror.sequence);
        assert_eq!(check.mirror.update_sequence, Some(1));
    }
}

#[test]
fn a_copy_with_the_fixups_already_reverted_is_not_a_mismatch() {
    // What `ntfscat` writes: the multi-sector protection is undone, the content is the same.
    let mft = mft_bytes();
    let mut mirror = mirror_of(&mft);
    for i in 0..MIRRORED_RECORDS as usize {
        let r = &mut mirror[i * RS..(i + 1) * RS];
        assert_eq!(apply_fixups(r, 0x30, 3), FixupStatus::Ok);
    }
    let c = compare(&mft, mirror);
    assert!(c.agrees(), "{:?}", c.disagreements().collect::<Vec<_>>());
    assert_eq!(c.counts().fixup_only, MIRRORED_RECORDS);
    assert_eq!(c.anomalies(), Vec::new());
    let check = &c.checks[0];
    assert_eq!(check.verdict, MirrorVerdict::FixupOnly);
    assert_eq!(check.primary.fixup, Some(FixupStatus::Ok));
    assert_eq!(check.mirror.fixup, Some(FixupStatus::PreApplied));
    // Raw bytes still differ: the finding must be able to show exactly what was stored.
    assert_ne!(check.primary.raw, check.mirror.raw);
}

/// A record whose stride 0 still holds the USN while stride 1 already holds the saved bytes:
/// half-reverted, which is what a torn write (or a tampered record) looks like. Its fixed-up bytes
/// equal a clean copy's, so a comparison that only asks "do the fixed bytes match" would call it
/// agreement and the torn status would never reach the analyst.
fn half_revert_first_stride(record: &mut [u8]) {
    // Stride 1's tail is the second saved value; put it back and leave stride 0 carrying the USN.
    let usa = 0x30;
    let saved = [record[usa + 4], record[usa + 5]];
    record[2 * FIXUP_STRIDE - 2..2 * FIXUP_STRIDE].copy_from_slice(&saved);
}

#[test]
fn a_torn_side_is_never_absorbed_into_fixup_only() {
    let mut mft = mft_bytes();
    let mirror = mirror_of(&mft);
    half_revert_first_stride(&mut mft[..RS]);
    let c = compare(&mft, mirror);

    let check = &c.checks[0];
    assert_eq!(
        check.primary.fixup,
        Some(FixupStatus::Torn {
            mismatched: 1,
            first: 1
        })
    );
    assert_eq!(check.mirror.fixup, Some(FixupStatus::Ok));
    // The content does agree — that is exactly why this used to pass as `fixup_only`.
    assert_eq!(check.primary.fixed_bytes(), check.mirror.fixed_bytes());
    assert!(check.verdict.content_agrees());
    assert_eq!(check.verdict, MirrorVerdict::FixupTorn);
    // ...but it is not clean, so it reaches the analyst as a check record with both sides.
    assert!(!check.agrees());
    assert!(c.disagreements().any(|d| d.entry == 0));
    assert!(check.primary.raw.is_some() && check.mirror.raw.is_some());
    assert_eq!(c.counts().fixup_torn, 1);
    assert_eq!(c.counts().fixup_only, 0);
    // A torn write is a checksum failure, not "the two copies hold different records".
    assert_eq!(
        c.anomalies(),
        vec![NtfsAnomaly::MftMirrTorn { entries: vec![0] }]
    );
    assert_eq!(
        check.anomaly(),
        Some(NtfsAnomaly::MftMirrTorn { entries: vec![0] })
    );
}

#[test]
fn a_difference_in_the_header_padding_still_names_where_it_is() {
    let mft = mft_bytes();
    let mut mirror = mirror_of(&mft);
    // Bytes 42..44 are header padding: no named field decodes them, and they are inside the
    // header, so neither the field loop nor the body comparison sees them.
    mirror[42] ^= 0xFF;
    let c = compare(&mft, mirror);
    let check = &c.checks[0];
    assert_eq!(check.verdict, MirrorVerdict::Divergent);
    assert_eq!(check.differing_fields, vec!["header_other"]);
    assert_eq!(check.first_difference, Some(42));
    assert!(check.to_string().contains("header_other"));
}

#[test]
fn a_file_that_is_not_a_mirror_at_all_is_not_diagnosed_as_tampering() {
    // A wrong-stream export named `$MFTMirr`: a clean multiple of the record size, so the size
    // anomaly does not fire either. Not one slot holds a record header.
    let boot =
        crate::boot::BootSector::parse(&crate::fixtures::boot_sector(512, 2, 32767, 4, -10, 1))
            .unwrap();
    let junk: Vec<u8> = (0..4 * RS).map(|i| (i % 251) as u8).collect();
    let mirr = MftMirr::open(Box::new(BytesSource(junk)), Some(&boot)).unwrap();
    assert!(mirr.anomalies.is_empty(), "{:?}", mirr.anomalies);
    let c = mirr.compare_with(&Mft::from_bytes(mft_bytes()).unwrap());

    assert!(c.is_not_a_mirror());
    assert_eq!(
        c.anomalies(),
        vec![NtfsAnomaly::MftMirrNotAMirror { slots: 4 }]
    );
    // The per-record evidence is untouched: both sides are still on every check.
    assert_eq!(c.checks.len(), 4);
    assert!(c.checks.iter().all(|x| x.mirror.raw.is_some()));
    // A real mirror, even a badly damaged one, is not mistaken for this.
    let real = compare(&mft_bytes(), mirror_of(&mft_bytes()));
    assert!(!real.is_not_a_mirror());
}

#[test]
fn a_tampered_mirror_record_carries_both_sides_and_names_the_fields() {
    let mft = mft_bytes();
    let mut mirror = mirror_of(&mft);
    // Record 3 ($Volume): change the sequence number, the LSN and one byte of the body.
    let at = 3 * RS;
    mirror[at + 16..at + 18].copy_from_slice(&0x0042u16.to_le_bytes());
    mirror[at + 8..at + 16].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
    mirror[at + 200] ^= 0xFF;
    let c = compare(&mft, mirror);

    assert!(!c.agrees());
    assert_eq!(
        c.anomalies(),
        vec![NtfsAnomaly::MftMirrMismatch { entries: vec![3] }]
    );
    let counts = c.counts();
    assert_eq!(
        (counts.compared, counts.identical, counts.divergent),
        (4, 3, 1)
    );

    let bad: Vec<&MirrorRecordCheck> = c.disagreements().collect();
    assert_eq!(bad.len(), 1);
    let check = bad[0];
    assert_eq!(check.entry, 3);
    assert_eq!(check.verdict, MirrorVerdict::Divergent);
    assert_eq!(check.differing_fields, vec!["lsn", "sequence", "body"]);
    assert_eq!(check.first_difference, Some(8));
    // Both sides, raw as stored, plus the sequence each claims.
    let p = check.primary.raw.as_ref().expect("primary read");
    let m = check.mirror.raw.as_ref().expect("mirror read");
    assert_eq!(p.len(), RS);
    assert_eq!(m.len(), RS);
    assert_ne!(p, m);
    assert_eq!(check.primary.sequence, Some(3));
    assert_eq!(check.mirror.sequence, Some(0x42));
    assert_eq!(check.primary.reference(3), Some(FileRef::new(3, 3)));
    assert_eq!(check.mirror.reference(3), Some(FileRef::new(3, 0x42)));
    assert!(check.to_string().contains("lsn"));
}

#[test]
fn a_truncated_trailing_record_is_an_err_item_not_a_panic() {
    let mft = mft_bytes();
    let mut mirror = mirror_of(&mft);
    mirror.truncate(3 * RS + 100);
    let mirr = MftMirr::from_bytes(mirror).expect("a truncated $MFTMirr still opens");
    assert_eq!(
        mirr.anomalies,
        vec![NtfsAnomaly::MftFileSizeMismatch {
            length: (3 * RS + 100) as u64,
            record_size: RS as u32,
        }]
    );
    // The partial record is still a slot, so it is reported rather than silently dropped.
    assert_eq!(mirr.record_count(), 4);
    let items: Vec<_> = mirr.records().collect();
    assert_eq!(items.len(), 4);
    assert!(items[..3].iter().all(Result::is_ok));
    let err = items[3]
        .as_ref()
        .expect_err("the cut record must be an Err");
    assert!(!err.to_string().is_empty());
    assert!(mirr.raw_record(3).is_err());
    assert!(mirr.record(3).is_err());

    let primary = Mft::from_bytes(mft).unwrap();
    let c = mirr.compare_with(&primary);
    assert_eq!(c.checks[3].verdict, MirrorVerdict::Unreadable);
    assert!(c.checks[3].mirror.unreadable.is_some());
    assert!(c.checks[3].mirror.raw.is_none());
    // The primary side of the same record is still evidence and is kept.
    assert!(c.checks[3].primary.raw.is_some());
    assert_eq!(
        c.anomalies(),
        vec![NtfsAnomaly::MftMirrMismatch { entries: vec![3] }]
    );
}

#[test]
fn a_mirror_longer_than_the_mft_says_which_side_was_missing() {
    let mft = mft_bytes();
    let mirror = mirror_of(&mft);
    let short = Mft::from_bytes(mft[..2 * RS].to_vec()).unwrap();
    let c = MftMirr::from_bytes(mirror).unwrap().compare_with(&short);
    assert_eq!(c.checks.len(), 4);
    assert!(c.checks[..2].iter().all(MirrorRecordCheck::agrees));
    for check in &c.checks[2..] {
        assert_eq!(check.verdict, MirrorVerdict::Unreadable);
        assert_eq!(check.primary.raw, None);
        assert!(check.primary.unreadable.is_some());
        // The mirror still has the record; only the primary could not supply it.
        assert!(check.mirror.raw.is_some());
    }
}

#[test]
fn every_prefix_and_bitflip_is_safe() {
    let mft = mft_bytes();
    let primary = Mft::from_bytes(mft.clone()).unwrap();
    let full = mirror_of(&mft);
    for len in 0..full.len() {
        if let Ok(m) = MftMirr::from_bytes(full[..len].to_vec()) {
            for item in m.records() {
                let _ = item;
            }
            let _ = m.compare_with(&primary);
        }
    }
    // Deterministic corruption: every 97th byte flipped in turn.
    for i in (0..full.len()).step_by(97) {
        let mut m = full.clone();
        m[i] ^= 0xA5;
        if let Ok(m) = MftMirr::from_bytes(m) {
            let c = m.compare_with(&primary);
            assert_eq!(c.checks.len(), m.record_count() as usize);
        }
    }
}

#[test]
fn an_empty_or_garbage_copy_is_an_error_not_a_panic() {
    assert!(MftMirr::from_bytes(Vec::new()).is_err());
    assert!(MftMirr::from_bytes(vec![0x41; 4096]).is_err());
    // With a boot sector the record size is known, so garbage opens and fails per record.
    let boot =
        crate::boot::BootSector::parse(&crate::fixtures::boot_sector(512, 8, 32767, 4, -10, 1))
            .unwrap();
    let m = MftMirr::open(Box::new(BytesSource(vec![0x41; 4096])), Some(&boot)).unwrap();
    assert_eq!(m.record_count(), 4);
    assert_eq!(m.records().filter(|r| r.is_err()).count(), 4);
}

#[test]
fn a_window_of_a_volume_reads_the_mirror_at_the_boot_lcn() {
    // 8 clusters of 4 KiB; the mirror sits at LCN 4 and holds the first four records.
    let mft = mft_bytes();
    let mut media = vec![0u8; 8 * 4096];
    media[4 * 4096..4 * 4096 + 4 * RS].copy_from_slice(&mirror_of(&mft));
    let mut boot =
        crate::boot::BootSector::parse(&crate::fixtures::boot_sector(512, 8, 64, 1, -10, 1))
            .unwrap();
    boot.mftmirr_lcn = 4;
    let media: std::sync::Arc<dyn crate::source::RecordSource> =
        std::sync::Arc::new(BytesSource(media));
    let mirr = MftMirr::at_boot_lcn(media, &boot).unwrap();
    assert_eq!(mirr.record_count(), MIRRORED_RECORDS);
    let c = mirr.compare_with(&Mft::from_bytes(mft).unwrap());
    assert!(c.agrees());
    // Offsets are relative to the $MFTMirr stream, not to the volume.
    assert_eq!(c.checks[1].mirror.offset, RS as u64);
}

#[test]
fn a_file_far_larger_than_any_mirror_is_capped_and_says_so() {
    // A whole $MFT handed over as a "$MFTMirr": read the cap's worth, and report the rest.
    let one = crate::fixtures::RecordBuilder::file(0, 1)
        .std_info(FILE_TIME_2020)
        .build();
    let records = MAX_MIRROR_RECORDS + 7;
    let mut big = Vec::with_capacity(records as usize * RS);
    for _ in 0..records {
        big.extend_from_slice(&one);
    }
    let mirr = MftMirr::from_bytes(big).unwrap();
    assert_eq!(mirr.record_count(), records);
    assert_eq!(mirr.covered(), MAX_MIRROR_RECORDS);
    assert_eq!(
        mirr.anomalies,
        vec![NtfsAnomaly::MftMirrOversized {
            records,
            read: MAX_MIRROR_RECORDS,
        }]
    );
    assert_eq!(mirr.records().count(), MAX_MIRROR_RECORDS as usize);
    let c = mirr.compare_with(&Mft::from_bytes(mft_bytes()).unwrap());
    assert_eq!(c.checks.len(), MAX_MIRROR_RECORDS as usize);
}
