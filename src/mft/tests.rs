use super::*;
use crate::fixtures::{times, MftBuilder, RecordBuilder, DAY, FILE_TIME_2020 as T};

fn mft(b: &MftBuilder) -> Mft {
    Mft::from_bytes(b.build()).unwrap()
}

fn path(m: &Mft, entry: u64) -> ResolvedPath {
    m.path_of(&m.entry(entry).unwrap().unwrap())
}

#[test]
fn resolves_nested_paths() {
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
            .directory()
            .std_info(T)
            .file_name(40, 1, "bob", T)
            .build(),
    );
    b.put(
        42,
        RecordBuilder::file(42, 3)
            .std_info(T)
            .file_name(41, 1, "notes.txt", T)
            .resident_data("", b"secret")
            .build(),
    );
    let m = mft(&b);
    assert_eq!(m.record_size(), 1024);
    let p = path(&m, 42);
    assert_eq!(p.path, "\\Users\\bob\\notes.txt");
    assert_eq!(p.status, PathStatus::Resolved);
    assert_eq!(path(&m, 5).path, "\\");
    assert_eq!(path(&m, 0).path, "\\$MFT");
    let e = m.entry(42).unwrap().unwrap();
    assert_eq!(e.resident_data(""), Some(&b"secret"[..]));
}

#[test]
fn deleted_file_in_deleted_directory() {
    let mut b = MftBuilder::new();
    // Directory 40 was sequence 1 when the file was created; freeing it bumped it to 2.
    b.put(
        40,
        RecordBuilder::file(40, 2)
            .directory()
            .deleted()
            .std_info(T)
            .file_name(5, 5, "tmp", T)
            .build(),
    );
    b.put(
        42,
        RecordBuilder::file(42, 4)
            .deleted()
            .std_info(T)
            .file_name(40, 1, "evil.ps1", T)
            .resident_data("", b"iex")
            .build(),
    );
    let m = mft(&b);
    let e = m.entry(42).unwrap().unwrap();
    assert!(!e.in_use());
    let p = m.path_of(&e);
    assert_eq!(p.path, "\\tmp\\evil.ps1");
    assert_eq!(p.status, PathStatus::ParentDeleted);
    assert!(p.anomaly.is_none());
}

#[test]
fn reused_parent_is_stale_orphan() {
    let mut b = MftBuilder::new();
    // Record 40 now holds an unrelated live directory at sequence 7.
    b.put(
        40,
        RecordBuilder::file(40, 7)
            .directory()
            .std_info(T)
            .file_name(5, 5, "other", T)
            .build(),
    );
    b.put(
        42,
        RecordBuilder::file(42, 2)
            .deleted()
            .std_info(T)
            .file_name(40, 3, "old.doc", T)
            .build(),
    );
    let m = mft(&b);
    let p = path(&m, 42);
    assert_eq!(p.path, "\\$Orphan\\old.doc");
    assert_eq!(p.status, PathStatus::StaleParent);
    assert!(matches!(
        p.anomaly,
        Some(NtfsAnomaly::ParentStale {
            found_sequence: 7,
            ..
        })
    ));
}

#[test]
fn parent_cycle_and_non_directory_parent() {
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(41, 1, "a", T)
            .build(),
    );
    b.put(
        41,
        RecordBuilder::file(41, 1)
            .directory()
            .std_info(T)
            .file_name(40, 1, "b", T)
            .build(),
    );
    b.put(
        42,
        RecordBuilder::file(42, 1)
            .std_info(T)
            .file_name(40, 1, "x", T)
            .build(),
    );
    b.put(
        43,
        RecordBuilder::file(43, 1)
            .std_info(T)
            .file_name(42, 1, "y", T)
            .build(),
    );
    let m = mft(&b);
    let p = path(&m, 42);
    assert!(p.path.starts_with("\\$Orphan"), "{}", p.path);
    assert_eq!(p.status, PathStatus::Cycle);
    let p = path(&m, 43);
    assert_eq!(p.status, PathStatus::Orphan);
    assert!(matches!(
        p.anomaly,
        Some(NtfsAnomaly::ParentNotDirectory { .. })
    ));
}

#[test]
fn hard_links_and_dos_names() {
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(5, 5, "d", T)
            .build(),
    );
    b.put(
        42,
        RecordBuilder::file(42, 1)
            .std_info(T)
            .file_name_full(FileRef::new(5, 5), "LONGFI~1.TXT", &times(T), 2)
            .file_name_full(FileRef::new(5, 5), "long file name.txt", &times(T), 1)
            .file_name_full(FileRef::new(40, 1), "link.txt", &times(T), 0)
            .build(),
    );
    let m = mft(&b);
    let e = m.entry(42).unwrap().unwrap();
    assert_eq!(e.primary_name().unwrap().name, "long file name.txt");
    assert_eq!(e.short_name().unwrap().name, "LONGFI~1.TXT");
    let paths: Vec<String> = m.paths_of(&e).into_iter().map(|p| p.path).collect();
    assert_eq!(paths, vec!["\\d\\link.txt", "\\long file name.txt"]);
}

#[test]
fn extension_records_merge_and_orphans_are_flagged() {
    let mut b = MftBuilder::new();
    b.put(
        42,
        RecordBuilder::file(42, 3)
            .std_info(T)
            .file_name(5, 5, "big.bin", T)
            .build(),
    );
    b.put(
        43,
        RecordBuilder::file(43, 1)
            .base(FileRef::new(42, 3))
            .resident_data("ads", b"hidden")
            .build(),
    );
    // Extension pointing to a base that has been reused.
    b.put(
        44,
        RecordBuilder::file(44, 1)
            .base(FileRef::new(42, 1))
            .resident_data("", b"stale")
            .build(),
    );
    let m = mft(&b);
    let e = m.entry(42).unwrap().unwrap();
    assert_eq!(e.extensions, vec![FileRef::new(43, 1)]);
    assert_eq!(e.resident_data("ads"), Some(&b"hidden"[..]));
    assert!(m.entry(43).unwrap().is_none());
    let orphan = m.entry(44).unwrap().unwrap();
    assert!(orphan
        .anomalies
        .iter()
        .any(|a| matches!(a, NtfsAnomaly::ExtensionOrphan { .. })));
    let listed: Vec<u64> = m.entries().map(|e| e.unwrap().reference.entry).collect();
    assert_eq!(listed, vec![0, 5, 11, 42, 44]);
}

#[test]
fn timestomp_rule_fires_only_when_si_predates_fn() {
    let mut b = MftBuilder::new();
    let stomped = times(T - 400 * DAY);
    b.put(
        42,
        RecordBuilder::file(42, 1)
            .std_info_times(&stomped, 0x20, 0)
            .file_name(5, 5, "a.exe", T)
            .build(),
    );
    b.put(
        43,
        RecordBuilder::file(43, 1)
            .std_info_times(&times(T + DAY), 0x20, 0)
            .file_name(5, 5, "b.exe", T)
            .build(),
    );
    let m = mft(&b);
    let (a, _) = timestomp::check(&m.entry(42).unwrap().unwrap(), m.index().volume_created);
    // Every $SI time backdated, the change time included.
    assert!(matches!(
        a.as_slice(),
        [NtfsAnomaly::SiCreatedBeforeFnCreated {
            second_sign: "si_changed_before_fn_created",
            ..
        }]
    ));
    let (a, _) = timestomp::check(&m.entry(43).unwrap().unwrap(), m.index().volume_created);
    assert!(a.is_empty());
}

#[test]
fn si_before_fn_alone_is_an_indicator_and_a_second_sign_makes_it_an_anomaly() {
    use crate::anomaly::NtfsIndicator;
    use crate::time::NtfsTimes;
    let mut b = MftBuilder::new();
    // Installed file: original $SI created/modified (with sub-second ticks), but the change time
    // moved on at install, after the $FN creation.
    let installed = NtfsTimes {
        created: T - 400 * DAY + 1_234_567,
        modified: T - 400 * DAY + 1_234_567,
        mft_modified: T + 7_654_321,
        accessed: T + 7_654_321,
    };
    b.put(
        42,
        RecordBuilder::file(42, 1)
            .std_info_times(&installed, 0x20, 0)
            .file_name(5, 5, "installed.dll", T + 1_111)
            .build(),
    );
    // Only created/modified backdated, but to whole seconds while $FN has ticks.
    let whole = NtfsTimes {
        created: T - 400 * DAY,
        modified: T - 400 * DAY,
        mft_modified: T + DAY,
        accessed: T + DAY,
    };
    b.put(
        43,
        RecordBuilder::file(43, 1)
            .std_info_times(&whole, 0x20, 0)
            .file_name(5, 5, "stomped.exe", T + 1_111)
            .build(),
    );
    let m = mft(&b);
    let (a, i) = timestomp::check(&m.entry(42).unwrap().unwrap(), m.index().volume_created);
    assert!(a.is_empty(), "{a:?}");
    assert!(i.contains(&NtfsIndicator::SiCreatedBeforeFn), "{i:?}");
    // Older than the volume, like any file deployed from an image: still only an indicator.
    assert!(i.contains(&NtfsIndicator::SiCreatedBeforeVolume), "{i:?}");
    let (a, _) = timestomp::check(&m.entry(43).unwrap().unwrap(), m.index().volume_created);
    assert!(
        matches!(
            a.as_slice(),
            [NtfsAnomaly::SiCreatedBeforeFnCreated {
                second_sign: "si_whole_seconds",
                ..
            }]
        ),
        "{a:?}"
    );
}

#[test]
fn corrupt_record_is_one_error_and_iteration_continues() {
    let mut b = MftBuilder::new();
    b.put(42, vec![0x41; 1024]);
    b.put(
        43,
        RecordBuilder::file(43, 1)
            .std_info(T)
            .file_name(5, 5, "ok.txt", T)
            .build(),
    );
    let m = mft(&b);
    let items: Vec<_> = m.entries().collect();
    assert_eq!(items.iter().filter(|r| r.is_err()).count(), 1);
    assert!(items
        .iter()
        .any(|r| matches!(r, Ok(e) if e.reference.entry == 43)));
    assert_eq!(m.index().invalid, 1);
}

#[test]
fn record_size_inference_and_truncation() {
    let mut b = MftBuilder::new();
    b.put(
        42,
        RecordBuilder::file(42, 1)
            .std_info(T)
            .file_name(5, 5, "x", T)
            .build(),
    );
    let mut bytes = b.build();
    bytes.truncate(bytes.len() - 100);
    let m = Mft::from_bytes(bytes).unwrap();
    assert!(matches!(
        m.anomalies.as_slice(),
        [NtfsAnomaly::MftFileSizeMismatch { .. }]
    ));
    assert!(Mft::from_bytes(vec![0u8; 4096]).is_err());
    let big = RecordBuilder::file(0, 1).size(4096).std_info(T).build();
    let m = Mft::from_bytes(big).unwrap();
    assert_eq!(m.record_size(), 4096);
}

#[test]
fn garbage_mft_never_panics() {
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
        42,
        RecordBuilder::file(42, 1)
            .std_info(T)
            .file_name(40, 1, "x", T)
            .resident_data("", b"abc")
            .build(),
    );
    let clean = b.build();
    let mut seed = 0xDEAD_BEEFu32;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for _ in 0..300 {
        let mut m = clean.clone();
        for _ in 0..32 {
            let i = rnd() as usize % m.len();
            m[i] = rnd() as u8;
        }
        if let Ok(mft) = Mft::from_bytes(m) {
            for e in mft.entries().flatten() {
                let _ = mft.paths_of(&e);
                let _ = timestomp::check(&e, None);
            }
        }
    }
    for cut in (0..clean.len()).step_by(97) {
        if let Ok(mft) = Mft::from_bytes(clean[..cut].to_vec()) {
            let _ = mft.entries().count();
        }
    }
}
