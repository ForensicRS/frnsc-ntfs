use super::*;
use crate::fixtures::usn::{usn_v2, usn_v3};
use crate::fixtures::FILE_TIME_2020 as T;
use crate::source::BytesSource;

fn journal() -> Vec<u8> {
    // Sparse prefix, then records, page padding, a damaged stretch, more records.
    let mut j = vec![0u8; 3 * 4096];
    j.extend(usn_v2(
        FileRef::new(60, 1),
        FileRef::new(40, 1),
        0x3000,
        T,
        0x100,
        "a.txt",
    ));
    j.extend(usn_v3(
        FileRef::new(61, 2),
        FileRef::new(40, 1),
        0x3050,
        T + 1,
        0x8000_0200,
        "b.txt",
    ));
    j.resize(4 * 4096, 0);
    j.extend([0xAB; 24]);
    j.extend(usn_v2(
        FileRef::new(62, 1),
        FileRef::new(5, 5),
        0x4000,
        T + 2,
        0x2000,
        "c.txt",
    ));
    j
}

#[test]
fn reads_records_and_reports_damage_once() {
    let src = BytesSource(journal());
    let items: Vec<_> = UsnReader::new(&src).collect();
    let ok: Vec<&UsnRecord> = items.iter().filter_map(|r| r.as_ref().ok()).collect();
    let errs = items.iter().filter(|r| r.is_err()).count();
    assert_eq!(errs, 1, "{items:?}");
    assert_eq!(ok.len(), 3);
    assert_eq!(ok[0].name.as_deref(), Some("a.txt"));
    assert_eq!(ok[0].offset, 3 * 4096);
    assert_eq!(ok[1].major, 3);
    assert_eq!(ok[1].file_reference, FileRef::new(61, 2));
    assert_eq!(reason_names(ok[1].reason), vec!["file_delete", "close"]);
    assert_eq!(ok[2].usn, 0x4000);
}

#[test]
fn garbage_and_truncation_never_panic() {
    let clean = journal();
    for cut in (0..clean.len()).step_by(13) {
        let src = BytesSource(clean[..cut].to_vec());
        let _ = UsnReader::new(&src).count();
    }
    let mut seed = 99u32;
    for _ in 0..200 {
        let mut m = clean.clone();
        for _ in 0..40 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let i = seed as usize % m.len();
            m[i] = (seed >> 8) as u8;
        }
        let src = BytesSource(m);
        let _ = UsnReader::new(&src).count();
    }
}
