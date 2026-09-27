use super::*;
use crate::fixtures::indx::{index_entry, indx_record};
use crate::fixtures::{file_name_value_times, times, FILE_TIME_2020 as T};

fn key(parent: FileRef, name: &str) -> Vec<u8> {
    file_name_value_times(parent, name, &times(T), 1, 4096, 100)
}

const DIR: FileRef = FileRef::new(40, 3);

fn sample() -> Vec<u8> {
    let live = vec![
        index_entry(FileRef::new(60, 1), &key(DIR, "a.txt")),
        index_entry(FileRef::new(61, 1), &key(DIR, "b.txt")),
    ];
    // The deleted entry's bytes survive after the used length...
    let mut slack = index_entry(FileRef::new(62, 4), &key(DIR, "mimikatz.exe"));
    // ...next to an entry from another directory (moved there by a B-tree split) and noise.
    slack.extend(index_entry(
        FileRef::new(63, 1),
        &key(FileRef::new(77, 1), "elsewhere.txt"),
    ));
    slack.extend([0xFFu8; 40]);
    let mut stream = indx_record(0, &live, &slack, 4096);
    stream.extend(vec![0u8; 4096]);
    stream.extend(indx_record(
        2,
        &[index_entry(FileRef::new(64, 1), &key(DIR, "c.txt"))],
        &[],
        4096,
    ));
    stream
}

#[test]
fn parses_live_entries_and_directory() {
    let ia = IndexAllocation::parse(&sample()).unwrap();
    assert_eq!(ia.record_size, 4096);
    assert_eq!(ia.nodes.len(), 2);
    assert_eq!(ia.nodes[1].stream_offset, 8192);
    let names: Vec<&str> = ia
        .nodes
        .iter()
        .flat_map(|n| n.entries.iter().map(|e| e.key.name.as_str()))
        .collect();
    assert_eq!(names, vec!["a.txt", "b.txt", "c.txt"]);
    assert_eq!(ia.directory(), Some(DIR));
}

#[test]
fn slack_gate_keeps_only_this_directory() {
    let ia = IndexAllocation::parse(&sample()).unwrap();
    let mut stats = RecoveryStats::default();
    let found: Vec<_> = ia
        .nodes
        .iter()
        .flat_map(|n| n.carve_slack(DIR, 0xA0, &mut stats))
        .collect();
    assert_eq!(found.len(), 1);
    let e = found[0].value();
    assert_eq!(e.key.name, "mimikatz.exe");
    assert_eq!(e.reference, FileRef::new(62, 4));
    assert_eq!(found[0].recovery(), Recovery::Slack);
    assert_eq!(stats.admitted, 1);
    assert_eq!(stats.rejected, 1);
}

#[test]
fn torn_indx_is_flagged_and_garbage_is_safe() {
    let mut s = sample();
    s[4095] ^= 0xFF;
    let ia = IndexAllocation::parse(&s).unwrap();
    assert!(ia.nodes[0]
        .anomalies
        .iter()
        .any(|a| matches!(a, NtfsAnomaly::IndxFixupMismatch { .. })));
    let clean = sample();
    for cut in (0..clean.len()).step_by(61) {
        if let Ok(ia) = IndexAllocation::parse(&clean[..cut]) {
            let mut st = RecoveryStats::default();
            for n in &ia.nodes {
                let _ = n.carve_slack(DIR, 0xA0, &mut st);
            }
        }
    }
    let mut seed = 7u32;
    for _ in 0..300 {
        let mut m = clean.clone();
        for _ in 0..24 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let i = seed as usize % m.len();
            m[i] = (seed >> 8) as u8;
        }
        if let Ok(ia) = IndexAllocation::parse(&m) {
            let mut st = RecoveryStats::default();
            for n in &ia.nodes {
                let _ = n.carve_slack(DIR, 0xA0, &mut st);
            }
        }
    }
}

#[test]
fn index_root_node() {
    // $INDEX_ROOT value: 16-byte root header + node header + entries.
    let e = index_entry(FileRef::new(60, 1), &key(DIR, "root.txt"));
    let last = crate::fixtures::indx::last_entry();
    let mut v = vec![0u8; 32];
    v[0..4].copy_from_slice(&0x30u32.to_le_bytes());
    let used = 16 + e.len() + last.len();
    v[16..20].copy_from_slice(&16u32.to_le_bytes());
    v[20..24].copy_from_slice(&(used as u32).to_le_bytes());
    v[24..28].copy_from_slice(&((used + 200) as u32).to_le_bytes());
    v.extend(&e);
    v.extend(&last);
    v.extend(index_entry(FileRef::new(61, 2), &key(DIR, "gone.txt")));
    v.resize(16 + used + 200, 0);
    let node = IndexNode::parse_root(&v).unwrap();
    assert_eq!(node.entries.len(), 1);
    let mut st = RecoveryStats::default();
    let carved = node.carve_slack(DIR, 0x90, &mut st);
    assert_eq!(carved.len(), 1);
    assert_eq!(carved[0].value().key.name, "gone.txt");
}
