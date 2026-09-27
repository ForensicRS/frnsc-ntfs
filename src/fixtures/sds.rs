//! `$SDS` entry and security descriptor builders.

use crate::secure::sd_hash;

/// Encodes a SID string like `S-1-5-21-1-2-3-1001`.
pub fn sid(s: &str) -> Vec<u8> {
    let parts: Vec<u64> = s
        .trim_start_matches("S-")
        .split('-')
        .filter_map(|p| p.parse().ok())
        .collect();
    let mut b = vec![parts[0] as u8, (parts.len() - 2) as u8];
    b.extend(&parts[1].to_be_bytes()[2..8]);
    for sub in &parts[2..] {
        b.extend((*sub as u32).to_le_bytes());
    }
    b
}

/// Self-relative descriptor: owner = group = `owner`, DACL with one allow-all ACE for `owner`.
pub fn security_descriptor(owner: &str) -> Vec<u8> {
    let o = sid(owner);
    let ace_len = 8 + o.len();
    let acl_len = 8 + ace_len;
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let owner_off = 20;
    let group_off = owner_off + o.len();
    let dacl_off = group_off + o.len();
    sd[4..8].copy_from_slice(&(owner_off as u32).to_le_bytes());
    sd[8..12].copy_from_slice(&(group_off as u32).to_le_bytes());
    sd[16..20].copy_from_slice(&(dacl_off as u32).to_le_bytes());
    sd.extend(&o);
    sd.extend(&o);
    let mut acl = vec![2u8, 0];
    acl.extend((acl_len as u16).to_le_bytes());
    acl.extend(1u16.to_le_bytes());
    acl.extend(0u16.to_le_bytes());
    acl.extend([0u8, 0]);
    acl.extend((ace_len as u16).to_le_bytes());
    acl.extend(0x001F_01FFu32.to_le_bytes());
    acl.extend(&o);
    sd.extend(acl);
    while !sd.len().is_multiple_of(4) {
        sd.push(0);
    }
    sd
}

/// An `$SDS` entry at stream offset `offset`.
pub fn sds_entry(security_id: u32, offset: u64, sd: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend(sd_hash(sd).to_le_bytes());
    e.extend(security_id.to_le_bytes());
    e.extend(offset.to_le_bytes());
    e.extend(((20 + sd.len()) as u32).to_le_bytes());
    e.extend(sd);
    e
}
