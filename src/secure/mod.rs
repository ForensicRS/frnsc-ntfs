//! `$Secure:$SDS`: the volume's shared security descriptors, keyed by `security_id` (the value in
//! each file's `$STANDARD_INFORMATION`).
//!
//! The stream is written in 256 KiB blocks, each followed by a mirror copy. Every entry carries its
//! own offset and a hash of its descriptor; both are checked, and the mirror is compared. A
//! mismatch is an anomaly on the entry, not a reason to drop it.

use crate::anomaly::NtfsAnomaly;

/// Size of an `$SDS` block (and of its mirror).
pub const SDS_BLOCK: u64 = 256 * 1024;
const HEADER: usize = 20;
/// Most ACEs summarised per ACL.
pub const MAX_ACES: usize = 64;

/// One access control entry (basic allow/deny/audit types; others keep their type only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: Option<String>,
}

impl Ace {
    /// `type:flags:mask:sid` summary (`A` allow, `D` deny, `U` audit, or the numeric type).
    pub fn summary(&self) -> String {
        let t = match self.ace_type {
            0 => "A".to_string(),
            1 => "D".to_string(),
            2 => "U".to_string(),
            other => other.to_string(),
        };
        format!(
            "{t}:{:#x}:{:#010x}:{}",
            self.flags,
            self.mask,
            self.sid.as_deref().unwrap_or("?")
        )
    }
}

/// A decoded `$SDS` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdsEntry {
    pub offset: u64,
    pub hash: u32,
    pub security_id: u32,
    pub control: u16,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl: Option<Vec<Ace>>,
    pub sacl_present: bool,
    pub anomalies: Vec<NtfsAnomaly>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Formats a SID at `at` (`S-R-A-S1-S2...`).
pub fn sid_at(b: &[u8], at: usize) -> Option<String> {
    let rev = *b.get(at)?;
    let count = usize::from(*b.get(at + 1)?);
    if rev != 1 || count > 15 {
        return None;
    }
    let auth = b
        .get(at + 2..at + 8)?
        .iter()
        .fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut s = format!("S-{rev}-{auth}");
    for i in 0..count {
        s.push('-');
        s.push_str(&u32_at(b, at + 8 + i * 4)?.to_string());
    }
    Some(s)
}

/// NTFS security descriptor hash: for each dword, `hash = dword + rotl(hash, 3)`.
pub fn sd_hash(sd: &[u8]) -> u32 {
    sd.as_chunks::<4>().0.iter().fold(0u32, |h, c| {
        u32::from_le_bytes([c[0], c[1], c[2], c[3]]).wrapping_add(h.rotate_left(3))
    })
}

fn parse_acl(sd: &[u8], at: usize) -> Option<Vec<Ace>> {
    let size = usize::from(u16_at(sd, at + 2)?);
    let count = usize::from(u16_at(sd, at + 4)?);
    let end = at.checked_add(size)?.min(sd.len());
    let mut out = Vec::new();
    let mut off = at + 8;
    for _ in 0..count.min(MAX_ACES) {
        if off + 8 > end {
            break;
        }
        let ace_type = sd[off];
        let flags = sd[off + 1];
        let ace_size = usize::from(u16_at(sd, off + 2)?);
        if ace_size < 8 || off + ace_size > end {
            break;
        }
        let mask = u32_at(sd, off + 4)?;
        let sid = if ace_type <= 3 {
            sid_at(&sd[..off + ace_size], off + 8)
        } else {
            None
        };
        out.push(Ace {
            ace_type,
            flags,
            mask,
            sid,
        });
        off += ace_size;
    }
    Some(out)
}

/// Decoded self-relative security descriptor.
struct Descriptor {
    control: u16,
    owner: Option<String>,
    group: Option<String>,
    dacl: Option<Vec<Ace>>,
    sacl_present: bool,
}

/// Parses a self-relative security descriptor.
fn parse_sd(sd: &[u8]) -> Option<Descriptor> {
    if sd.len() < 20 || sd[0] != 1 {
        return None;
    }
    let control = u16_at(sd, 2)?;
    let off = |at| u32_at(sd, at).map(|v| v as usize).filter(|&v| v != 0);
    let owner = off(4).and_then(|o| sid_at(sd, o));
    let group = off(8).and_then(|o| sid_at(sd, o));
    let sacl_present = off(12).is_some();
    let dacl = off(16).and_then(|o| parse_acl(sd, o));
    Some(Descriptor {
        control,
        owner,
        group,
        dacl,
        sacl_present,
    })
}

/// Owner SID of a self-relative security descriptor (a resident `$SECURITY_DESCRIPTOR` value or
/// an `$SDS` entry body).
pub fn descriptor_owner(sd: &[u8]) -> Option<String> {
    parse_sd(sd)?.owner
}

/// Parses every entry of a loose `$SDS` stream (mirror blocks are compared, not re-emitted).
/// Returns entries and the offsets of stretches that could not be parsed.
pub fn parse(stream: &[u8]) -> (Vec<SdsEntry>, Vec<u64>) {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    let len = stream.len() as u64;
    let mut pos = 0u64;
    let mut in_bad = false;
    while pos + HEADER as u64 <= len {
        // Skip mirror blocks.
        if (pos / SDS_BLOCK) % 2 == 1 {
            pos = (pos / SDS_BLOCK + 1) * SDS_BLOCK;
            continue;
        }
        let block_end = ((pos / SDS_BLOCK) + 1) * SDS_BLOCK;
        let p = pos as usize;
        let (Some(hash), Some(sid), Some(off), Some(elen)) = (
            u32_at(stream, p),
            u32_at(stream, p + 4),
            u64_at(stream, p + 8),
            u32_at(stream, p + 16),
        ) else {
            break;
        };
        let elen = elen as usize;
        if hash == 0 && sid == 0 && off == 0 && elen == 0 {
            // Zero fill: rest of this block is unused.
            in_bad = false;
            pos = block_end;
            continue;
        }
        let valid = off == pos && elen >= HEADER + 20 && pos + elen as u64 <= block_end.min(len);
        if !valid {
            if !in_bad {
                bad.push(pos);
                in_bad = true;
            }
            pos += 16;
            continue;
        }
        in_bad = false;
        let bytes = &stream[p..p + elen];
        let sd = &bytes[HEADER..];
        let mut anomalies = Vec::new();
        if sd_hash(sd) != hash {
            anomalies.push(NtfsAnomaly::SdsEntryMismatch {
                security_id: sid,
                reason: "descriptor hash does not match",
            });
        }
        let mirror = p + SDS_BLOCK as usize;
        if let Some(m) = stream.get(mirror..mirror + elen) {
            if m != bytes {
                anomalies.push(NtfsAnomaly::SdsEntryMismatch {
                    security_id: sid,
                    reason: "entry differs from its mirror copy",
                });
            }
        }
        match parse_sd(sd) {
            Some(d) => out.push(SdsEntry {
                offset: pos,
                hash,
                security_id: sid,
                control: d.control,
                owner: d.owner,
                group: d.group,
                dacl: d.dacl,
                sacl_present: d.sacl_present,
                anomalies,
            }),
            None => bad.push(pos),
        }
        pos += ((elen as u64) + 15) & !15;
    }
    (out, bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::sds::{sds_entry, security_descriptor};

    #[test]
    fn parses_entries_hash_and_mirror() {
        let sd = security_descriptor("S-1-5-21-1-2-3-1001");
        let mut stream = vec![0u8; 2 * SDS_BLOCK as usize];
        let e1 = sds_entry(256, 0, &sd);
        let e2 = sds_entry(257, 0x90, &security_descriptor("S-1-5-18"));
        stream[..e1.len()].copy_from_slice(&e1);
        stream[0x90..0x90 + e2.len()].copy_from_slice(&e2);
        let (a, b) = stream.split_at_mut(SDS_BLOCK as usize);
        b[..0x90 + e2.len()].copy_from_slice(&a[..0x90 + e2.len()]);
        // Tamper with the mirror of entry 2 only.
        b[0x90 + 30] ^= 1;
        let (entries, bad) = parse(&stream);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].owner.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert!(entries[0].anomalies.is_empty());
        assert_eq!(entries[1].security_id, 257);
        assert_eq!(entries[1].anomalies.len(), 1);
        let dacl = entries[0].dacl.as_ref().unwrap();
        assert_eq!(dacl[0].sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
    }

    #[test]
    fn garbage_never_panics() {
        let sd = security_descriptor("S-1-5-32-544");
        let mut stream = vec![0u8; 4096];
        let e = sds_entry(300, 0, &sd);
        stream[..e.len()].copy_from_slice(&e);
        for cut in 0..stream.len().min(400) {
            let _ = parse(&stream[..cut]);
        }
        let mut seed = 5u32;
        for _ in 0..500 {
            let mut m = stream.clone();
            for _ in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let i = seed as usize % 200;
                m[i] = (seed >> 8) as u8;
            }
            let _ = parse(&m);
        }
    }
}
