//! Data run (mapping pairs) decoding: VCN ranges of a non-resident attribute to LCNs.

/// One run: `length` clusters starting at virtual cluster `vcn`, stored at `lcn` (`None` = sparse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub vcn: u64,
    pub lcn: Option<u64>,
    pub length: u64,
}

/// Decoded run list. Decoding stops at the first malformed run; `error` says why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Runlist {
    pub runs: Vec<Run>,
    /// Reason decoding stopped early, if it did.
    pub error: Option<&'static str>,
}

impl Runlist {
    /// Total clusters that are backed by storage (non-sparse).
    pub fn allocated_clusters(&self) -> u64 {
        self.runs
            .iter()
            .filter(|r| r.lcn.is_some())
            .map(|r| r.length)
            .fold(0u64, u64::saturating_add)
    }

    /// Total clusters covered, including sparse runs.
    pub fn total_clusters(&self) -> u64 {
        self.runs
            .iter()
            .map(|r| r.length)
            .fold(0u64, u64::saturating_add)
    }

    /// Finds the run containing `vcn`.
    pub fn locate(&self, vcn: u64) -> Option<&Run> {
        let idx = self
            .runs
            .partition_point(|r| r.vcn.saturating_add(r.length) <= vcn);
        self.runs.get(idx).filter(|r| r.vcn <= vcn)
    }
}

/// Decodes `bytes` starting at `starting_vcn`. With `total_clusters`, runs outside the volume stop
/// decoding. Never panics; bounded by the input length.
pub fn decode(bytes: &[u8], starting_vcn: u64, total_clusters: Option<u64>) -> Runlist {
    let mut out = Runlist::default();
    let mut pos = 0usize;
    let mut vcn = starting_vcn;
    let mut lcn: i64 = 0;
    loop {
        let Some(&header) = bytes.get(pos) else {
            out.error = Some("run list not terminated");
            break;
        };
        if header == 0 {
            break;
        }
        let len_size = usize::from(header & 0x0F);
        let off_size = usize::from(header >> 4);
        if len_size == 0 || len_size > 8 || off_size > 8 {
            out.error = Some("run header field size out of range");
            break;
        }
        let Some(len_bytes) = bytes.get(pos + 1..pos + 1 + len_size) else {
            out.error = Some("run length truncated");
            break;
        };
        let length = le_unsigned(len_bytes);
        if length == 0 || length > i64::MAX as u64 {
            out.error = Some("run length zero or out of range");
            break;
        }
        let run_lcn = if off_size == 0 {
            None
        } else {
            let Some(off_bytes) = bytes.get(pos + 1 + len_size..pos + 1 + len_size + off_size)
            else {
                out.error = Some("run offset truncated");
                break;
            };
            let Some(next) = lcn.checked_add(le_signed(off_bytes)) else {
                out.error = Some("run offset overflow");
                break;
            };
            if next < 0 {
                out.error = Some("run starts before cluster 0");
                break;
            }
            lcn = next;
            let start = next as u64;
            if let Some(total) = total_clusters {
                if start.checked_add(length).is_none_or(|end| end > total) {
                    out.error = Some("run extends past the end of the volume");
                    break;
                }
            }
            Some(start)
        };
        out.runs.push(Run {
            vcn,
            lcn: run_lcn,
            length,
        });
        let Some(next_vcn) = vcn.checked_add(length) else {
            out.error = Some("VCN overflow");
            break;
        };
        vcn = next_vcn;
        pos += 1 + len_size + off_size;
    }
    out
}

fn le_unsigned(b: &[u8]) -> u64 {
    b.iter()
        .rev()
        .fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
}

fn le_signed(b: &[u8]) -> i64 {
    let mut v = le_unsigned(b) as i64;
    let bits = b.len() * 8;
    if bits < 64 && b.last().is_some_and(|&x| x & 0x80 != 0) {
        v -= 1i64 << bits;
    }
    v
}

/// Encodes runs (fixture builder helper). `lcn: None` is a sparse run.
/// LCN deltas restart at 0 in every segment, so a segment's starting VCN does not change it.
pub fn encode(runs: &[(u64, Option<u64>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev: i64 = 0;
    for &(length, lcn) in runs {
        let len_bytes = min_unsigned(length);
        let off_bytes = match lcn {
            Some(l) => {
                let delta = l as i64 - prev;
                prev = l as i64;
                min_signed(delta)
            }
            None => Vec::new(),
        };
        out.push(((off_bytes.len() as u8) << 4) | len_bytes.len() as u8);
        out.extend(len_bytes);
        out.extend(off_bytes);
    }
    out.push(0);
    out
}

fn min_unsigned(v: u64) -> Vec<u8> {
    let mut b = v.to_le_bytes().to_vec();
    while b.len() > 1 && b[b.len() - 1] == 0 {
        b.pop();
    }
    b
}

fn min_signed(v: i64) -> Vec<u8> {
    let mut b = v.to_le_bytes().to_vec();
    while b.len() > 1 {
        let last = b[b.len() - 1];
        let prev_hi = b[b.len() - 2] & 0x80;
        if (last == 0 && prev_hi == 0) || (last == 0xFF && prev_hi != 0) {
            b.pop();
        } else {
            break;
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_example() {
        // 0x21 0x18 0x34 0x56: 0x18 clusters at LCN 0x5634.
        let rl = decode(&[0x21, 0x18, 0x34, 0x56, 0x00], 0, None);
        assert_eq!(
            rl.runs,
            vec![Run {
                vcn: 0,
                lcn: Some(0x5634),
                length: 0x18
            }]
        );
        assert!(rl.error.is_none());
    }

    #[test]
    fn negative_delta_and_sparse() {
        let bytes = encode(&[
            (16, Some(1000)),
            (16, None),
            (8, Some(200)),
            (4, Some(5000)),
        ]);
        let rl = decode(&bytes, 0, Some(10_000));
        assert!(rl.error.is_none(), "{:?}", rl.error);
        assert_eq!(
            rl.runs
                .iter()
                .map(|r| (r.vcn, r.lcn, r.length))
                .collect::<Vec<_>>(),
            vec![
                (0, Some(1000), 16),
                (16, None, 16),
                (32, Some(200), 8),
                (40, Some(5000), 4)
            ]
        );
        assert_eq!(rl.allocated_clusters(), 28);
        assert_eq!(rl.locate(20).unwrap().lcn, None);
        assert_eq!(rl.locate(43).unwrap().lcn, Some(5000));
        assert!(rl.locate(44).is_none());
    }

    #[test]
    fn out_of_volume_and_garbage() {
        let bytes = encode(&[(16, Some(1000))]);
        assert!(decode(&bytes, 0, Some(1010)).error.is_some());
        assert!(decode(&[0x21, 0x18], 0, None).error.is_some());
        assert!(decode(&[0x0F], 0, None).error.is_some());
        assert!(decode(&[0x11, 0x01, 0x80, 0x00], 0, None).error.is_some()); // LCN -128
        let mut seed = 0x1234_5678u32;
        for _ in 0..5000 {
            let len = (seed % 40) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            let _ = decode(&buf, 0, Some(1 << 20));
        }
    }
}
