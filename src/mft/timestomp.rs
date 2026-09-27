//! `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp checks.
//!
//! `$SI` times are settable from user mode; `$FN` times are only written by the kernel. A `$SI`
//! creation time earlier than the `$FN` one is the classic timestomp sign, but on its own it is
//! only an indicator: installers and image deployment keep the original `$SI` times, and on a real
//! Windows Server 2008 R2 volume that was 94% of the `$MFT`. It becomes an anomaly when a second
//! sign agrees:
//! - the `$SI` MFT-changed time is also before `$FN` created: every `$SI` time was backdated, which
//!   `SetFileTime` (what installers and copies use) cannot do, since the change time moves on;
//! - the `$SI` times are whole seconds while the `$FN` ones are not (many stomping tools).
//!
//! `$SI` created predating the volume is not a second sign: image deployment keeps `$SI` times
//! from before the volume was formatted, which is the very noise this rule avoids.
//!
//! Everything weaker stays an indicator: ordinary copies, moves and archive extraction produce
//! `$SI`/`$FN` differences all the time.

use crate::anomaly::{NtfsAnomaly, NtfsIndicator};
use crate::mft::entry::MftEntry;

/// Runs the checks for one entry.
pub fn check(
    entry: &MftEntry,
    volume_created: Option<u64>,
) -> (Vec<NtfsAnomaly>, Vec<NtfsIndicator>) {
    let mut anomalies = Vec::new();
    let mut indicators = Vec::new();
    let Some(si) = entry.std_info.as_ref() else {
        return (anomalies, indicators);
    };
    let fname = entry.primary_name();
    if let Some(f) = fname {
        let whole_seconds = si.times.whole_seconds() && !f.times.whole_seconds();
        let before_volume = volume_created.is_some_and(|vol| {
            si.times.created != 0
                && si.times.created < vol
                && f.times.created >= vol
                && entry.reference.entry > 26
        });
        if si.times.created != 0 && f.times.created != 0 && si.times.created < f.times.created {
            let changed_backdated =
                si.times.mft_modified != 0 && si.times.mft_modified < f.times.created;
            let second_sign = if changed_backdated {
                Some("si_changed_before_fn_created")
            } else if whole_seconds {
                Some("si_whole_seconds")
            } else {
                None
            };
            match second_sign {
                Some(second_sign) => anomalies.push(NtfsAnomaly::SiCreatedBeforeFnCreated {
                    si: si.times.created,
                    fn_: f.times.created,
                    second_sign,
                }),
                None => indicators.push(NtfsIndicator::SiCreatedBeforeFn),
            }
        }
        if whole_seconds {
            indicators.push(NtfsIndicator::SiWholeSeconds);
        }
        if before_volume {
            indicators.push(NtfsIndicator::SiCreatedBeforeVolume);
        }
    }
    if si.times.any_implausible() || entry.names.iter().any(|n| n.times.any_implausible()) {
        indicators.push(NtfsIndicator::TimestampOutOfRange);
    }
    (anomalies, indicators)
}
