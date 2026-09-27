//! `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp checks.
//!
//! `$SI` times are settable from user mode (`SetFileTime`); `$FN` times are only written by the
//! kernel. A `$SI` creation time earlier than the `$FN` one is the classic timestomp sign and is
//! raised as an anomaly (with its benign explanation). Everything weaker is an indicator only:
//! ordinary copies, moves and archive extraction produce `$SI`/`$FN` differences all the time.

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
        if si.times.created != 0 && f.times.created != 0 && si.times.created < f.times.created {
            anomalies.push(NtfsAnomaly::SiCreatedBeforeFnCreated {
                si: si.times.created,
                fn_: f.times.created,
            });
        }
        if si.times.whole_seconds() && !f.times.whole_seconds() {
            indicators.push(NtfsIndicator::SiWholeSeconds);
        }
        if let Some(vol) = volume_created {
            if si.times.created != 0
                && si.times.created < vol
                && f.times.created >= vol
                && entry.reference.entry > 26
            {
                indicators.push(NtfsIndicator::SiCreatedBeforeVolume);
            }
        }
    }
    if si.times.any_implausible() || entry.names.iter().any(|n| n.times.any_implausible()) {
        indicators.push(NtfsIndicator::TimestampOutOfRange);
    }
    (anomalies, indicators)
}
