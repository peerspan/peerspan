//! The host's notion of "now".
//!
//! Every wall-clock decision (leases and their renewal, invite, request and
//! join-stage windows, policy and group leases, call deadlines, capability
//! idle stop) reads the time here. Debug builds add a test offset so suites can
//! jump hours or days in seconds (DEC-OWN9):
//!
//! - `PEERSPAN_TEST_CLOCK_OFFSET`: a signed duration fixed for the process.
//! - `PEERSPAN_TEST_CLOCK_OFFSET_FILE`: a file holding a signed duration,
//!   re-read on every clock read, so a suite advances running daemons and CLI
//!   processes together by rewriting it. A missing file counts as zero.
//!
//! The two add up. A duration is an optional sign followed by one or more
//! `<digits><unit>` groups, unit `s`, `m`, `h` or `d` (`+3d`, `-2h`, `1d12h`,
//! `0s`). Release builds compile all of this out and ignore both variables.

use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};

/// The current UTC time, including the debug-build test offset.
pub fn now() -> DateTime<Utc> {
    Utc::now() + offset()
}

/// A monotonic instant shifted by the same test offset, for timers measured
/// with `Instant` (capability idle stop).
pub fn instant() -> Instant {
    let base = Instant::now();
    let shift = offset();
    match shift.to_std() {
        Ok(ahead) => base.checked_add(ahead).unwrap_or(base),
        Err(_) => (-shift)
            .to_std()
            .ok()
            .and_then(|behind| base.checked_sub(behind))
            .unwrap_or(base),
    }
}

#[cfg(not(debug_assertions))]
fn offset() -> TimeDelta {
    TimeDelta::zero()
}

#[cfg(debug_assertions)]
fn offset() -> TimeDelta {
    static FIXED: std::sync::OnceLock<TimeDelta> = std::sync::OnceLock::new();
    let fixed = *FIXED.get_or_init(|| match std::env::var("PEERSPAN_TEST_CLOCK_OFFSET") {
        Ok(value) => parse_offset(&value)
            .unwrap_or_else(|| panic!("invalid PEERSPAN_TEST_CLOCK_OFFSET {value:?}")),
        Err(_) => TimeDelta::zero(),
    });
    let Some(path) = std::env::var_os("PEERSPAN_TEST_CLOCK_OFFSET_FILE") else {
        return fixed;
    };
    let from_file = match std::fs::read_to_string(&path) {
        Ok(value) => parse_offset(value.trim())
            .unwrap_or_else(|| panic!("invalid PEERSPAN_TEST_CLOCK_OFFSET_FILE content {value:?}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => TimeDelta::zero(),
        Err(e) => panic!("unreadable PEERSPAN_TEST_CLOCK_OFFSET_FILE: {e}"),
    };
    fixed
        .checked_add(&from_file)
        .expect("test clock offset overflow")
}

/// Parses a signed duration such as `+3d`, `-2h` or `1d12h`.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
fn parse_offset(value: &str) -> Option<TimeDelta> {
    let (negative, mut rest) = match value.as_bytes().first()? {
        b'+' => (false, &value[1..]),
        b'-' => (true, &value[1..]),
        _ => (false, value),
    };
    if rest.is_empty() {
        return None;
    }
    let mut seconds: i64 = 0;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let amount: i64 = rest[..digits].parse().ok()?;
        let unit = match rest.as_bytes().get(digits)? {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            b'd' => 86400,
            _ => return None,
        };
        seconds = seconds.checked_add(amount.checked_mul(unit)?)?;
        rest = &rest[digits + 1..];
    }
    TimeDelta::try_seconds(if negative { -seconds } else { seconds })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_signed_durations() {
        assert_eq!(parse_offset("+3d"), Some(TimeDelta::days(3)));
        assert_eq!(parse_offset("-2h"), Some(TimeDelta::hours(-2)));
        assert_eq!(parse_offset("90s"), Some(TimeDelta::seconds(90)));
        assert_eq!(parse_offset("10m"), Some(TimeDelta::minutes(10)));
        assert_eq!(
            parse_offset("-1d12h"),
            Some(-(TimeDelta::days(1) + TimeDelta::hours(12)))
        );
        assert_eq!(parse_offset("0s"), Some(TimeDelta::zero()));
        for bad in ["", "+", "3", "d", "3w", "+-3d", "3d ", " 3d", "1.5h", "3dd"] {
            assert_eq!(parse_offset(bad), None, "{bad:?}");
        }
        assert_eq!(parse_offset("99999999999999999999d"), None);
    }
}
