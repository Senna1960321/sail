//! RFC 3339 times, in UTC, as Mihomo's API and sail's write them.

use std::time::SystemTime;

use time::format_description::well_known::Rfc3339;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

const SECONDS: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
const MILLIS: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

fn format(at: OffsetDateTime, format: &[FormatItem<'static>]) -> String {
    at.to_offset(UtcOffset::UTC)
        .format(format)
        .expect("a UTC time in time's range formats")
}

/// `2025-11-19T03:04:05Z`: whole seconds, any fraction cut off.
pub fn seconds(at: SystemTime) -> String {
    format(OffsetDateTime::from(at), SECONDS)
}

/// `2025-11-19T03:04:05.123Z`: always three fraction digits.
pub fn millis(at: SystemTime) -> String {
    format(OffsetDateTime::from(at), MILLIS)
}

/// Seconds since the epoch as `seconds` writes them; None out of range.
pub fn seconds_from_unix(secs: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .map(|at| format(at, SECONDS))
}

/// Milliseconds since the epoch as `millis` writes them; None out of
/// range (past the year 9999).
pub fn millis_from_unix(millis: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .ok()
        .map(|at| format(at, MILLIS))
}

/// An RFC 3339 time, with `Z` or an offset, as the time it names.
pub fn parse(at: &str) -> Result<SystemTime, time::error::Parse> {
    OffsetDateTime::parse(at, &Rfc3339).map(SystemTime::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    // What the API wrote with chrono's to_rfc3339_opts(Secs | Millis, true):
    // the shapes Mihomo clients read must not change.
    #[test]
    fn formats_as_before() {
        let at = UNIX_EPOCH + Duration::from_millis(1_763_521_445_123);
        assert_eq!(seconds(at), "2025-11-19T03:04:05Z");
        assert_eq!(millis(at), "2025-11-19T03:04:05.123Z");
        let whole = UNIX_EPOCH + Duration::from_secs(1_763_521_445);
        assert_eq!(millis(whole), "2025-11-19T03:04:05.000Z");
        let fine = UNIX_EPOCH + Duration::from_nanos(1_763_521_445_123_999_999);
        assert_eq!(millis(fine), "2025-11-19T03:04:05.123Z", "cut, not rounded");
        assert_eq!(seconds(fine), "2025-11-19T03:04:05Z");
        assert_eq!(seconds(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            seconds_from_unix(1_763_521_445).as_deref(),
            Some("2025-11-19T03:04:05Z")
        );
        assert_eq!(
            millis_from_unix(1_763_521_445_123).as_deref(),
            Some("2025-11-19T03:04:05.123Z")
        );
        assert_eq!(millis_from_unix(i64::MAX), None);
    }

    #[test]
    fn parses_z_and_offsets_as_the_same_time() {
        let z = parse("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(z, UNIX_EPOCH + Duration::from_secs(1_767_225_600));
        assert_eq!(parse("2026-01-01T08:00:00+08:00").unwrap(), z);
        assert_eq!(parse("2025-12-31T19:00:00-05:00").unwrap(), z);
        assert_eq!(
            parse("2026-01-01T00:00:00.250Z").unwrap(),
            z + Duration::from_millis(250)
        );
        for bad in [
            "",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "2026-13-01T00:00:00Z",
            "2026-01-01T25:00:00Z",
            "2026-01-01 00:00:00 +0800",
            "tomorrow",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
