//! Query-string parameters shared by several routes, and their validation.

use crate::error::ApiError;
use crate::state::Clock;
use flagman_core::time::Timestamp;
use flagman_store::{Store, StoreError, TimeRange};
use serde::Serialize;

/// A named time span ("last hour") and the chart bucket size that suits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Span {
    pub label: &'static str,
    pub duration_ms: i64,
    pub bucket_ms: i64,
}

const MINUTE: i64 = 60_000;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;

/// The spans the dashboard offers. Each gives between 15 and 96 chart points.
const SPANS: [Span; 6] = [
    Span {
        label: "15m",
        duration_ms: 15 * MINUTE,
        bucket_ms: MINUTE,
    },
    Span {
        label: "1h",
        duration_ms: HOUR,
        bucket_ms: MINUTE,
    },
    Span {
        label: "6h",
        duration_ms: 6 * HOUR,
        bucket_ms: 5 * MINUTE,
    },
    Span {
        label: "24h",
        duration_ms: DAY,
        bucket_ms: 15 * MINUTE,
    },
    Span {
        label: "7d",
        duration_ms: 7 * DAY,
        bucket_ms: 2 * HOUR,
    },
    Span {
        label: "30d",
        duration_ms: 30 * DAY,
        bucket_ms: 12 * HOUR,
    },
];

pub fn parse_span(text: Option<&str>, default: &str) -> Result<Span, ApiError> {
    let wanted = text.unwrap_or(default);
    SPANS
        .iter()
        .copied()
        .find(|span| span.label == wanted)
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "range must be one of 15m, 1h, 6h, 24h, 7d, 30d (got {wanted:?})"
            ))
        })
}

impl Span {
    /// Turns "the last hour" into concrete times, using the clock.
    pub fn resolve(&self, store: &Store, clock: Clock) -> Result<TimeRange, StoreError> {
        let until = match clock {
            Clock::Live => Timestamp::now(),
            // +1 ms so the newest record is inside the half-open range.
            Clock::LatestData => store
                .latest_timestamp()?
                .unwrap_or_else(Timestamp::now)
                .plus_millis(1),
        };
        // Round up to a bucket boundary, so a range always holds whole buckets
        // (the last one is the bucket in progress).
        let step = self.bucket_ms;
        let until = Timestamp((until.millis() + step - 1).div_euclid(step) * step);
        Ok(TimeRange {
            since: until.plus_millis(-self.duration_ms),
            until,
            bucket_ms: self.bucket_ms,
        })
    }
}

/// Keeps a client-supplied `limit` within sensible bounds.
pub fn clamp_limit(limit: Option<u32>, default: u32, max: u32) -> u32 {
    limit.unwrap_or(default).clamp(1, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_spans_and_rejects_others() {
        assert_eq!(
            parse_span(Some("24h"), "1h").unwrap().bucket_ms,
            15 * MINUTE
        );
        assert_eq!(parse_span(None, "1h").unwrap().label, "1h");
        assert!(parse_span(Some("1y"), "1h").is_err());
        assert_eq!(clamp_limit(Some(100_000), 50, 500), 500);
        assert_eq!(clamp_limit(None, 50, 500), 50);
    }
}
