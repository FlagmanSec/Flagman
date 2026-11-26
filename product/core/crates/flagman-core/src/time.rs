//! Time as Flagman sees it: milliseconds since the Unix epoch, in UTC.
//!
//! In replay mode "now" is the timestamp of the packet being processed, so a
//! capture from last year is analysed exactly as if it were live.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A point in time, in milliseconds since 1970-01-01 00:00:00 UTC.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub const MILLIS_PER_SECOND: i64 = 1_000;
    pub const MILLIS_PER_MINUTE: i64 = 60_000;

    /// Builds a timestamp from the seconds and microseconds that libpcap reports.
    pub fn from_secs_micros(secs: i64, micros: i64) -> Timestamp {
        Timestamp(secs * Self::MILLIS_PER_SECOND + micros / 1_000)
    }

    /// The current wall-clock time.
    pub fn now() -> Timestamp {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp(elapsed.as_millis() as i64)
    }

    pub fn millis(self) -> i64 {
        self.0
    }

    pub fn plus_millis(self, millis: i64) -> Timestamp {
        Timestamp(self.0 + millis)
    }

    pub fn plus_secs(self, secs: i64) -> Timestamp {
        self.plus_millis(secs * Self::MILLIS_PER_SECOND)
    }

    /// Milliseconds from `earlier` to `self` (negative if `earlier` is later).
    pub fn millis_since(self, earlier: Timestamp) -> i64 {
        self.0 - earlier.0
    }

    /// The start of the minute that contains this timestamp.
    pub fn minute_start(self) -> Timestamp {
        Timestamp(self.0.div_euclid(Self::MILLIS_PER_MINUTE) * Self::MILLIS_PER_MINUTE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_pcap_time_and_rounds_to_minutes() {
        let ts = Timestamp::from_secs_micros(125, 500_000);
        assert_eq!(ts.millis(), 125_500);
        assert_eq!(ts.minute_start(), Timestamp(120_000));
        assert_eq!(ts.plus_secs(5).millis_since(ts), 5_000);
    }
}
