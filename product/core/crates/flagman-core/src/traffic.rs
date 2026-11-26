//! Traffic counters for the dashboard: packets and bytes per minute and per
//! protocol family. Partial counts are flushed every 5 seconds so the
//! dashboard stays current; storage adds them up per minute.

use crate::time::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficClass {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Other,
}

impl TrafficClass {
    pub const ALL: [TrafficClass; 5] = [
        TrafficClass::Tcp,
        TrafficClass::Udp,
        TrafficClass::Icmp,
        TrafficClass::Arp,
        TrafficClass::Other,
    ];

    fn index(self) -> usize {
        match self {
            TrafficClass::Tcp => 0,
            TrafficClass::Udp => 1,
            TrafficClass::Icmp => 2,
            TrafficClass::Arp => 3,
            TrafficClass::Other => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TrafficClass::Tcp => "tcp",
            TrafficClass::Udp => "udp",
            TrafficClass::Icmp => "icmp",
            TrafficClass::Arp => "arp",
            TrafficClass::Other => "other",
        }
    }
}

/// Packets and bytes of one protocol family during (part of) one minute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrafficMinute {
    pub minute: Timestamp,
    pub class: TrafficClass,
    pub packets: u64,
    pub bytes: u64,
}

const FLUSH_EVERY_MS: i64 = 5_000;

#[derive(Default)]
pub struct TrafficCounter {
    minute: Option<Timestamp>,
    last_flush: Timestamp,
    packets: [u64; 5],
    bytes: [u64; 5],
}

impl TrafficCounter {
    pub fn add(
        &mut self,
        ts: Timestamp,
        class: TrafficClass,
        bytes: u32,
        out: &mut Vec<TrafficMinute>,
    ) {
        let minute = ts.minute_start();
        match self.minute {
            Some(current) if minute > current => {
                self.flush(out);
                self.minute = Some(minute);
            }
            // Same minute, or a slightly late packet: count it in the current minute.
            Some(_) => {}
            None => {
                self.minute = Some(minute);
                self.last_flush = ts;
            }
        }
        self.packets[class.index()] += 1;
        self.bytes[class.index()] += u64::from(bytes);
    }

    /// Flushes if 5 seconds passed since the last flush, or the minute is over.
    pub fn flush_if_due(&mut self, now: Timestamp, out: &mut Vec<TrafficMinute>) {
        let Some(current) = self.minute else {
            return;
        };
        let minute_over = now >= current.plus_millis(Timestamp::MILLIS_PER_MINUTE);
        if minute_over || now.millis_since(self.last_flush) >= FLUSH_EVERY_MS {
            self.flush(out);
            self.last_flush = now;
            if minute_over {
                self.minute = None;
            }
        }
    }

    /// Emits one row per protocol family that saw traffic, then resets.
    pub fn flush(&mut self, out: &mut Vec<TrafficMinute>) {
        let Some(minute) = self.minute else {
            return;
        };
        for class in TrafficClass::ALL {
            let i = class.index();
            if self.packets[i] > 0 {
                out.push(TrafficMinute {
                    minute,
                    class,
                    packets: self.packets[i],
                    bytes: self.bytes[i],
                });
            }
        }
        self.packets = [0; 5];
        self.bytes = [0; 5];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolls_over_at_each_minute() {
        let mut counter = TrafficCounter::default();
        let mut rows = Vec::new();
        counter.add(Timestamp(1_000), TrafficClass::Tcp, 100, &mut rows);
        counter.add(Timestamp(2_000), TrafficClass::Tcp, 50, &mut rows);
        counter.add(Timestamp(3_000), TrafficClass::Arp, 42, &mut rows);
        assert!(rows.is_empty());
        counter.add(Timestamp(61_000), TrafficClass::Udp, 10, &mut rows);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].class, TrafficClass::Tcp);
        assert_eq!((rows[0].packets, rows[0].bytes), (2, 150));
        assert_eq!(rows[0].minute, Timestamp(0));
    }

    #[test]
    fn flushes_partial_counts_every_five_seconds() {
        let mut counter = TrafficCounter::default();
        let mut rows = Vec::new();
        counter.add(Timestamp(0), TrafficClass::Tcp, 100, &mut rows);
        counter.flush_if_due(Timestamp(4_000), &mut rows);
        assert!(rows.is_empty());
        counter.flush_if_due(Timestamp(5_000), &mut rows);
        assert_eq!(rows.len(), 1);
    }
}
