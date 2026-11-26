//! A sliding time window that counts distinct values.
//!
//! Example: "how many different ports did 192.168.1.50 try on 192.168.1.10
//! during the last 60 seconds?" Each attempt is added with its time; attempts
//! older than the window fall out automatically.

use crate::time::Timestamp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

pub struct DistinctWindow<T> {
    window_ms: i64,
    /// Hard cap on stored events, so a flood cannot use unbounded memory.
    max_events: usize,
    /// Events in arrival order, oldest at the front.
    events: VecDeque<(Timestamp, T)>,
    /// How many times each value appears in `events`.
    occurrences: HashMap<T, u32>,
}

impl<T: Copy + Eq + Hash> DistinctWindow<T> {
    pub fn new(window_ms: i64, max_events: usize) -> DistinctWindow<T> {
        DistinctWindow {
            window_ms,
            max_events,
            events: VecDeque::new(),
            occurrences: HashMap::new(),
        }
    }

    /// Adds one event and drops events that are now outside the window.
    pub fn add(&mut self, ts: Timestamp, value: T) {
        self.events.push_back((ts, value));
        *self.occurrences.entry(value).or_insert(0) += 1;
        if self.events.len() > self.max_events {
            self.pop_oldest();
        }
        self.evict_older_than_window(ts);
    }

    /// Drops events older than `now - window`.
    pub fn evict_older_than_window(&mut self, now: Timestamp) {
        while let Some(&(ts, _)) = self.events.front() {
            if now.millis_since(ts) <= self.window_ms {
                break;
            }
            self.pop_oldest();
        }
    }

    fn pop_oldest(&mut self) {
        let Some((_, value)) = self.events.pop_front() else {
            return;
        };
        if let Some(count) = self.occurrences.get_mut(&value) {
            *count -= 1;
            if *count == 0 {
                self.occurrences.remove(&value);
            }
        }
    }

    /// Number of different values in the window.
    pub fn distinct(&self) -> usize {
        self.occurrences.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Time of the oldest event still in the window.
    pub fn oldest(&self) -> Option<Timestamp> {
        self.events.front().map(|&(ts, _)| ts)
    }

    /// The distinct values, in the order they first appear in the window.
    pub fn distinct_values(&self) -> Vec<T> {
        let mut seen = HashSet::new();
        let mut values = Vec::new();
        for &(_, value) in &self.events {
            if seen.insert(value) {
                values.push(value);
            }
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_distinct_values_inside_the_window() {
        let mut window = DistinctWindow::new(10_000, 100);
        window.add(Timestamp(0), 22u16);
        window.add(Timestamp(1_000), 22);
        window.add(Timestamp(2_000), 80);
        assert_eq!(window.distinct(), 2);
        assert_eq!(window.distinct_values(), vec![22, 80]);
    }

    #[test]
    fn forgets_events_older_than_the_window() {
        let mut window = DistinctWindow::new(10_000, 100);
        window.add(Timestamp(0), 22u16);
        window.add(Timestamp(5_000), 80);
        window.add(Timestamp(12_000), 443);
        assert_eq!(window.distinct(), 2, "port 22 is 12 s old and must be gone");
        assert_eq!(window.oldest(), Some(Timestamp(5_000)));
        window.evict_older_than_window(Timestamp(30_000));
        assert!(window.is_empty());
    }

    #[test]
    fn never_stores_more_than_the_cap() {
        let mut window = DistinctWindow::new(60_000, 3);
        for port in 0..10u16 {
            window.add(Timestamp(0), port);
        }
        assert_eq!(window.distinct(), 3);
    }
}
