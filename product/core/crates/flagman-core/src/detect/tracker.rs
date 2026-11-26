//! The shared logic behind every behavioural detector.
//!
//! A detector reports "key K touched value V at time T". For a port scan, K is
//! the pair (scanner, target) and V is a port. The tracker then:
//!
//! 1. counts the distinct values of each key in a sliding window;
//! 2. opens a *finding* (with a new alert id) when that count reaches the threshold;
//! 3. keeps adding values to the open finding, and says when it has grown
//!    enough to be published again;
//! 4. closes the finding once the key has been quiet for `finding_idle_secs`.

use super::window::DistinctWindow;
use crate::ids::IdGenerator;
use crate::time::Timestamp;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Limits that keep memory bounded even under a flood.
const MAX_KEYS: usize = 50_000;
const MAX_EVENTS_PER_KEY: usize = 10_000;
const MAX_VALUES_PER_FINDING: usize = 65_536;
/// How many example values (ports, hosts) an alert carries.
const SAMPLE_SIZE: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrackerConfig {
    pub window_secs: i64,
    /// Distinct values needed inside the window to open a finding.
    pub threshold: usize,
    pub finding_idle_secs: i64,
    /// Minimum time between two publications of a growing finding
    /// (a finding that doubles is published at once).
    pub update_every_secs: i64,
}

/// A snapshot of a finding, ready to be turned into an alert.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding<K, V> {
    pub key: K,
    pub alert_id: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// Distinct values seen since the finding opened (including the window
    /// that triggered it).
    pub count: u64,
    pub sample: Vec<V>,
}

struct OpenFinding<V> {
    alert_id: u64,
    first_seen: Timestamp,
    last_seen: Timestamp,
    values: HashSet<V>,
    sample: Vec<V>,
    published_count: u64,
    published_at: Timestamp,
}

impl<V: Copy + Eq + Hash> OpenFinding<V> {
    fn add(&mut self, ts: Timestamp, value: V) {
        self.last_seen = self.last_seen.max(ts);
        let has_room = self.values.len() < MAX_VALUES_PER_FINDING;
        if has_room && self.values.insert(value) && self.sample.len() < SAMPLE_SIZE {
            self.sample.push(value);
        }
    }

    fn count(&self) -> u64 {
        self.values.len() as u64
    }

    fn worth_publishing(&self, now: Timestamp, update_every_ms: i64) -> bool {
        let grown = self.count() > self.published_count;
        let doubled = self.count() >= self.published_count * 2;
        let interval_passed = now.millis_since(self.published_at) >= update_every_ms;
        grown && (doubled || interval_passed)
    }

    fn mark_published(&mut self, now: Timestamp) {
        self.published_count = self.count();
        self.published_at = now;
    }

    fn snapshot<K: Clone>(&self, key: &K) -> Finding<K, V> {
        Finding {
            key: key.clone(),
            alert_id: self.alert_id,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            count: self.count(),
            sample: self.sample.clone(),
        }
    }
}

struct KeyState<V> {
    window: DistinctWindow<V>,
    finding: Option<OpenFinding<V>>,
}

pub struct Tracker<K, V> {
    config: TrackerConfig,
    states: HashMap<K, KeyState<V>>,
}

impl<K: Clone + Eq + Hash, V: Copy + Eq + Hash> Tracker<K, V> {
    pub fn new(config: TrackerConfig) -> Tracker<K, V> {
        Tracker {
            config,
            states: HashMap::new(),
        }
    }

    /// Records one event. Returns a finding when an alert should be published:
    /// either a new finding, or an open one that has grown.
    pub fn record(
        &mut self,
        key: K,
        value: V,
        ts: Timestamp,
        ids: &mut IdGenerator,
    ) -> Option<Finding<K, V>> {
        if !self.states.contains_key(&key) && self.states.len() >= MAX_KEYS {
            return None;
        }
        let window_ms = self.config.window_secs * 1_000;
        let update_every_ms = self.config.update_every_secs * 1_000;
        let state = self.states.entry(key.clone()).or_insert_with(|| KeyState {
            window: DistinctWindow::new(window_ms, MAX_EVENTS_PER_KEY),
            finding: None,
        });
        state.window.add(ts, value);

        if let Some(finding) = state.finding.as_mut() {
            finding.add(ts, value);
            if !finding.worth_publishing(ts, update_every_ms) {
                return None;
            }
            finding.mark_published(ts);
            return Some(finding.snapshot(&key));
        }

        if state.window.distinct() < self.config.threshold {
            return None;
        }
        let mut finding = OpenFinding {
            alert_id: ids.next_id(),
            first_seen: state.window.oldest().unwrap_or(ts),
            last_seen: ts,
            values: HashSet::new(),
            sample: Vec::new(),
            published_count: 0,
            published_at: ts,
        };
        for earlier_value in state.window.distinct_values() {
            finding.add(ts, earlier_value);
        }
        finding.mark_published(ts);
        let snapshot = finding.snapshot(&key);
        state.finding = Some(finding);
        Some(snapshot)
    }

    /// Runs once a second. Closes findings that went quiet (reporting their
    /// final size if it grew), re-publishes open findings that grew since
    /// their last update, and forgets idle keys.
    pub fn expire(&mut self, now: Timestamp) -> Vec<Finding<K, V>> {
        let idle_ms = self.config.finding_idle_secs * 1_000;
        let update_every_ms = self.config.update_every_secs * 1_000;
        let mut snapshots = Vec::new();
        self.states.retain(|key, state| {
            state.window.evict_older_than_window(now);
            let quiet = state
                .finding
                .as_ref()
                .is_some_and(|finding| now.millis_since(finding.last_seen) >= idle_ms);
            if quiet {
                if let Some(finding) = state.finding.take()
                    && finding.count() > finding.published_count
                {
                    snapshots.push(finding.snapshot(key));
                }
            } else if let Some(finding) = state.finding.as_mut()
                && finding.worth_publishing(now, update_every_ms)
            {
                // The scan stopped before its next update was due: catch up,
                // so the dashboard shows the real count within seconds.
                finding.mark_published(now);
                snapshots.push(finding.snapshot(key));
            }
            !(state.window.is_empty() && state.finding.is_none())
        });
        snapshots.sort_by_key(|finding| finding.alert_id);
        snapshots
    }

    /// True while the key has events in its window or an open finding.
    pub fn contains(&self, key: &K) -> bool {
        self.states.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker(threshold: usize) -> Tracker<&'static str, u16> {
        Tracker::new(TrackerConfig {
            window_secs: 60,
            threshold,
            finding_idle_secs: 120,
            update_every_secs: 5,
        })
    }

    #[test]
    fn opens_a_finding_exactly_at_the_threshold() {
        let mut tracker = tracker(3);
        let mut ids = IdGenerator::starting_after(0);
        assert!(
            tracker
                .record("scanner", 1, Timestamp(0), &mut ids)
                .is_none()
        );
        assert!(
            tracker
                .record("scanner", 2, Timestamp(100), &mut ids)
                .is_none()
        );
        let finding = tracker
            .record("scanner", 3, Timestamp(200), &mut ids)
            .unwrap();
        assert_eq!(finding.alert_id, 1);
        assert_eq!(finding.count, 3);
        assert_eq!(finding.first_seen, Timestamp(0));
        assert_eq!(finding.sample, vec![1, 2, 3]);
    }

    #[test]
    fn a_finding_that_stops_growing_catches_up_without_waiting_to_close() {
        let mut tracker = tracker(2);
        let mut ids = IdGenerator::starting_after(0);
        tracker.record("scanner", 1, Timestamp(0), &mut ids);
        tracker.record("scanner", 2, Timestamp(10), &mut ids); // published: 2
        tracker.record("scanner", 3, Timestamp(20), &mut ids); // 3 < 4: held back
        assert!(tracker.expire(Timestamp(1_000)).is_empty(), "too soon");
        let caught_up = tracker.expire(Timestamp(5_010));
        assert_eq!(caught_up.len(), 1);
        assert_eq!(caught_up[0].count, 3);
        assert!(
            tracker.expire(Timestamp(200_000)).is_empty(),
            "nothing new to say when it closes"
        );
    }

    #[test]
    fn republishes_a_growing_finding_without_flooding() {
        let mut tracker = tracker(2);
        let mut ids = IdGenerator::starting_after(0);
        tracker.record("scanner", 1, Timestamp(0), &mut ids);
        assert!(
            tracker
                .record("scanner", 2, Timestamp(10), &mut ids)
                .is_some()
        );
        assert!(
            tracker
                .record("scanner", 3, Timestamp(20), &mut ids)
                .is_none()
        );
        // 4 values = double the 2 published: published at once, same alert id.
        let grown = tracker
            .record("scanner", 4, Timestamp(30), &mut ids)
            .unwrap();
        assert_eq!((grown.alert_id, grown.count), (1, 4));
        // After 5 s any growth is published.
        assert!(
            tracker
                .record("scanner", 5, Timestamp(5_100), &mut ids)
                .is_some()
        );
    }

    #[test]
    fn closes_a_quiet_finding_and_reports_its_final_size() {
        let mut tracker = tracker(2);
        let mut ids = IdGenerator::starting_after(0);
        tracker.record("scanner", 1, Timestamp(0), &mut ids);
        tracker.record("scanner", 2, Timestamp(10), &mut ids); // published: 2
        tracker.record("scanner", 3, Timestamp(20), &mut ids); // held back
        // First housekeeping after 120 quiet seconds: closed with its final size.
        let finals = tracker.expire(Timestamp(120_020));
        assert_eq!(finals.len(), 1);
        assert_eq!(finals[0].count, 3);
        assert!(!tracker.contains(&"scanner"));
        // New activity later is a new alert.
        tracker.record("scanner", 1, Timestamp(200_000), &mut ids);
        let again = tracker
            .record("scanner", 2, Timestamp(200_010), &mut ids)
            .unwrap();
        assert_eq!(again.alert_id, 2);
    }

    #[test]
    fn keys_are_independent() {
        let mut tracker = tracker(2);
        let mut ids = IdGenerator::starting_after(0);
        tracker.record("a", 1, Timestamp(0), &mut ids);
        assert!(tracker.record("b", 2, Timestamp(0), &mut ids).is_none());
    }
}
