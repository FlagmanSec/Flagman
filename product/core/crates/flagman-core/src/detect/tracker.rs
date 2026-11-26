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
//!
//! Memory is bounded: a tracker follows at most 50,000 keys. When it is full
//! it does not ignore newcomers (an attacker could then fill it with fake
//! addresses and scan unseen). It forgets the least active tenth of its keys
//! instead: first keys without an open finding, then those with the fewest
//! distinct values, then those quiet for longest. A real scanner, whose key
//! collects many values within seconds, is kept; fake one-packet keys go.

use super::window::DistinctWindow;
use crate::ids::IdGenerator;
use crate::time::Timestamp;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Limits that keep memory bounded even under a flood.
const MAX_KEYS: usize = 50_000;
/// When full, a tracker forgets this share of its keys at once (1/10), so
/// the cost of choosing them is paid rarely.
const EVICT_SHARE: usize = 10;
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

impl<V: Copy + Eq + Hash> KeyState<V> {
    /// How much a key matters, smallest first: keys without an open finding,
    /// then fewer distinct values, then an older last event.
    fn activity(&self) -> (bool, usize, Timestamp) {
        let last_event = self.window.newest().unwrap_or(Timestamp(i64::MIN));
        (self.finding.is_some(), self.window.distinct(), last_event)
    }
}

/// How often a tracker had to forget keys because it was full.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evictions {
    /// Keys forgotten since the start.
    pub count: u64,
    /// When it last happened.
    pub last_at: Option<Timestamp>,
}

impl Evictions {
    /// Adds up the evictions of several trackers.
    pub fn merge(self, other: Evictions) -> Evictions {
        Evictions {
            count: self.count + other.count,
            last_at: self.last_at.max(other.last_at),
        }
    }
}

pub struct Tracker<K, V> {
    config: TrackerConfig,
    states: HashMap<K, KeyState<V>>,
    capacity: usize,
    evictions: Evictions,
    /// Final snapshots of findings forgotten to make room; `expire` hands
    /// them out, so even then a finding's last growth is not lost.
    forgotten: Vec<Finding<K, V>>,
}

impl<K: Clone + Eq + Hash, V: Copy + Eq + Hash> Tracker<K, V> {
    pub fn new(config: TrackerConfig) -> Tracker<K, V> {
        Tracker::with_capacity(config, MAX_KEYS)
    }

    /// A tracker that follows at most `capacity` keys (tests use small ones).
    pub fn with_capacity(config: TrackerConfig, capacity: usize) -> Tracker<K, V> {
        Tracker {
            config,
            states: HashMap::new(),
            capacity: capacity.max(1),
            evictions: Evictions::default(),
            forgotten: Vec::new(),
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
        if !self.states.contains_key(&key) && self.states.len() >= self.capacity {
            self.make_room(ts);
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
        let mut snapshots = std::mem::take(&mut self.forgotten);
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

    pub fn evictions(&self) -> Evictions {
        self.evictions
    }

    /// Forgets the least active tenth of the keys (at least one).
    fn make_room(&mut self, now: Timestamp) {
        let count = (self.capacity / EVICT_SHARE).clamp(1, self.states.len().max(1));
        let mut ranked: Vec<((bool, usize, Timestamp), K)> = self
            .states
            .iter()
            .map(|(key, state)| (state.activity(), key.clone()))
            .collect();
        if count < ranked.len() {
            ranked.select_nth_unstable_by_key(count - 1, |(activity, _)| *activity);
            ranked.truncate(count);
        }
        for (_, key) in ranked {
            let Some(state) = self.states.remove(&key) else {
                continue;
            };
            if let Some(finding) = state.finding
                && finding.count() > finding.published_count
            {
                self.forgotten.push(finding.snapshot(&key));
            }
            self.evictions.count += 1;
            self.evictions.last_at = Some(now);
        }
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

    fn small_tracker(threshold: usize, capacity: usize) -> Tracker<u32, u16> {
        Tracker::with_capacity(
            TrackerConfig {
                window_secs: 60,
                threshold,
                finding_idle_secs: 120,
                update_every_secs: 5,
            },
            capacity,
        )
    }

    #[test]
    fn a_full_tracker_forgets_its_least_active_keys_instead_of_newcomers() {
        let mut tracker = small_tracker(20, 100);
        let mut ids = IdGenerator::starting_after(0);
        // Key 0 is busy (5 values); keys 1..=99 sent one value each.
        for value in 0..5 {
            tracker.record(0, value, Timestamp(0), &mut ids);
        }
        for key in 1..100 {
            tracker.record(key, 1, Timestamp(i64::from(key)), &mut ids);
        }
        // Full: the newcomer gets in, the 10 oldest one-value keys go.
        tracker.record(1_000, 1, Timestamp(500), &mut ids);
        assert!(tracker.contains(&1_000));
        assert!(tracker.contains(&0), "the busy key is kept");
        assert!(!tracker.contains(&1) && !tracker.contains(&10));
        assert!(tracker.contains(&11));
        assert_eq!(
            tracker.evictions(),
            Evictions {
                count: 10,
                last_at: Some(Timestamp(500))
            }
        );
    }

    #[test]
    fn a_flood_of_fake_sources_cannot_hide_a_real_scan() {
        // The attack from the review: fill the tracker with one-packet fake
        // sources, then scan. The scan must still be found.
        let mut tracker = small_tracker(20, 1_000);
        let mut ids = IdGenerator::starting_after(0);
        let mut found = None;
        for step in 0..5_000u32 {
            let ms = i64::from(step);
            tracker.record(10_000 + step, 80, Timestamp(ms), &mut ids);
            if (2_000..2_100).contains(&step) {
                // The real scanner tries one new port per step, between fakes.
                let port = u16::try_from(step - 2_000).unwrap();
                if let Some(finding) = tracker.record(1, port, Timestamp(ms), &mut ids) {
                    found = Some(finding);
                }
            }
        }
        let finding = found.expect("the scan was detected despite the flood");
        assert_eq!(finding.key, 1);
        assert!(finding.count >= 20);
        assert!(tracker.evictions().count > 3_000);
    }

    #[test]
    fn a_forgotten_finding_still_reports_its_last_growth() {
        let mut tracker = small_tracker(2, 1);
        let mut ids = IdGenerator::starting_after(0);
        tracker.record(1, 1, Timestamp(0), &mut ids);
        tracker.record(1, 2, Timestamp(1), &mut ids); // published: 2
        tracker.record(1, 3, Timestamp(2), &mut ids); // held back
        // A newcomer arrives while the tracker is full: key 1 is forgotten.
        tracker.record(2, 1, Timestamp(3), &mut ids);
        assert!(!tracker.contains(&1));
        let reported = tracker.expire(Timestamp(4));
        assert_eq!(reported.len(), 1);
        assert_eq!((reported[0].key, reported[0].count), (1, 3));
    }
}
