//! Brute force: many new connections to a login service in a short time.
//!
//! A password-guessing tool (for example Hydra against SSH) opens connection
//! after connection, each with a new source port. A person logging in opens one.
//! We count distinct source ports, so retransmissions of the same attempt do
//! not count twice. Flagman never reads the password itself: only headers.

use super::attack;
use super::config::BruteForceConfig;
use super::tracker::{Finding, Tracker, TrackerConfig};
use crate::alert::{Alert, AlertDetails, AlertKind, Severity};
use crate::flow::{FlowStart, StartKind};
use crate::ids::IdGenerator;
use crate::time::Timestamp;
use std::collections::HashSet;
use std::net::IpAddr;

/// (guesser, target, service port)
type Key = (IpAddr, IpAddr, u16);

pub struct BruteForceDetector {
    tracker: Tracker<Key, u16>,
    login_ports: HashSet<u16>,
    window_secs: i64,
}

impl BruteForceDetector {
    pub fn new(
        config: &BruteForceConfig,
        idle_secs: i64,
        update_every_secs: i64,
    ) -> BruteForceDetector {
        BruteForceDetector {
            tracker: Tracker::new(TrackerConfig {
                window_secs: config.window_secs,
                threshold: config.min_attempts,
                finding_idle_secs: idle_secs,
                update_every_secs,
            }),
            login_ports: config.ports.iter().copied().collect(),
            window_secs: config.window_secs,
        }
    }

    pub fn on_flow_start(
        &mut self,
        start: &FlowStart,
        ids: &mut IdGenerator,
        out: &mut Vec<Alert>,
    ) {
        let service_port = start.responder.port;
        if start.kind != StartKind::TcpSyn || !self.login_ports.contains(&service_port) {
            return;
        }
        let key = (start.initiator.ip, start.responder.ip, service_port);
        if let Some(finding) = self
            .tracker
            .record(key, start.initiator.port, start.ts, ids)
        {
            out.push(self.alert_from(finding));
        }
    }

    pub fn expire(&mut self, now: Timestamp, out: &mut Vec<Alert>) {
        for finding in self.tracker.expire(now) {
            out.push(self.alert_from(finding));
        }
    }

    fn alert_from(&self, finding: Finding<Key, u16>) -> Alert {
        let (guesser, target, service_port) = finding.key;
        Alert {
            id: finding.alert_id,
            incident_id: None,
            kind: AlertKind::BruteForce,
            severity: Severity::High,
            first_seen: finding.first_seen,
            last_seen: finding.last_seen,
            src_ip: guesser,
            dst_ip: Some(target),
            dst_port: Some(service_port),
            count: finding.count,
            details: AlertDetails::BruteForce {
                service_port,
                window_secs: self.window_secs,
            },
            attack: Some(attack::brute_force()),
        }
    }
}
