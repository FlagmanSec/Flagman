//! Brute force: many failed logins to one service in a short time.
//!
//! A password-guessing tool (for example Hydra against SSH) opens connection
//! after connection, each with a new source port, and each ends in failure.
//! Flagman never reads the password, only packet headers, so it cannot see
//! "wrong password". It looks at how each finished connection went instead,
//! and counts it as a failed attempt when it was:
//!
//! - **refused**: the server answered the request with a reset (nothing
//!   listens there, or a firewall rejects the guesser), or
//! - **very short**: the connection was set up, then closed (FIN or reset)
//!   within `max_attempt_secs` (30 s by default).
//!
//! A working session stays open longer (an interactive SSH login, VS Code
//! Remote, Ansible's shared connection), so it never counts. Why 30 s and not
//! less: servers slow down wrong passwords on purpose. In the lab recording
//! `lab-ssh-logins.pcap` (real OpenSSH), a connection with one wrong password
//! lasted 3.1 s, and one with wrong passwords until the server hung up (six,
//! OpenSSH's default limit) 17.8 s, while a successful login running one
//! command took 0.24 s. So duration alone cannot tell a quick successful
//! login from a failed one; it can only rule out sessions that stay open.
//!
//! By default only services inside the home network are watched: connections
//! from your devices to servers on the internet (git to GitHub, Ansible to a
//! cloud server) are not counted. Retransmissions of the same attempt have
//! the same source port and count once.

use super::attack;
use super::config::BruteForceConfig;
use super::tracker::{Evictions, Finding, Tracker, TrackerConfig};
use crate::alert::{Alert, AlertDetails, AlertKind, Severity};
use crate::flow::{FlowEnd, FlowRecord, Protocol, TcpOutcome};
use crate::ids::IdGenerator;
use crate::net::is_local;
use crate::time::Timestamp;
use std::collections::HashSet;
use std::net::IpAddr;

/// (guesser, target, service port)
type Key = (IpAddr, IpAddr, u16);

pub struct BruteForceDetector {
    tracker: Tracker<Key, u16>,
    login_ports: HashSet<u16>,
    window_secs: i64,
    max_attempt_ms: i64,
    local_targets_only: bool,
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
            max_attempt_ms: config.max_attempt_secs * 1_000,
            local_targets_only: config.local_targets_only,
        }
    }

    /// Called for every finished flow, at the moment it ends.
    pub fn on_flow_end(&mut self, flow: &FlowRecord, ids: &mut IdGenerator, out: &mut Vec<Alert>) {
        let service_port = flow.responder.port;
        let target = flow.responder.ip;
        if flow.protocol != Protocol::Tcp
            || !self.login_ports.contains(&service_port)
            || (self.local_targets_only && !is_local(target))
            || !is_failed_attempt(flow, self.max_attempt_ms)
        {
            return;
        }
        let key = (flow.initiator.ip, target, service_port);
        if let Some(finding) = self
            .tracker
            .record(key, flow.initiator.port, flow.last_seen, ids)
        {
            out.push(self.alert_from(finding));
        }
    }

    pub fn expire(&mut self, now: Timestamp, out: &mut Vec<Alert>) {
        for finding in self.tracker.expire(now) {
            out.push(self.alert_from(finding));
        }
    }

    pub fn evictions(&self) -> Evictions {
        self.tracker.evictions()
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

/// Refused, or set up and closed within `max_attempt_ms`.
fn is_failed_attempt(flow: &FlowRecord, max_attempt_ms: i64) -> bool {
    match flow.tcp_outcome {
        Some(TcpOutcome::Rejected) => true,
        Some(TcpOutcome::Established) => {
            flow.end == FlowEnd::Closed
                && flow.last_seen.millis_since(flow.first_seen) <= max_attempt_ms
        }
        _ => false,
    }
}
