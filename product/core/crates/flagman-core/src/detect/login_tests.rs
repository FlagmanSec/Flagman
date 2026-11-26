//! Tests of the login attempts (brute force) detector, through [`Detectors`]:
//! which finished connections count as failed logins, and which never do.

use super::*;
use crate::alert::{AlertDetails, AlertKind, Severity};
use crate::flow::{Endpoint, FlowEnd, FlowRecord, FlowStart, Protocol, StartKind, TcpOutcome};
use crate::testutil::ip;

const ATTACKER: &str = "192.168.1.66";
const VICTIM: &str = "192.168.1.10";

fn detectors() -> Detectors {
    Detectors::new(&DetectConfig::default(), IdGenerator::starting_after(0))
}

/// A finished TCP connection to `dst:dst_port`, as the flow meter reports it.
fn finished(
    start_ms: i64,
    secs: i64,
    src_port: u16,
    dst: &str,
    dst_port: u16,
    outcome: TcpOutcome,
    end: FlowEnd,
) -> FlowRecord {
    FlowRecord {
        protocol: Protocol::Tcp,
        initiator: Endpoint {
            ip: ip(ATTACKER),
            port: src_port,
        },
        responder: Endpoint {
            ip: ip(dst),
            port: dst_port,
        },
        first_seen: Timestamp(start_ms),
        last_seen: Timestamp(start_ms + secs * 1_000),
        packets_fwd: 14,
        packets_rev: 13,
        bytes_fwd: 4_000,
        bytes_rev: 3_900,
        tcp_outcome: Some(outcome),
        end,
    }
}

/// Feeds `count` connections, one every 2 s, and returns the brute force alerts.
fn connections(
    detectors: &mut Detectors,
    count: u16,
    dst: &str,
    secs: i64,
    outcome: TcpOutcome,
    end: FlowEnd,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for attempt in 0..count {
        let flow = finished(
            i64::from(attempt) * 2_000,
            secs,
            41_000 + attempt,
            dst,
            22,
            outcome,
            end,
        );
        detectors.on_flow_end(&flow, &mut alerts);
    }
    detectors.expire(Timestamp(1_000_000), &mut alerts);
    alerts.retain(|alert| alert.kind == AlertKind::BruteForce);
    alerts
}

/// Feeds 30 connections, one every 2 s, and returns the brute force alerts.
fn thirty_connections(
    detectors: &mut Detectors,
    dst: &str,
    secs: i64,
    outcome: TcpOutcome,
    end: FlowEnd,
) -> Vec<Alert> {
    connections(detectors, 30, dst, secs, outcome, end)
}

#[test]
fn wrong_passwords_are_brute_force() {
    // Each connection: set up, one wrong password, closed after 3 s.
    let alerts = thirty_connections(
        &mut detectors(),
        VICTIM,
        3,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    let first = alerts.first().expect("brute force alert");
    assert_eq!(first.dst_port, Some(22));
    assert_eq!(first.severity, Severity::High);
    assert_eq!(first.count, 10, "first published at the threshold");
    assert_eq!(alerts.last().unwrap().count, 30);
}

#[test]
fn refused_connections_are_brute_force() {
    let alerts = thirty_connections(
        &mut detectors(),
        VICTIM,
        0,
        TcpOutcome::Rejected,
        FlowEnd::Closed,
    );
    assert_eq!(alerts.last().map(|alert| alert.count), Some(30));
}

#[test]
fn a_full_round_of_six_wrong_passwords_still_counts() {
    // 17.8 s in the lab recording; the limit is 30 s.
    let alerts = thirty_connections(
        &mut detectors(),
        VICTIM,
        22,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(!alerts.is_empty());
}

#[test]
fn working_sessions_never_count() {
    // Logins that stay open (interactive SSH, VS Code Remote, Ansible's
    // shared connection) are not attempts, however many there are.
    let alerts = thirty_connections(
        &mut detectors(),
        VICTIM,
        45,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(alerts.is_empty(), "{alerts:?}");
    // Still open when the flow meter let them go: no verdict, no count.
    for end in [
        FlowEnd::Idle,
        FlowEnd::ActiveTimeout,
        FlowEnd::Evicted,
        FlowEnd::Stopped,
    ] {
        let alerts = thirty_connections(&mut detectors(), VICTIM, 3, TcpOutcome::Established, end);
        assert!(alerts.is_empty(), "{end:?}");
    }
}

#[test]
fn unanswered_and_half_open_connections_are_not_login_attempts() {
    // No login happened: the port scan detector deals with these.
    for outcome in [
        TcpOutcome::Unanswered,
        TcpOutcome::HalfOpen,
        TcpOutcome::Midstream,
    ] {
        let alerts = thirty_connections(&mut detectors(), VICTIM, 0, outcome, FlowEnd::Idle);
        assert!(alerts.is_empty(), "{outcome:?}");
    }
}

/// An address on the internet (a documentation range, RFC 5737).
const INTERNET_SERVER: &str = "203.0.113.5";

fn detectors_with(brute_force: BruteForceConfig) -> Detectors {
    let config = DetectConfig {
        brute_force,
        ..DetectConfig::default()
    };
    Detectors::new(&config, IdGenerator::starting_after(0))
}

#[test]
fn guessing_passwords_on_an_internet_server_is_reported() {
    // One of your devices tries a wrong password on an internet server every
    // 2 s, as an infected device does: 30 attempts reach the outbound limit.
    let alerts = thirty_connections(
        &mut detectors(),
        INTERNET_SERVER,
        3,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    let first = alerts.first().expect("brute force alert");
    assert_eq!(first.count, 30, "first published at the outbound limit");
    assert_eq!(
        first.details,
        AlertDetails::BruteForce {
            service_port: 22,
            window_secs: 60,
            outbound: true,
        }
    );
}

#[test]
fn quick_logins_to_an_internet_server_stay_silent() {
    // Like git over SSH to a code host: one short, successful login per
    // command. 20 commands in 40 s stay under the outbound limit (30), while
    // the same 20 against a machine at home would cross the local one (10).
    let to_the_internet = connections(
        &mut detectors(),
        20,
        INTERNET_SERVER,
        1,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(to_the_internet.is_empty());
    let at_home = connections(
        &mut detectors(),
        20,
        VICTIM,
        1,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(!at_home.is_empty());
}

#[test]
fn local_targets_only_turns_the_internet_watch_off() {
    let mut detectors = detectors_with(BruteForceConfig {
        local_targets_only: true,
        ..BruteForceConfig::default()
    });
    let alerts = connections(
        &mut detectors,
        40,
        INTERNET_SERVER,
        3,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(alerts.is_empty());
}

#[test]
fn ignore_logins_silences_one_login_and_nothing_else() {
    let mut detectors = detectors_with(BruteForceConfig {
        ignore_logins: vec![LoginException {
            source: ip(ATTACKER),
            target: ip(VICTIM),
            port: 22,
        }],
        ..BruteForceConfig::default()
    });
    // Your own script logging in to one machine again and again: silent.
    let excepted = thirty_connections(
        &mut detectors,
        VICTIM,
        1,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(excepted.is_empty());
    // The same source against another machine is still reported.
    let other_target = thirty_connections(
        &mut detectors,
        "192.168.1.11",
        1,
        TcpOutcome::Established,
        FlowEnd::Closed,
    );
    assert!(!other_target.is_empty());
    // And its scans are still seen, unlike with `ignore_sources`.
    let mut alerts = Vec::new();
    for port in 1..=100u16 {
        let syn = FlowStart {
            ts: Timestamp(200_000 + i64::from(port)),
            protocol: Protocol::Tcp,
            initiator: Endpoint {
                ip: ip(ATTACKER),
                port: 50_000,
            },
            responder: Endpoint {
                ip: ip(VICTIM),
                port,
            },
            kind: StartKind::TcpSyn,
        };
        detectors.on_flow_start(&syn, &mut alerts);
    }
    assert!(alerts.iter().any(|alert| alert.kind == AlertKind::PortScan));
}

#[test]
fn one_login_retried_is_one_attempt() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    // The same connection reported five times (same source port) counts once.
    for retry in 0..5 {
        let flow = finished(
            retry * 1_000,
            1,
            41_000,
            VICTIM,
            22,
            TcpOutcome::Rejected,
            FlowEnd::Closed,
        );
        detectors.on_flow_end(&flow, &mut alerts);
    }
    detectors.expire(Timestamp(1_000_000), &mut alerts);
    assert!(alerts.is_empty());
}
