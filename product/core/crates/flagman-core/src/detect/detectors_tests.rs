//! Scenario tests: each one plays a small story (a scan, normal browsing...)
//! and checks which alerts come out.

use super::*;
use crate::alert::{AlertDetails, AlertKind, Severity, SweepMethod};
use crate::flow::{Endpoint, Protocol, StartKind};
use crate::packet::ArpOperation;
use crate::testutil::ip;
use std::net::Ipv4Addr;

const ATTACKER: &str = "192.168.1.66";
const VICTIM: &str = "192.168.1.10";

fn detectors() -> Detectors {
    Detectors::new(&DetectConfig::default(), IdGenerator::starting_after(0))
}

fn start(
    ms: i64,
    kind: StartKind,
    src: &str,
    src_port: u16,
    dst: &str,
    dst_port: u16,
) -> FlowStart {
    let protocol = match kind {
        StartKind::TcpSyn | StartKind::TcpMidstream => Protocol::Tcp,
        StartKind::Udp => Protocol::Udp,
        _ => Protocol::Icmp,
    };
    FlowStart {
        ts: Timestamp(ms),
        protocol,
        initiator: Endpoint {
            ip: ip(src),
            port: src_port,
        },
        responder: Endpoint {
            ip: ip(dst),
            port: dst_port,
        },
        kind,
    }
}

#[test]
fn an_nmap_syn_scan_gives_one_growing_port_scan_alert() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    for port in 1..=1_000u16 {
        let flow = start(
            i64::from(port),
            StartKind::TcpSyn,
            ATTACKER,
            55_555,
            VICTIM,
            port,
        );
        detectors.on_flow_start(&flow, &mut alerts);
    }
    detectors.expire(Timestamp(200_000), &mut alerts);

    let scans: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind == AlertKind::PortScan)
        .collect();
    assert!(!scans.is_empty());
    assert!(
        scans.iter().all(|a| a.id == scans[0].id),
        "one finding, one id"
    );
    let last = scans.last().unwrap();
    assert_eq!(last.count, 1_000);
    assert_eq!(last.src_ip, ip(ATTACKER));
    assert_eq!(last.dst_ip, Some(ip(VICTIM)));
    assert!(
        scans.len() < 20,
        "growth is throttled, got {} snapshots",
        scans.len()
    );
    let AlertDetails::PortScan {
        protocol,
        ports_sample,
        ..
    } = &last.details
    else {
        panic!("wrong details");
    };
    assert_eq!(*protocol, Protocol::Tcp);
    assert_eq!(&ports_sample[..3], &[1, 2, 3]);
}

#[test]
fn normal_browsing_raises_nothing() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    // 80 HTTPS connections to 40 public servers in one minute, plus DNS.
    for i in 0..80u16 {
        let server = format!("93.184.{}.{}", i % 40, 10);
        let ms = i64::from(i) * 700;
        detectors.on_flow_start(
            &start(ms, StartKind::TcpSyn, VICTIM, 40_000 + i, &server, 443),
            &mut alerts,
        );
        detectors.on_flow_start(
            &start(ms, StartKind::Udp, VICTIM, 50_000 + i, "192.168.1.1", 53),
            &mut alerts,
        );
    }
    detectors.expire(Timestamp(300_000), &mut alerts);
    assert!(alerts.is_empty(), "unexpected alerts: {alerts:?}");
}

#[test]
fn an_arp_sweep_of_the_subnet_is_a_host_sweep() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    for last_octet in 1..=254u8 {
        let arp = ArpPacket {
            operation: ArpOperation::Request,
            sender_mac: [2, 0, 0, 0, 0, 0x66],
            sender_ip: Ipv4Addr::new(192, 168, 1, 66),
            target_ip: Ipv4Addr::new(192, 168, 1, last_octet),
        };
        detectors.on_arp(Timestamp(i64::from(last_octet) * 10), &arp, &mut alerts);
    }
    let sweep = alerts.last().expect("a host sweep alert");
    assert_eq!(sweep.kind, AlertKind::HostSweep);
    assert_eq!(sweep.src_ip, ip(ATTACKER));
    assert!(matches!(
        sweep.details,
        AlertDetails::HostSweep {
            method: SweepMethod::Arp,
            ..
        }
    ));
}

#[test]
fn ordinary_arp_traffic_is_not_a_sweep() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    // A PC asking for the router and two printers, again and again.
    for i in 0..100u8 {
        let arp = ArpPacket {
            operation: ArpOperation::Request,
            sender_mac: [2, 0, 0, 0, 0, 0x10],
            sender_ip: Ipv4Addr::new(192, 168, 1, 10),
            target_ip: Ipv4Addr::new(192, 168, 1, 1 + i % 3),
        };
        detectors.on_arp(Timestamp(i64::from(i) * 500), &arp, &mut alerts);
    }
    assert!(alerts.is_empty());
}

#[test]
fn repeated_ssh_logins_are_brute_force() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    for attempt in 0..30u16 {
        let flow = start(
            i64::from(attempt) * 1_000,
            StartKind::TcpSyn,
            ATTACKER,
            41_000 + attempt,
            VICTIM,
            22,
        );
        detectors.on_flow_start(&flow, &mut alerts);
    }
    let alert = alerts
        .iter()
        .find(|a| a.kind == AlertKind::BruteForce)
        .expect("brute force alert");
    assert_eq!(alert.dst_port, Some(22));
    assert_eq!(alert.severity, Severity::High);
    assert_eq!(alert.count, 10, "first published at the threshold");
}

#[test]
fn one_ssh_login_is_fine() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    // The same attempt retransmitted (same source port) counts once.
    for retry in 0..5 {
        let flow = start(
            retry * 1_000,
            StartKind::TcpSyn,
            VICTIM,
            41_000,
            "192.168.1.20",
            22,
        );
        detectors.on_flow_start(&flow, &mut alerts);
    }
    assert!(alerts.is_empty());
}

#[test]
fn ignored_sources_are_never_reported() {
    let config = DetectConfig {
        ignore_sources: vec![ip(ATTACKER)],
        ..DetectConfig::default()
    };
    let mut detectors = Detectors::new(&config, IdGenerator::starting_after(0));
    let mut alerts = Vec::new();
    for port in 1..=100u16 {
        detectors.on_flow_start(
            &start(0, StartKind::TcpSyn, ATTACKER, 1, VICTIM, port),
            &mut alerts,
        );
    }
    assert!(alerts.is_empty());
}

#[test]
fn suricata_hits_are_grouped_per_rule_and_hosts() {
    let mut detectors = detectors();
    let mut alerts = Vec::new();
    for i in 0..3 {
        let hit = SignatureHit {
            ts: Timestamp(i * 100),
            src_ip: ip(ATTACKER),
            dst_ip: ip(VICTIM),
            src_port: Some(4444),
            dst_port: Some(80),
            protocol: Some(Protocol::Tcp),
            signature_id: 2_001_219,
            signature: "ET SCAN Potential SSH Scan".to_string(),
            category: "Attempted Information Leak".to_string(),
            severity: 2,
            attack: None,
            engine: "suricata".to_string(),
        };
        detectors.on_signature(hit, &mut alerts);
    }
    detectors.expire(Timestamp(1_000_000), &mut alerts);
    assert!(alerts.iter().all(|a| a.id == alerts[0].id));
    assert_eq!(alerts.last().unwrap().count, 3);
    assert_eq!(alerts[0].severity, Severity::Medium);
}
