//! Store tests: write what the engine would write, read it back as the API would.

use super::*;
use flagman_core::alert::{Alert, AlertDetails, AlertKind, Severity};
use flagman_core::engine::Output;
use flagman_core::flow::{Endpoint, FlowEnd, FlowRecord, Protocol, TcpOutcome};
use flagman_core::incident::Incident;
use flagman_core::time::Timestamp;
use flagman_core::traffic::{TrafficClass, TrafficMinute};

const MINUTE: i64 = 60_000;

fn flow(at: i64, src: &str, dst: &str, dst_port: u16, bytes: u64) -> Output {
    Output::Flow(FlowRecord {
        protocol: Protocol::Tcp,
        initiator: Endpoint {
            ip: src.parse().unwrap(),
            port: 40_000,
        },
        responder: Endpoint {
            ip: dst.parse().unwrap(),
            port: dst_port,
        },
        first_seen: Timestamp(at),
        last_seen: Timestamp(at + 500),
        packets_fwd: 3,
        packets_rev: 2,
        bytes_fwd: bytes,
        bytes_rev: 0,
        tcp_outcome: Some(TcpOutcome::Rejected),
        end: FlowEnd::Closed,
    })
}

fn scan_alert(id: u64, count: u64, at: i64) -> Output {
    Output::Alert(Alert {
        id,
        incident_id: Some(1),
        kind: AlertKind::PortScan,
        severity: Severity::Medium,
        first_seen: Timestamp(at),
        last_seen: Timestamp(at + 1_000),
        src_ip: "192.168.1.66".parse().unwrap(),
        dst_ip: Some("192.168.1.10".parse().unwrap()),
        dst_port: None,
        count,
        details: AlertDetails::PortScan {
            protocol: Protocol::Tcp,
            ports_sample: vec![22, 80],
            window_secs: 60,
        },
        attack: None,
    })
}

fn incident(alert_count: u64, last_seen: i64) -> Output {
    Output::Incident(Incident {
        id: 1,
        first_seen: Timestamp(0),
        last_seen: Timestamp(last_seen),
        src_ip: "192.168.1.66".parse().unwrap(),
        severity: Severity::Medium,
        alert_count,
        kinds: vec![AlertKind::PortScan],
        tactics: vec!["Discovery".to_string()],
        targets: vec!["192.168.1.10".parse().unwrap()],
    })
}

fn traffic(minute: i64, class: TrafficClass, packets: u64, bytes: u64) -> Output {
    Output::Traffic(TrafficMinute {
        minute: Timestamp(minute),
        class,
        packets,
        bytes,
    })
}

fn range(minutes: i64) -> TimeRange {
    TimeRange {
        since: Timestamp(0),
        until: Timestamp(minutes * MINUTE),
        bucket_ms: MINUTE,
    }
}

#[test]
fn an_alert_published_twice_is_stored_once_with_the_latest_count() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_outputs(&[scan_alert(1, 20, 0), incident(1, 1_000)])
        .unwrap();
    store
        .write_outputs(&[scan_alert(1, 1_000, 0), incident(1, 9_000)])
        .unwrap();
    let alerts = store
        .recent_alerts(Timestamp(0), Timestamp(MINUTE), 10)
        .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].count, 1_000);
    assert_eq!(alerts[0].details["type"], "port_scan");
    assert_eq!(store.last_ids().unwrap(), (1, 1));
}

#[test]
fn the_analyst_status_survives_engine_updates() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_outputs(&[scan_alert(1, 20, 0), incident(1, 1_000)])
        .unwrap();
    assert!(
        store
            .set_incident_status(1, "confirmed", Timestamp(2_000))
            .unwrap()
    );
    store.write_outputs(&[incident(2, 5_000)]).unwrap();
    let detail = store.incident_detail(1).unwrap().unwrap();
    assert_eq!(detail.incident.status, "confirmed");
    assert_eq!(detail.incident.alert_count, 2);
    assert!(
        store
            .set_incident_status(1, "deleted", Timestamp(0))
            .is_err()
    );
    assert!(
        !store
            .set_incident_status(99, "resolved", Timestamp(0))
            .unwrap()
    );
}

#[test]
fn incident_detail_includes_the_storyline_and_the_hosts_flows() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_outputs(&[
            flow(100, "192.168.1.66", "192.168.1.10", 22, 60),
            flow(200, "192.168.1.66", "192.168.1.10", 23, 60),
            flow(300, "192.168.1.20", "8.8.8.8", 443, 5_000),
            scan_alert(1, 20, 0),
            incident(1, 1_000),
        ])
        .unwrap();
    let detail = store.incident_detail(1).unwrap().unwrap();
    assert_eq!(detail.alerts.len(), 1);
    assert_eq!(detail.flows.len(), 2, "only flows of 192.168.1.66");
    assert_eq!(detail.flows[0].dst_port, 22, "oldest first");
    assert!(!detail.flows_truncated);
    assert!(store.incident_detail(42).unwrap().is_none());
}

#[test]
fn traffic_counts_add_up_per_minute_and_fill_empty_buckets() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_outputs(&[
            traffic(0, TrafficClass::Tcp, 10, 1_000),
            traffic(0, TrafficClass::Tcp, 5, 500), // a second partial flush of minute 0
            traffic(2 * MINUTE, TrafficClass::Arp, 3, 180),
        ])
        .unwrap();
    let series = store.traffic_series(range(3)).unwrap();
    assert_eq!(series.len(), 3);
    assert_eq!(series[0].bytes.tcp, 1_500);
    assert_eq!(
        series[1].packets.tcp, 0,
        "empty minute is a zero, not a gap"
    );
    assert_eq!(series[2].packets.arp, 3);
    let (packets, _bytes) = store.protocol_totals(range(3)).unwrap();
    assert_eq!((packets.tcp, packets.arp), (15, 3));
}

#[test]
fn overview_and_top_lists_summarise_the_range() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_outputs(&[
            flow(100, "192.168.1.20", "8.8.8.8", 443, 5_000),
            flow(200, "192.168.1.20", "1.1.1.1", 443, 1_000),
            flow(300, "192.168.1.66", "192.168.1.10", 22, 60),
            traffic(0, TrafficClass::Tcp, 10, 6_060),
            scan_alert(1, 20, 0),
            incident(1, 1_000),
        ])
        .unwrap();
    let overview = store.overview(range(1)).unwrap();
    assert_eq!(
        (overview.flows, overview.alerts, overview.open_incidents),
        (3, 1, 1)
    );
    assert_eq!(overview.bytes, 6_060);
    assert_eq!(overview.local_hosts, 3);
    assert_eq!(overview.incidents_by_severity.medium, 1);

    let talkers = store.top_talkers(range(1), 5).unwrap();
    assert_eq!(talkers[0].ip, "192.168.1.20");
    assert_eq!(talkers[0].bytes, 6_000);
    let ports = store.top_ports(range(1), 5).unwrap();
    assert_eq!((ports[0].name.as_str(), ports[0].count), ("443", 2));
    let alert_types = store.top_alerts(range(1), 5).unwrap();
    assert_eq!(alert_types[0].name, "port_scan");
    assert_eq!(alert_types[0].value, Some(serde_json::json!("medium")));
    let series = store.alert_series(range(1)).unwrap();
    assert_eq!(series[0].counts.medium, 1);
}

#[test]
fn flows_can_be_filtered_and_old_data_pruned() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_outputs(&[
            flow(100, "192.168.1.20", "8.8.8.8", 443, 5_000),
            flow(10 * MINUTE, "192.168.1.66", "192.168.1.10", 22, 60),
        ])
        .unwrap();
    let ssh = FlowFilter {
        port: Some(22),
        limit: 10,
        ..FlowFilter::default()
    };
    assert_eq!(store.flows(&ssh).unwrap().len(), 1);
    let by_ip = FlowFilter {
        ip: Some("8.8.8.8".to_string()),
        limit: 10,
        ..FlowFilter::default()
    };
    assert_eq!(
        store.flows(&by_ip).unwrap()[0].tcp_outcome.as_deref(),
        Some("rejected")
    );
    assert_eq!(
        store.latest_timestamp().unwrap(),
        Some(Timestamp(10 * MINUTE + 500))
    );

    store.prune(Timestamp(MINUTE), Timestamp(0)).unwrap();
    let all = FlowFilter {
        limit: 10,
        ..FlowFilter::default()
    };
    assert_eq!(store.flows(&all).unwrap().len(), 1);
}

#[test]
fn a_database_file_can_be_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flagman.db");
    {
        let mut store = Store::open(&path).unwrap();
        store
            .write_outputs(&[scan_alert(7, 20, 0), incident(1, 1_000)])
            .unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(store.last_ids().unwrap(), (7, 1));
}
