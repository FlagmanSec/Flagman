//! Replay tests on real traffic.
//!
//! The capture files in `product/core/testdata/pcap` were recorded with
//! `record-lab-captures.sh` and `record-ssh-capture.sh`, in an isolated lab
//! of two network namespaces. The README next to them explains every number
//! checked here.

use super::*;
use flagman_store::FlowFilter;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pcap")
        .join(name)
}

fn replay_into_memory(name: &str) -> (Store, Summary) {
    let mut store = Store::open_in_memory().unwrap();
    let summary = analyse(&fixture(name), &Config::default(), &mut store).unwrap();
    (store, summary)
}

fn all_incidents(store: &Store) -> Vec<flagman_store::IncidentRow> {
    store
        .incidents(&IncidentFilter {
            limit: 100,
            ..IncidentFilter::default()
        })
        .unwrap()
}

#[test]
fn a_real_nmap_attack_chain_becomes_one_critical_incident() {
    let (store, summary) = replay_into_memory("lab-attack-chain.pcap");
    assert_eq!(summary.counters.packets, 2_676);
    assert_eq!(summary.counters.packets_skipped, 0);

    let incidents = all_incidents(&store);
    assert_eq!(incidents.len(), 1, "one attacker, one storyline");
    let incident = &incidents[0];
    assert_eq!(incident.src_ip, "192.168.77.66");
    assert_eq!(incident.alert_count, 3);
    assert!(incident.tactics.contains(&"Discovery".to_string()));
    assert!(incident.tactics.contains(&"Credential Access".to_string()));
    assert_eq!(
        incident.severity, "critical",
        "a high alert plus a second ATT&CK tactic raises the incident"
    );

    let detail = store.incident_detail(incident.id).unwrap().unwrap();
    let alert = |kind: &str| {
        detail
            .alerts
            .iter()
            .find(|alert| alert.kind == kind)
            .unwrap_or_else(|| panic!("no {kind} alert"))
    };
    // `nmap -sn 192.168.77.0/24`: ARP for every address but its own (256 - 1).
    assert_eq!(alert("host_sweep").count, 255);
    // `nmap 192.168.77.10`: a SYN scan of nmap's 1,000 most common ports.
    let scan = alert("port_scan");
    assert_eq!(scan.count, 1_000);
    assert_eq!(scan.dst_ip.as_deref(), Some("192.168.77.10"));
    // The 15 scripted SSH connections, each closed within a second. The
    // scan's own SYN to port 22 is not a login attempt: the port answered
    // and nmap reset the connection (half-open), so it does not count.
    let logins = alert("brute_force");
    assert_eq!(logins.count, 15);
    assert_eq!(logins.dst_port, Some(22));
}

#[test]
fn normal_traffic_raises_no_incident() {
    let (store, summary) = replay_into_memory("lab-normal-traffic.pcap");
    assert_eq!(summary.counters.packets, 500);
    assert!(all_incidents(&store).is_empty());
    let flows = store
        .flows(&FlowFilter {
            limit: 1_000,
            ..FlowFilter::default()
        })
        .unwrap();
    let web = flows
        .iter()
        .filter(|flow| flow.dst_port == 8080 && flow.tcp_outcome.as_deref() == Some("established"))
        .count();
    assert_eq!(web, 40, "40 page loads, each a complete TCP connection");
}

#[test]
fn real_ssh_logins_count_only_refused_or_short_connections() {
    let (store, summary) = replay_into_memory("lab-ssh-logins.pcap");
    assert_eq!(summary.counters.packets, 649);

    let incidents = all_incidents(&store);
    assert_eq!(incidents.len(), 1);
    let incident = &incidents[0];
    assert_eq!(incident.src_ip, "192.168.77.66");
    assert_eq!(incident.severity, "high", "one tactic: not raised");
    let detail = store.incident_detail(incident.id).unwrap().unwrap();
    assert_eq!(detail.alerts.len(), 1);
    let logins = &detail.alerts[0];
    assert_eq!(logins.kind, "brute_force");
    assert_eq!(logins.dst_port, Some(22));
    // 10 connections with one wrong password, 3 with six, 5 refused once the
    // server stopped, and 5 quick successful logins: from headers alone they
    // look like failed ones (the known limit, see the README). The 40-second
    // working session is the only connection that does not count.
    assert_eq!(logins.count, 23);

    let ssh = store
        .flows(&FlowFilter {
            port: Some(22),
            limit: 100,
            ..FlowFilter::default()
        })
        .unwrap();
    assert_eq!(ssh.len(), 24);
    let long: Vec<i64> = ssh
        .iter()
        .map(|flow| flow.last_seen - flow.first_seen)
        .filter(|millis| *millis > 30_000)
        .collect();
    assert_eq!(long.len(), 1, "only the working session lasted over 30 s");
}

#[test]
fn replaying_twice_into_one_database_continues_the_ids() {
    let mut store = Store::open_in_memory().unwrap();
    let config = Config::default();
    analyse(&fixture("lab-attack-chain.pcap"), &config, &mut store).unwrap();
    analyse(&fixture("lab-attack-chain.pcap"), &config, &mut store).unwrap();
    let ids: Vec<u64> = all_incidents(&store).iter().map(|i| i.id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&1) && ids.contains(&2));
}

#[test]
fn an_existing_results_file_is_never_replaced_silently() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("results.db");
    std::fs::write(&db, b"old").unwrap();
    let error = prepare_database(&db, false).unwrap_err();
    assert!(error.to_string().contains("--overwrite"));
    assert!(db.exists());
    prepare_database(&db, true).unwrap();
    assert!(!db.exists());
}
