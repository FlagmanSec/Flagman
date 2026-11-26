//! Tests for the flow meter. Each test replays a tiny conversation.

use super::*;
use crate::packet::{Network, PacketMeta};
use crate::testutil::{ACK, RST, RST_ACK, SYN, SYN_ACK, packet_at, tcp_frame, udp_frame};

const CLIENT: &str = "192.168.1.50";
const SERVER: &str = "192.168.1.10";

fn ip_packet(meta: &PacketMeta) -> IpPacket {
    match meta.network {
        Network::Ip(packet) => packet,
        Network::Arp(_) => panic!("expected IP"),
    }
}

/// Feeds one frame at time `ms` into the table.
fn feed(table: &mut FlowTable, ms: i64, frame: Vec<u8>) -> Option<FlowStart> {
    let meta = packet_at(ms, &frame);
    table.observe(meta.ts, meta.wire_len, &ip_packet(&meta))
}

#[test]
fn a_full_handshake_is_one_established_flow() {
    let mut table = FlowTable::new(FlowTableConfig::default());
    let start = feed(&mut table, 0, tcp_frame(CLIENT, 40_000, SERVER, 22, SYN)).unwrap();
    assert_eq!(start.kind, StartKind::TcpSyn);
    assert_eq!(start.responder.port, 22);
    assert!(
        feed(
            &mut table,
            1,
            tcp_frame(SERVER, 22, CLIENT, 40_000, SYN_ACK)
        )
        .is_none()
    );
    assert!(feed(&mut table, 2, tcp_frame(CLIENT, 40_000, SERVER, 22, ACK)).is_none());
    assert_eq!(table.active(), 1);

    let ended = table.drain();
    assert_eq!(ended.len(), 1);
    let record = ended[0];
    assert_eq!(record.packets_fwd, 2);
    assert_eq!(record.packets_rev, 1);
    assert_eq!(record.tcp_outcome, Some(TcpOutcome::Established));
}

#[test]
fn a_closed_port_is_rejected_and_ends_after_the_linger_time() {
    let mut table = FlowTable::new(FlowTableConfig::default());
    feed(&mut table, 0, tcp_frame(CLIENT, 40_001, SERVER, 23, SYN));
    feed(
        &mut table,
        1,
        tcp_frame(SERVER, 23, CLIENT, 40_001, RST_ACK),
    );
    assert!(table.expire(Timestamp(4_000)).is_empty(), "still lingering");
    let ended = table.expire(Timestamp(6_000));
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].tcp_outcome, Some(TcpOutcome::Rejected));
}

#[test]
fn a_syn_scan_on_an_open_port_is_half_open() {
    let mut table = FlowTable::new(FlowTableConfig::default());
    feed(&mut table, 0, tcp_frame(CLIENT, 40_002, SERVER, 80, SYN));
    feed(
        &mut table,
        1,
        tcp_frame(SERVER, 80, CLIENT, 40_002, SYN_ACK),
    );
    feed(&mut table, 2, tcp_frame(CLIENT, 40_002, SERVER, 80, RST));
    assert_eq!(table.drain()[0].tcp_outcome, Some(TcpOutcome::HalfOpen));
}

#[test]
fn an_unanswered_syn_ends_after_the_tcp_idle_timeout() {
    let config = FlowTableConfig::default();
    let idle_ms = config.tcp_idle_secs * 1_000;
    let mut table = FlowTable::new(config);
    feed(&mut table, 0, tcp_frame(CLIENT, 40_003, SERVER, 8080, SYN));
    assert!(table.expire(Timestamp(idle_ms - 1)).is_empty());
    let ended = table.expire(Timestamp(idle_ms));
    assert_eq!(ended[0].tcp_outcome, Some(TcpOutcome::Unanswered));
}

#[test]
fn udp_flows_end_after_the_udp_idle_timeout() {
    let mut table = FlowTable::new(FlowTableConfig::default());
    let start = feed(&mut table, 0, udp_frame(CLIENT, 5_000, SERVER, 53)).unwrap();
    assert_eq!(start.kind, StartKind::Udp);
    feed(&mut table, 10, udp_frame(SERVER, 53, CLIENT, 5_000));
    let ended = table.expire(Timestamp(60_010));
    assert_eq!(ended.len(), 1);
    assert_eq!((ended[0].packets_fwd, ended[0].packets_rev), (1, 1));
    assert_eq!(ended[0].tcp_outcome, None);
}

#[test]
fn a_long_flow_is_cut_at_the_active_timeout() {
    let config = FlowTableConfig {
        active_timeout_secs: 10,
        ..FlowTableConfig::default()
    };
    let mut table = FlowTable::new(config);
    for second in 0..12 {
        feed(
            &mut table,
            second * 1_000,
            udp_frame(CLIENT, 6_000, SERVER, 9_000),
        );
    }
    assert_eq!(table.expire(Timestamp(11_000)).len(), 1);
}

#[test]
fn a_full_table_still_reports_new_flows_to_the_detectors() {
    let config = FlowTableConfig {
        max_flows: 2,
        ..FlowTableConfig::default()
    };
    let mut table = FlowTable::new(config);
    for port in 1..=4 {
        let start = feed(&mut table, 0, tcp_frame(CLIENT, 40_000, SERVER, port, SYN));
        assert!(start.is_some(), "port {port} must still be reported");
    }
    assert_eq!(table.active(), 2);
    assert_eq!(table.untracked(), 2);
}
