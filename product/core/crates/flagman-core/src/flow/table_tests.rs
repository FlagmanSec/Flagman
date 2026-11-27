//! Tests for the flow meter. Each test replays a tiny conversation.

use super::*;
use crate::flow::TcpOutcome;
use crate::packet::{Network, PacketMeta};
use crate::testutil::{ACK, FIN_ACK, RST, RST_ACK, SYN, SYN_ACK, packet_at, tcp_frame, udp_frame};

const CLIENT: &str = "192.168.1.50";
const SERVER: &str = "192.168.1.10";

fn ip_packet(meta: &PacketMeta) -> IpPacket {
    match meta.network {
        Network::Ip(packet) => packet,
        Network::Arp(_) => panic!("expected IP"),
    }
}

/// Feeds one frame at time `ms` into the table, and returns any flow the
/// table had to end early to make room.
fn feed_full(
    table: &mut FlowTable,
    ms: i64,
    frame: Vec<u8>,
) -> (Option<FlowStart>, Vec<FlowRecord>) {
    let meta = packet_at(ms, &frame);
    let mut ended = Vec::new();
    let start = table.observe(meta.ts, meta.wire_len, &ip_packet(&meta), &mut ended);
    (start, ended)
}

/// Feeds one frame at time `ms` into a table that is not full.
fn feed(table: &mut FlowTable, ms: i64, frame: Vec<u8>) -> Option<FlowStart> {
    let (start, ended) = feed_full(table, ms, frame);
    assert!(ended.is_empty(), "the table was not supposed to be full");
    start
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
    assert_eq!(
        record.end,
        FlowEnd::Stopped,
        "still open when the replay ended"
    );
}

#[test]
fn a_connection_closed_with_fin_in_both_directions_ends_as_closed() {
    let mut table = FlowTable::new(FlowTableConfig::default());
    feed(&mut table, 0, tcp_frame(CLIENT, 40_010, SERVER, 22, SYN));
    feed(
        &mut table,
        1,
        tcp_frame(SERVER, 22, CLIENT, 40_010, SYN_ACK),
    );
    feed(&mut table, 2, tcp_frame(CLIENT, 40_010, SERVER, 22, ACK));
    feed(
        &mut table,
        300,
        tcp_frame(CLIENT, 40_010, SERVER, 22, FIN_ACK),
    );
    feed(
        &mut table,
        301,
        tcp_frame(SERVER, 22, CLIENT, 40_010, FIN_ACK),
    );
    let ended = table.expire(Timestamp(6_000));
    assert_eq!(ended.len(), 1, "closed flows only linger 5 s");
    assert_eq!(ended[0].tcp_outcome, Some(TcpOutcome::Established));
    assert_eq!(ended[0].end, FlowEnd::Closed);
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
    assert_eq!(ended[0].end, FlowEnd::Closed);
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
    assert_eq!(ended[0].end, FlowEnd::Idle);
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
    let ended = table.expire(Timestamp(11_000));
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].end, FlowEnd::ActiveTimeout);
}

#[test]
fn a_full_table_ends_its_least_recently_active_flow_to_make_room() {
    let config = FlowTableConfig {
        max_flows: 3,
        ..FlowTableConfig::default()
    };
    let mut table = FlowTable::new(config);
    // Three flows; the one to port 1 then stays quiet while the others talk.
    for port in 1..=3 {
        feed(&mut table, 0, tcp_frame(CLIENT, 40_000, SERVER, port, SYN));
    }
    feed(&mut table, 10, tcp_frame(CLIENT, 40_000, SERVER, 2, ACK));
    feed(&mut table, 10, tcp_frame(CLIENT, 40_000, SERVER, 3, ACK));

    let (start, ended) = feed_full(&mut table, 20, tcp_frame(CLIENT, 40_000, SERVER, 4, SYN));
    assert!(start.is_some(), "the newcomer is tracked, never refused");
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].responder.port, 1, "the quietest flow made room");
    assert_eq!(ended[0].end, FlowEnd::Evicted);
    assert_eq!(table.active(), 3);
    assert_eq!(table.evictions(), (1, Some(Timestamp(20))));
}

#[test]
fn a_flood_of_new_flows_cannot_push_out_an_active_connection() {
    let config = FlowTableConfig {
        max_flows: 100,
        ..FlowTableConfig::default()
    };
    let mut table = FlowTable::new(config);
    feed(&mut table, 0, tcp_frame(CLIENT, 41_000, SERVER, 22, SYN));
    let mut evicted = Vec::new();
    for i in 0..1_000u16 {
        let ms = 1 + i64::from(i);
        // One packet from a new fake address each millisecond...
        let fake = format!("10.9.{}.{}", i / 250, i % 250 + 1);
        evicted.extend(feed_full(&mut table, ms, tcp_frame(&fake, 1_234, SERVER, 80, SYN)).1);
        // ...while the real connection keeps sending.
        evicted.extend(feed_full(&mut table, ms, tcp_frame(CLIENT, 41_000, SERVER, 22, ACK)).1);
    }
    assert!(evicted.len() >= 900, "the flood pushed out its own entries");
    assert!(evicted.iter().all(|record| record.responder.port == 80));
    let real = table
        .drain()
        .into_iter()
        .find(|record| record.responder.port == 22);
    assert_eq!(real.map(|record| record.packets_fwd), Some(1_001));
}

/// Flows sit in a hash table whose order changes with every new table, like
/// it changes between two runs of the program. Ties must not show it.
fn udp_flows_started_together(table: &mut FlowTable, ports: impl Iterator<Item = u16>) {
    for port in ports {
        let frame = udp_frame(CLIENT, port, SERVER, 53);
        let meta = packet_at(0, &frame);
        let mut ended = Vec::new();
        table.observe(meta.ts, meta.wire_len, &ip_packet(&meta), &mut ended);
    }
}

fn client_ports(flows: &[FlowRecord]) -> Vec<u16> {
    flows.iter().map(|flow| flow.initiator.port).collect()
}

#[test]
fn flows_that_start_in_the_same_millisecond_always_end_in_the_same_order() {
    let in_key_order: Vec<u16> = (40_000..40_020).collect();
    for _ in 0..5 {
        let mut table = FlowTable::new(FlowTableConfig::default());
        udp_flows_started_together(&mut table, (40_000..40_020).rev());
        assert_eq!(client_ports(&table.expire(Timestamp(61_000))), in_key_order);

        let mut table = FlowTable::new(FlowTableConfig::default());
        udp_flows_started_together(&mut table, (40_000..40_020).rev());
        assert_eq!(client_ports(&table.drain()), in_key_order);
    }
}

#[test]
fn a_full_table_always_ends_the_same_flow_when_several_are_equally_old() {
    let config = FlowTableConfig {
        max_flows: 10,
        ..FlowTableConfig::default()
    };
    for _ in 0..5 {
        let mut table = FlowTable::new(config.clone());
        udp_flows_started_together(
            &mut table,
            [40_005, 40_002, 40_009, 40_000, 40_007].into_iter(),
        );
        udp_flows_started_together(
            &mut table,
            [40_001, 40_008, 40_003, 40_006, 40_004].into_iter(),
        );
        let (_, ended) = feed_full(&mut table, 0, udp_frame(CLIENT, 41_000, SERVER, 53));
        assert_eq!(
            client_ports(&ended),
            [40_000],
            "the smallest key goes first"
        );
    }
}
