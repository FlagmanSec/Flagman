//! The extension slot of the flow table: what an extension sees, and what
//! comes out when the flow ends.

use super::*;
use crate::flow::{FlowEnd, FlowTable, FlowTableConfig};
use crate::packet::Network;
use crate::testutil::{ACK, FIN_ACK, SYN, SYN_ACK, packet_at, tcp_frame};

/// Remembers what it was shown.
#[derive(Default)]
struct Seen {
    forward: Vec<bool>,
    packets_so_far: Vec<u64>,
}

impl FlowExtra for Seen {
    type Finished = (FlowRecord, Seen);

    fn add_packet(&mut self, packet: &FlowPacket<'_>) {
        self.forward.push(packet.forward);
        let record = packet.record;
        self.packets_so_far
            .push(record.packets_fwd + record.packets_rev);
    }

    fn finish(self, record: FlowRecord) -> (FlowRecord, Seen) {
        (record, self)
    }

    fn record(finished: &(FlowRecord, Seen)) -> &FlowRecord {
        &finished.0
    }
}

const CLIENT: &str = "192.168.1.50";
const SERVER: &str = "192.168.1.10";

fn show(table: &mut FlowTable<Seen>, ms: i64, frame: &[u8], ended: &mut Vec<(FlowRecord, Seen)>) {
    let meta = packet_at(ms, frame);
    let Network::Ip(ip) = meta.network else {
        panic!("test frames are IP");
    };
    table.observe(meta.ts, meta.wire_len, &ip, ended);
}

#[test]
fn an_extension_sees_every_packet_in_order_and_ends_with_the_record() {
    let mut table: FlowTable<Seen> = FlowTable::with_extra(FlowTableConfig::default());
    let mut ended = Vec::new();
    let conversation = [
        (0, tcp_frame(CLIENT, 40_000, SERVER, 22, SYN)),
        (1, tcp_frame(SERVER, 22, CLIENT, 40_000, SYN_ACK)),
        (2, tcp_frame(CLIENT, 40_000, SERVER, 22, ACK)),
        (10, tcp_frame(CLIENT, 40_000, SERVER, 22, FIN_ACK)),
        (11, tcp_frame(SERVER, 22, CLIENT, 40_000, FIN_ACK)),
    ];
    for (ms, frame) in &conversation {
        show(&mut table, *ms, frame, &mut ended);
    }
    let mut finished = table.drain();
    assert!(ended.is_empty());
    assert_eq!(finished.len(), 1);
    let (record, seen) = finished.remove(0);
    assert_eq!(seen.forward, [true, false, true, true, false]);
    // The record already counts the packet the extension is shown.
    assert_eq!(seen.packets_so_far, [1, 2, 3, 4, 5]);
    assert_eq!(record.end, FlowEnd::Closed);
}

#[test]
fn an_evicted_flow_keeps_its_extension() {
    let config = FlowTableConfig {
        max_flows: 2,
        ..FlowTableConfig::default()
    };
    let mut table: FlowTable<Seen> = FlowTable::with_extra(config);
    let mut ended = Vec::new();
    for (ms, port) in [(0, 1_001), (5, 1_002), (9, 1_003)] {
        show(
            &mut table,
            ms,
            &tcp_frame(CLIENT, port, SERVER, 80, SYN),
            &mut ended,
        );
    }
    // The table held two flows: the oldest one made room for the third.
    assert_eq!(ended.len(), 1);
    let (record, seen) = &ended[0];
    assert_eq!(record.initiator.port, 1_001);
    assert_eq!(record.end, FlowEnd::Evicted);
    assert_eq!(seen.forward, [true]);
}
