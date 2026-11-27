//! Tests for the engine: replayed traffic in, flows, alerts and incidents out.

use super::*;
use crate::alert::AlertKind;
use crate::testutil::{RST_ACK, SYN, tcp_frame, udp_frame};

#[test]
fn a_replayed_scan_becomes_an_incident_with_flows_and_traffic() {
    let mut engine = Engine::new(&EngineConfig::default(), StartIds::default());
    let mut out = Vec::new();
    for port in 1..=50u16 {
        let ms = i64::from(port) * 10;
        let syn = tcp_frame("192.168.1.66", 60_000, "192.168.1.10", port, SYN);
        let reset = tcp_frame("192.168.1.10", port, "192.168.1.66", 60_000, RST_ACK);
        engine.process_frame(
            LinkType::Ethernet,
            Timestamp(ms),
            syn.len() as u32,
            &syn,
            &mut out,
        );
        engine.process_frame(
            LinkType::Ethernet,
            Timestamp(ms + 1),
            reset.len() as u32,
            &reset,
            &mut out,
        );
    }
    engine.finish(&mut out);

    let flows = out.iter().filter(|o| matches!(o, Output::Flow(_))).count();
    assert_eq!(flows, 50);
    let alert = out
        .iter()
        .rev()
        .find_map(|o| match o {
            Output::Alert(alert) => Some(alert),
            _ => None,
        })
        .expect("an alert");
    assert_eq!(alert.kind, AlertKind::PortScan);
    assert_eq!(alert.count, 50);
    assert_eq!(alert.incident_id, Some(1));
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Incident(i) if i.id == 1))
    );
    assert!(out.iter().any(|o| matches!(o, Output::Traffic(_))));
    assert_eq!(engine.counters().packets, 100);
}

/// The attack from the review of phase 1: about 1,000 packets per second
/// from 60,000 fake addresses fill the detectors, then a real scan runs.
/// Before the fix the scan went unseen; now the fake entries make room.
#[test]
fn a_flood_of_fake_addresses_does_not_hide_a_real_scan() {
    let mut engine = Engine::new(&EngineConfig::default(), StartIds::default());
    let mut out = Vec::new();
    let send = |engine: &mut Engine, ms: i64, frame: Vec<u8>, out: &mut Vec<Output>| {
        engine.process_frame(
            LinkType::Ethernet,
            Timestamp(ms),
            frame.len() as u32,
            &frame,
            out,
        );
    };
    for i in 0..60_000u32 {
        let fake = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 0xff, i & 0xff);
        send(
            &mut engine,
            i64::from(i),
            tcp_frame(&fake, 40_000, "192.168.1.10", 80, SYN),
            &mut out,
        );
        if (55_000..56_000).contains(&i) {
            let port = u16::try_from(i - 55_000 + 1).unwrap();
            let syn = tcp_frame("192.168.1.66", 50_000, "192.168.1.10", port, SYN);
            send(&mut engine, i64::from(i), syn, &mut out);
        }
    }
    engine.finish(&mut out);

    let scan = out
        .iter()
        .rev()
        .find_map(|o| match o {
            Output::Alert(alert) if alert.kind == AlertKind::PortScan => Some(alert),
            _ => None,
        })
        .expect("the real scan is detected");
    assert_eq!(scan.src_ip.to_string(), "192.168.1.66");
    assert_eq!(scan.count, 1_000);
    let counters = engine.counters();
    assert!(counters.detector_evicted > 0, "the detectors were full");
    assert!(counters.saturated_at.is_some());
}

/// Counts the packets of each flow, to check what an extension receives.
#[derive(Default)]
struct PacketCount(u64);

impl FlowExtra for PacketCount {
    type Finished = (FlowRecord, u64);

    fn add_packet(&mut self, _packet: &crate::flow::FlowPacket<'_>) {
        self.0 += 1;
    }

    fn finish(self, record: FlowRecord) -> (FlowRecord, u64) {
        (record, self.0)
    }

    fn record(finished: &(FlowRecord, u64)) -> &FlowRecord {
        &finished.0
    }
}

/// Runs a small scan with replies through any engine.
fn scan_through<X: FlowExtra>(engine: &mut Engine<X>) -> Outputs<X> {
    let mut out = Vec::new();
    for port in 1..=30u16 {
        let ms = i64::from(port) * 10;
        for (at, frame) in [
            (
                ms,
                tcp_frame("192.168.1.66", 60_000, "192.168.1.10", port, SYN),
            ),
            (
                ms + 1,
                tcp_frame("192.168.1.10", port, "192.168.1.66", 60_000, RST_ACK),
            ),
        ] {
            engine.process_frame(
                LinkType::Ethernet,
                Timestamp(at),
                frame.len() as u32,
                &frame,
                &mut out,
            );
        }
    }
    engine.finish(&mut out);
    out
}

#[test]
fn an_engine_with_an_extension_finds_the_same_flows_and_alerts() {
    // 30 ports: above the default threshold of 20, so the scan is found.
    let config = EngineConfig::default();
    let plain = scan_through(&mut Engine::new(&config, StartIds::default()));
    let extended = scan_through(&mut Engine::<PacketCount>::with_extra(
        &config,
        StartIds::default(),
    ));

    assert_eq!(plain.len(), extended.len());
    for (a, b) in plain.iter().zip(&extended) {
        match (a, b) {
            (Output::Flow(record), Output::Flow((same, packets))) => {
                assert_eq!(record, same);
                assert_eq!(*packets, record.packets_fwd + record.packets_rev);
            }
            (Output::Alert(x), Output::Alert(y)) => assert_eq!(x, y),
            (Output::Incident(x), Output::Incident(y)) => assert_eq!(x, y),
            (Output::Traffic(x), Output::Traffic(y)) => assert_eq!(x, y),
            _ => panic!("the outputs differ: {a:?} and {b:?}"),
        }
    }
    assert!(
        plain.iter().any(|o| matches!(o, Output::Alert(_))),
        "the scan was found"
    );
}

/// A known difference between live mode and replay, for the parity test in
/// `docs/phase-2-plan.md` (2.9). One UDP flow, silent for 70 s (its idle
/// timeout is 60 s), in a capture with no other traffic. Live, the capture
/// times out every 250 ms and the engine runs its timeouts with the clock,
/// so the flow ends during the silence and the late packet starts a new
/// one. A replay runs timeouts only after a packet, so the late packet
/// joins the old flow.
#[test]
fn a_flow_silent_past_its_timeout_is_cut_live_but_not_in_a_quiet_replay() {
    let flows = |live_tick: bool| {
        let mut engine = Engine::new(&EngineConfig::default(), StartIds::default());
        let mut out = Vec::new();
        let frame = udp_frame("192.168.1.50", 40_000, "192.168.1.10", 53);
        let len = frame.len() as u32;
        engine.process_frame(LinkType::Ethernet, Timestamp(0), len, &frame, &mut out);
        if live_tick {
            engine.tick(Timestamp(61_000), &mut out);
        }
        engine.process_frame(LinkType::Ethernet, Timestamp(70_000), len, &frame, &mut out);
        engine.finish(&mut out);
        out.iter()
            .filter_map(|o| match o {
                Output::Flow(flow) => Some(flow.packets_fwd),
                _ => None,
            })
            .collect::<Vec<u64>>()
    };
    assert_eq!(flows(true), [1, 1], "live: two flows of one packet");
    assert_eq!(flows(false), [2], "replay: one flow of two packets");
}
