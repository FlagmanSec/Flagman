//! The engine wires the pipeline together for one packet at a time:
//! decode, then flow meter, then detectors, then incidents.
//!
//! Detectors hear about a flow twice: when it starts (scans and sweeps count
//! connection requests) and when it ends (login attempts are judged by how
//! the connection finished).
//!
//! It never blocks and never touches the disk. Everything it produces is
//! pushed into an `out` vector of [`Output`]s, which the daemon hands to the
//! storage writer.

use crate::alert::Alert;
use crate::detect::{DetectConfig, Detectors, SignatureHit};
use crate::flow::{FlowRecord, FlowTable, FlowTableConfig};
use crate::ids::IdGenerator;
use crate::incident::{Incident, IncidentEngine};
use crate::packet::{LinkType, Network, PacketMeta, Transport, decode};
use crate::time::Timestamp;
use crate::traffic::{TrafficClass, TrafficCounter, TrafficMinute};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    pub flows: FlowTableConfig,
    pub detect: DetectConfig,
    /// Alerts from the same host more than this far apart start a new incident.
    pub incident_gap_secs: i64,
}

impl Default for EngineConfig {
    fn default() -> EngineConfig {
        EngineConfig {
            flows: FlowTableConfig::default(),
            detect: DetectConfig::default(),
            incident_gap_secs: 1_800,
        }
    }
}

/// The highest ids already stored, so new ids continue after them.
#[derive(Clone, Copy, Debug, Default)]
pub struct StartIds {
    pub last_alert_id: u64,
    pub last_incident_id: u64,
}

/// Everything the engine produces.
#[derive(Clone, Debug, PartialEq)]
pub enum Output {
    Flow(FlowRecord),
    Alert(Alert),
    Incident(Incident),
    Traffic(TrafficMinute),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineCounters {
    pub packets: u64,
    pub bytes: u64,
    pub packets_skipped: u64,
    pub flows_active: u64,
    /// Flows ended early because the flow table was full.
    pub flows_evicted: u64,
    /// Entries the detectors forgot because they were full.
    pub detector_evicted: u64,
    /// The last time the flow table or a detector was full.
    pub saturated_at: Option<Timestamp>,
    pub last_packet_at: Option<Timestamp>,
}

/// Housekeeping (timeouts) runs at most once per second of packet time.
const HOUSEKEEPING_EVERY_MS: i64 = 1_000;

pub struct Engine {
    flows: FlowTable,
    detectors: Detectors,
    incidents: IncidentEngine,
    traffic: TrafficCounter,
    counters: EngineCounters,
    next_housekeeping: Timestamp,
}

impl Engine {
    pub fn new(config: &EngineConfig, ids: StartIds) -> Engine {
        Engine {
            flows: FlowTable::new(config.flows.clone()),
            detectors: Detectors::new(
                &config.detect,
                IdGenerator::starting_after(ids.last_alert_id),
            ),
            incidents: IncidentEngine::new(
                config.incident_gap_secs,
                IdGenerator::starting_after(ids.last_incident_id),
            ),
            traffic: TrafficCounter::default(),
            counters: EngineCounters::default(),
            next_housekeeping: Timestamp(i64::MIN),
        }
    }

    /// Processes one captured frame.
    pub fn process_frame(
        &mut self,
        link: LinkType,
        ts: Timestamp,
        wire_len: u32,
        data: &[u8],
        out: &mut Vec<Output>,
    ) {
        self.counters.packets += 1;
        self.counters.bytes += u64::from(wire_len);
        self.counters.last_packet_at = Some(ts);
        match decode(link, ts, wire_len, data) {
            Ok(packet) => self.process_packet(&packet, out),
            Err(_) => {
                self.counters.packets_skipped += 1;
                self.count_traffic(ts, TrafficClass::Other, wire_len, out);
            }
        }
        self.tick(ts, out);
    }

    fn process_packet(&mut self, packet: &PacketMeta, out: &mut Vec<Output>) {
        let mut alerts = Vec::new();
        match &packet.network {
            Network::Ip(ip_packet) => {
                let class = match ip_packet.transport {
                    Transport::Tcp { .. } => TrafficClass::Tcp,
                    Transport::Udp { .. } => TrafficClass::Udp,
                    Transport::Icmp { .. } => TrafficClass::Icmp,
                    Transport::Other { .. } => TrafficClass::Other,
                };
                self.count_traffic(packet.ts, class, packet.wire_len, out);
                let mut evicted = Vec::new();
                let start = self
                    .flows
                    .observe(packet.ts, packet.wire_len, ip_packet, &mut evicted);
                self.flows_ended(evicted, &mut alerts, out);
                if let Some(start) = start {
                    self.detectors.on_flow_start(&start, &mut alerts);
                }
            }
            Network::Arp(arp) => {
                self.count_traffic(packet.ts, TrafficClass::Arp, packet.wire_len, out);
                self.detectors.on_arp(packet.ts, arp, &mut alerts);
            }
        }
        self.publish(alerts, out);
    }

    /// Processes one rule match reported by Suricata.
    pub fn process_signature(&mut self, hit: SignatureHit, out: &mut Vec<Output>) {
        let mut alerts = Vec::new();
        self.detectors.on_signature(hit, &mut alerts);
        self.publish(alerts, out);
    }

    /// Runs timeouts. Called after each packet, and by the daemon with the
    /// wall-clock time when no packet arrives.
    pub fn tick(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        if now < self.next_housekeeping {
            return;
        }
        self.next_housekeeping = now.plus_millis(HOUSEKEEPING_EVERY_MS);
        let mut alerts = Vec::new();
        let ended = self.flows.expire(now);
        self.flows_ended(ended, &mut alerts, out);
        self.detectors.expire(now, &mut alerts);
        self.publish(alerts, out);
        self.incidents.expire(now);
        let mut rows = Vec::new();
        self.traffic.flush_if_due(now, &mut rows);
        out.extend(rows.into_iter().map(Output::Traffic));
        self.refresh_flow_counters();
    }

    /// Flushes everything: open flows, open findings, partial traffic counts.
    /// Used at the end of a replay and when the daemon stops.
    pub fn finish(&mut self, out: &mut Vec<Output>) {
        let mut alerts = Vec::new();
        let ended = self.flows.drain();
        self.flows_ended(ended, &mut alerts, out);
        self.detectors.expire(Timestamp(i64::MAX / 2), &mut alerts);
        self.publish(alerts, out);
        let mut rows = Vec::new();
        self.traffic.flush(&mut rows);
        out.extend(rows.into_iter().map(Output::Traffic));
        self.refresh_flow_counters();
    }

    pub fn counters(&self) -> EngineCounters {
        self.counters
    }

    fn count_traffic(
        &mut self,
        ts: Timestamp,
        class: TrafficClass,
        bytes: u32,
        out: &mut Vec<Output>,
    ) {
        let mut rows = Vec::new();
        self.traffic.add(ts, class, bytes, &mut rows);
        out.extend(rows.into_iter().map(Output::Traffic));
    }

    /// Shows finished flows to the detectors, in the order they ended, then
    /// outputs them for storage.
    fn flows_ended(
        &mut self,
        ended: Vec<FlowRecord>,
        alerts: &mut Vec<Alert>,
        out: &mut Vec<Output>,
    ) {
        let mut by_end: Vec<&FlowRecord> = ended.iter().collect();
        by_end.sort_by_key(|flow| flow.last_seen);
        for flow in by_end {
            self.detectors.on_flow_end(flow, alerts);
        }
        out.extend(ended.into_iter().map(Output::Flow));
    }

    /// Links each alert to its incident, then outputs both.
    fn publish(&mut self, alerts: Vec<Alert>, out: &mut Vec<Output>) {
        for mut alert in alerts {
            let incident = self.incidents.on_alert(&alert);
            alert.incident_id = Some(incident.id);
            out.push(Output::Alert(alert));
            out.push(Output::Incident(incident));
        }
    }

    fn refresh_flow_counters(&mut self) {
        let (flows_evicted, flows_full_at) = self.flows.evictions();
        let detectors = self.detectors.evictions();
        self.counters.flows_active = self.flows.active() as u64;
        self.counters.flows_evicted = flows_evicted;
        self.counters.detector_evicted = detectors.count;
        self.counters.saturated_at = flows_full_at.max(detectors.last_at);
    }
}

#[cfg(test)]
#[path = "engine_flood_tests.rs"]
mod flood_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::AlertKind;
    use crate::testutil::{RST_ACK, SYN, tcp_frame};

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
}
