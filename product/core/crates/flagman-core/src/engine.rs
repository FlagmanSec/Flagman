//! The engine wires the pipeline together for one packet at a time:
//! decode, then flow meter, then detectors, then incidents.
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
    pub flows_untracked: u64,
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
                if let Some(start) = self.flows.observe(packet.ts, packet.wire_len, ip_packet) {
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
        out.extend(self.flows.expire(now).into_iter().map(Output::Flow));
        let mut alerts = Vec::new();
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
        out.extend(self.flows.drain().into_iter().map(Output::Flow));
        let mut alerts = Vec::new();
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
        self.counters.flows_active = self.flows.active() as u64;
        self.counters.flows_untracked = self.flows.untracked();
    }
}

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
}
