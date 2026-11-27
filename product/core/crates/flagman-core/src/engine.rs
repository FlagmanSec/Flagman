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
//!
//! The sensor's engine is an `Engine<()>`, made with [`Engine::new`].
//! `flagmand extract` makes an `Engine<FeatureState>` with
//! [`Engine::with_extra`]: the flow table then also computes each flow's
//! features (see [`FlowExtra`]), and everything else runs exactly as in the
//! sensor.

use crate::alert::Alert;
use crate::detect::{DetectConfig, Detectors, SignatureHit};
use crate::flow::{FlowExtra, FlowRecord, FlowTable, FlowTableConfig};
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

/// Everything the engine produces. `F` is a finished flow: a [`FlowRecord`]
/// in the sensor, a record with its features in `flagmand extract`.
#[derive(Clone, Debug, PartialEq)]
pub enum Output<F = FlowRecord> {
    Flow(F),
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

/// What the engine outputs when its flow table keeps an `X` per flow.
type Outputs<X> = Vec<Output<<X as FlowExtra>::Finished>>;

pub struct Engine<X = ()> {
    flows: FlowTable<X>,
    detectors: Detectors,
    incidents: IncidentEngine,
    traffic: TrafficCounter,
    counters: EngineCounters,
    next_housekeeping: Timestamp,
}

impl Engine<()> {
    /// The sensor's engine: finished flows are plain records.
    pub fn new(config: &EngineConfig, ids: StartIds) -> Engine<()> {
        Engine::with_extra(config, ids)
    }
}

impl<X: FlowExtra> Engine<X> {
    /// An engine whose flow table keeps an `X` next to each flow.
    pub fn with_extra(config: &EngineConfig, ids: StartIds) -> Engine<X> {
        Engine {
            flows: FlowTable::with_extra(config.flows.clone()),
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
        out: &mut Outputs<X>,
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

    fn process_packet(&mut self, packet: &PacketMeta, out: &mut Outputs<X>) {
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
    pub fn process_signature(&mut self, hit: SignatureHit, out: &mut Outputs<X>) {
        let mut alerts = Vec::new();
        self.detectors.on_signature(hit, &mut alerts);
        self.publish(alerts, out);
    }

    /// Runs timeouts. Called after each packet, and by the daemon with the
    /// wall-clock time when no packet arrives.
    pub fn tick(&mut self, now: Timestamp, out: &mut Outputs<X>) {
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
    pub fn finish(&mut self, out: &mut Outputs<X>) {
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
        out: &mut Outputs<X>,
    ) {
        let mut rows = Vec::new();
        self.traffic.add(ts, class, bytes, &mut rows);
        out.extend(rows.into_iter().map(Output::Traffic));
    }

    /// Shows finished flows to the detectors, in the order they ended, then
    /// outputs them for storage.
    fn flows_ended(
        &mut self,
        ended: Vec<X::Finished>,
        alerts: &mut Vec<Alert>,
        out: &mut Outputs<X>,
    ) {
        let mut by_end: Vec<&FlowRecord> = ended.iter().map(X::record).collect();
        by_end.sort_by_key(|flow| flow.last_seen);
        for flow in by_end {
            self.detectors.on_flow_end(flow, alerts);
        }
        out.extend(ended.into_iter().map(Output::Flow));
    }

    /// Links each alert to its incident, then outputs both.
    fn publish(&mut self, alerts: Vec<Alert>, out: &mut Outputs<X>) {
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
#[path = "engine_tests.rs"]
mod tests;
