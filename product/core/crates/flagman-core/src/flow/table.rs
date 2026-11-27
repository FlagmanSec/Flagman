//! The flow meter: keeps one entry per live conversation and reports
//! a [`FlowRecord`] when the conversation ends.
//!
//! A flow ends when it has been idle long enough, when TCP closed it (FIN in
//! both directions or a reset), or when it has run for `active_timeout_secs`
//! (long downloads are then reported in pieces, like NetFlow does).
//!
//! When the table is full, a new flow is never refused: the table first ends
//! the least recently active tenth of its flows. A flood of fake connections
//! therefore pushes out other idle entries, not the next real connection.
//!
//! A table can keep extra state next to each flow (see [`FlowExtra`]): the
//! sensor's table keeps nothing (`FlowTable<()>`), the feature builder keeps
//! its statistics there.
//!
//! Flows live in a hash table, whose order changes from one run to the next.
//! Wherever that order could leak out (flows ending at the same time, flows
//! last active in the same millisecond when the table is full), ties are
//! broken by flow key, so the same capture always gives the same flows in
//! the same order.

use super::extra::{FlowExtra, FlowPacket};
use super::key::{Endpoint, FlowKey, Protocol, endpoints_of};
use super::progress::TcpProgress;
use super::record::{FlowEnd, FlowRecord, FlowStart, StartKind};
use crate::packet::{IcmpKind, IpPacket, Transport};
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Timeouts and memory limit of the flow meter.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FlowTableConfig {
    pub tcp_idle_secs: i64,
    pub udp_idle_secs: i64,
    pub other_idle_secs: i64,
    /// How long a closed TCP flow is kept, to absorb the last ACKs.
    pub closed_linger_secs: i64,
    pub active_timeout_secs: i64,
    /// Upper bound on tracked flows, so a flood cannot exhaust memory.
    pub max_flows: usize,
}

impl Default for FlowTableConfig {
    fn default() -> FlowTableConfig {
        FlowTableConfig {
            tcp_idle_secs: 120,
            udp_idle_secs: 60,
            other_idle_secs: 30,
            closed_linger_secs: 5,
            active_timeout_secs: 300,
            max_flows: 100_000,
        }
    }
}

struct FlowState<X> {
    record: FlowRecord,
    tcp: TcpProgress,
    extra: X,
}

impl<X: FlowExtra> FlowState<X> {
    fn add(&mut self, ts: Timestamp, wire_len: u32, forward: bool, packet: &IpPacket) {
        let flags = match packet.transport {
            Transport::Tcp { flags, .. } => Some(flags),
            _ => None,
        };
        self.record.last_seen = self.record.last_seen.max(ts);
        if forward {
            self.record.packets_fwd += 1;
            self.record.bytes_fwd += u64::from(wire_len);
        } else {
            self.record.packets_rev += 1;
            self.record.bytes_rev += u64::from(wire_len);
        }
        if let Some(flags) = flags {
            self.tcp.note(forward, flags);
        }
        let packet = FlowPacket {
            ts,
            forward,
            ip: packet,
            record: &self.record,
        };
        self.extra.add_packet(&packet);
    }

    /// Why the flow should end at `now`, or `None` while it is still alive.
    fn end_reason(&self, now: Timestamp, config: &FlowTableConfig) -> Option<FlowEnd> {
        let idle_limit_secs = match self.record.protocol {
            Protocol::Tcp if self.tcp.is_closed() => config.closed_linger_secs,
            Protocol::Tcp => config.tcp_idle_secs,
            Protocol::Udp => config.udp_idle_secs,
            Protocol::Icmp | Protocol::Other => config.other_idle_secs,
        };
        let idle_ms = now.millis_since(self.record.last_seen);
        let age_ms = now.millis_since(self.record.first_seen);
        if idle_ms >= idle_limit_secs * 1_000 {
            Some(FlowEnd::Idle)
        } else if age_ms >= config.active_timeout_secs * 1_000 {
            Some(FlowEnd::ActiveTimeout)
        } else {
            None
        }
    }

    fn finish(&self, reason: FlowEnd) -> FlowRecord {
        let mut record = self.record;
        record.end = reason;
        if record.protocol == Protocol::Tcp {
            record.tcp_outcome = Some(self.tcp.outcome());
            if self.tcp.is_closed() {
                record.end = FlowEnd::Closed;
            }
        }
        record
    }

    /// Ends the flow: its final record, with the extra state's result.
    fn end(&mut self, reason: FlowEnd) -> X::Finished {
        let record = self.finish(reason);
        std::mem::take(&mut self.extra).finish(record)
    }
}

/// When the table is full, it ends this share of its flows at once (1/10),
/// so the cost of choosing them is paid rarely.
const EVICT_SHARE: usize = 10;

/// The table of live flows, with an `X` kept next to each one.
pub struct FlowTable<X = ()> {
    config: FlowTableConfig,
    flows: HashMap<FlowKey, FlowState<X>>,
    evicted: u64,
    last_eviction: Option<Timestamp>,
}

impl FlowTable<()> {
    /// The sensor's table: nothing extra per flow, finished flows are records.
    pub fn new(config: FlowTableConfig) -> FlowTable<()> {
        FlowTable::with_extra(config)
    }
}

impl<X: FlowExtra> FlowTable<X> {
    /// A table that keeps an `X` next to each flow (see [`FlowExtra`]).
    pub fn with_extra(config: FlowTableConfig) -> FlowTable<X> {
        FlowTable {
            config,
            flows: HashMap::new(),
            evicted: 0,
            last_eviction: None,
        }
    }

    /// Adds one packet. Returns a [`FlowStart`] when the packet opened a new flow.
    ///
    /// When the table is full, the least recently active flows are ended first
    /// to make room; their records are pushed into `ended`.
    pub fn observe(
        &mut self,
        ts: Timestamp,
        wire_len: u32,
        packet: &IpPacket,
        ended: &mut Vec<X::Finished>,
    ) -> Option<FlowStart> {
        let (protocol, src, dst) = endpoints_of(packet);
        let key = FlowKey::new(protocol, src, dst);
        if let Some(state) = self.flows.get_mut(&key) {
            let forward = state.record.initiator == src;
            state.add(ts, wire_len, forward, packet);
            return None;
        }

        let start = FlowStart {
            ts,
            protocol,
            initiator: src,
            responder: dst,
            kind: start_kind(&packet.transport),
        };
        if self.flows.len() >= self.config.max_flows {
            self.make_room(ts, ended);
        }
        let mut state = FlowState {
            record: new_record(ts, protocol, src, dst),
            tcp: TcpProgress::default(),
            extra: X::default(),
        };
        state.add(ts, wire_len, true, packet);
        self.flows.insert(key, state);
        Some(start)
    }

    /// Removes and returns the flows that have ended by `now`, oldest first.
    pub fn expire(&mut self, now: Timestamp) -> Vec<X::Finished> {
        let config = &self.config;
        let mut ended = Vec::new();
        self.flows
            .retain(|key, state| match state.end_reason(now, config) {
                Some(reason) => {
                    ended.push((*key, state.end(reason)));
                    false
                }
                None => true,
            });
        Self::in_start_order(ended)
    }

    /// Removes and returns every flow (used at the end of a replay).
    pub fn drain(&mut self) -> Vec<X::Finished> {
        let ended = self
            .flows
            .drain()
            .map(|(key, mut state)| (key, state.end(FlowEnd::Stopped)))
            .collect();
        Self::in_start_order(ended)
    }

    /// Number of flows being tracked right now.
    pub fn active(&self) -> usize {
        self.flows.len()
    }

    /// Flows ended early because the table was full, and when it last happened.
    pub fn evictions(&self) -> (u64, Option<Timestamp>) {
        (self.evicted, self.last_eviction)
    }

    /// Ends the least recently active tenth of the flows (at least one).
    /// Among flows last active in the same millisecond, the smallest keys
    /// go first.
    fn make_room(&mut self, now: Timestamp, ended: &mut Vec<X::Finished>) {
        let count = (self.config.max_flows / EVICT_SHARE).clamp(1, self.flows.len().max(1));
        let mut by_last_packet: Vec<(Timestamp, FlowKey)> = self
            .flows
            .iter()
            .map(|(key, state)| (state.record.last_seen, *key))
            .collect();
        if count < by_last_packet.len() {
            by_last_packet.select_nth_unstable(count - 1);
            by_last_packet.truncate(count);
        }
        let mut evicted = Vec::with_capacity(by_last_packet.len());
        for (_, key) in by_last_packet {
            if let Some(mut state) = self.flows.remove(&key) {
                evicted.push((key, state.end(FlowEnd::Evicted)));
                self.evicted += 1;
                self.last_eviction = Some(now);
            }
        }
        ended.extend(Self::in_start_order(evicted));
    }

    /// Sorts ended flows by start time, then by key, and drops the keys.
    fn in_start_order(mut ended: Vec<(FlowKey, X::Finished)>) -> Vec<X::Finished> {
        ended.sort_by_key(|(key, flow)| (X::record(flow).first_seen, *key));
        ended.into_iter().map(|(_, flow)| flow).collect()
    }
}

fn new_record(ts: Timestamp, protocol: Protocol, src: Endpoint, dst: Endpoint) -> FlowRecord {
    FlowRecord {
        protocol,
        initiator: src,
        responder: dst,
        first_seen: ts,
        last_seen: ts,
        packets_fwd: 0,
        packets_rev: 0,
        bytes_fwd: 0,
        bytes_rev: 0,
        tcp_outcome: None,
        end: FlowEnd::Idle,
    }
}

fn start_kind(transport: &Transport) -> StartKind {
    match transport {
        Transport::Tcp { flags, .. } if flags.is_connection_request() => StartKind::TcpSyn,
        Transport::Tcp { .. } => StartKind::TcpMidstream,
        Transport::Udp { .. } => StartKind::Udp,
        Transport::Icmp {
            kind: IcmpKind::EchoRequest,
        } => StartKind::IcmpEchoRequest,
        Transport::Icmp { .. } => StartKind::Icmp,
        Transport::Other { .. } => StartKind::Other,
    }
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
