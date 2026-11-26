//! The flow meter: keeps one entry per live conversation and reports
//! a [`FlowRecord`] when the conversation ends.
//!
//! A flow ends when it has been idle long enough, when TCP closed it (FIN in
//! both directions or a reset), or when it has run for `active_timeout_secs`
//! (long downloads are then reported in pieces, like NetFlow does).

use super::key::{Endpoint, FlowKey, Protocol, endpoints_of};
use super::record::{FlowRecord, FlowStart, StartKind, TcpOutcome};
use crate::packet::{IcmpKind, IpPacket, TcpFlags, Transport};
use crate::time::Timestamp;
use serde::Deserialize;
use std::collections::HashMap;

/// Timeouts and memory limit of the flow meter.
#[derive(Clone, Debug, PartialEq, Deserialize)]
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

/// What TCP flags we have seen so far in a flow.
#[derive(Clone, Copy, Debug, Default)]
struct TcpProgress {
    syn_fwd: bool,
    syn_ack_rev: bool,
    ack_fwd: bool,
    fin_fwd: bool,
    fin_rev: bool,
    rst_fwd: bool,
    rst_rev: bool,
}

impl TcpProgress {
    fn note(&mut self, forward: bool, flags: TcpFlags) {
        if forward {
            self.syn_fwd |= flags.is_connection_request();
            // A plain ACK from the initiator completes the handshake.
            self.ack_fwd |= flags.ack && !flags.syn && !flags.rst;
            self.fin_fwd |= flags.fin;
            self.rst_fwd |= flags.rst;
        } else {
            self.syn_ack_rev |= flags.syn && flags.ack;
            self.fin_rev |= flags.fin;
            self.rst_rev |= flags.rst;
        }
    }

    fn is_closed(&self) -> bool {
        self.rst_fwd || self.rst_rev || (self.fin_fwd && self.fin_rev)
    }

    fn outcome(&self) -> TcpOutcome {
        if !self.syn_fwd {
            TcpOutcome::Midstream
        } else if self.syn_ack_rev && self.ack_fwd {
            TcpOutcome::Established
        } else if self.syn_ack_rev {
            TcpOutcome::HalfOpen
        } else if self.rst_rev {
            TcpOutcome::Rejected
        } else {
            TcpOutcome::Unanswered
        }
    }
}

struct FlowState {
    record: FlowRecord,
    tcp: TcpProgress,
}

impl FlowState {
    fn add(&mut self, ts: Timestamp, wire_len: u32, forward: bool, flags: Option<TcpFlags>) {
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
    }

    fn has_ended(&self, now: Timestamp, config: &FlowTableConfig) -> bool {
        let idle_limit_secs = match self.record.protocol {
            Protocol::Tcp if self.tcp.is_closed() => config.closed_linger_secs,
            Protocol::Tcp => config.tcp_idle_secs,
            Protocol::Udp => config.udp_idle_secs,
            Protocol::Icmp | Protocol::Other => config.other_idle_secs,
        };
        let idle_ms = now.millis_since(self.record.last_seen);
        let age_ms = now.millis_since(self.record.first_seen);
        idle_ms >= idle_limit_secs * 1_000 || age_ms >= config.active_timeout_secs * 1_000
    }

    fn finish(&self) -> FlowRecord {
        let mut record = self.record;
        if record.protocol == Protocol::Tcp {
            record.tcp_outcome = Some(self.tcp.outcome());
        }
        record
    }
}

/// The table of live flows.
pub struct FlowTable {
    config: FlowTableConfig,
    flows: HashMap<FlowKey, FlowState>,
    untracked: u64,
}

impl FlowTable {
    pub fn new(config: FlowTableConfig) -> FlowTable {
        FlowTable {
            config,
            flows: HashMap::new(),
            untracked: 0,
        }
    }

    /// Adds one packet. Returns a [`FlowStart`] when the packet opened a new flow.
    ///
    /// When the table is full the packet is not tracked, but the start is still
    /// returned, so a flood cannot hide a scan from the detectors.
    pub fn observe(
        &mut self,
        ts: Timestamp,
        wire_len: u32,
        packet: &IpPacket,
    ) -> Option<FlowStart> {
        let (protocol, src, dst) = endpoints_of(packet);
        let flags = match packet.transport {
            Transport::Tcp { flags, .. } => Some(flags),
            _ => None,
        };
        let key = FlowKey::new(protocol, src, dst);
        if let Some(state) = self.flows.get_mut(&key) {
            let forward = state.record.initiator == src;
            state.add(ts, wire_len, forward, flags);
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
            self.untracked += 1;
            return Some(start);
        }
        let mut state = FlowState {
            record: new_record(ts, protocol, src, dst),
            tcp: TcpProgress::default(),
        };
        state.add(ts, wire_len, true, flags);
        self.flows.insert(key, state);
        Some(start)
    }

    /// Removes and returns the flows that have ended by `now`, oldest first.
    pub fn expire(&mut self, now: Timestamp) -> Vec<FlowRecord> {
        let config = &self.config;
        let mut ended = Vec::new();
        self.flows.retain(|_, state| {
            if state.has_ended(now, config) {
                ended.push(state.finish());
                false
            } else {
                true
            }
        });
        ended.sort_by_key(|record| record.first_seen);
        ended
    }

    /// Removes and returns every flow (used at the end of a replay).
    pub fn drain(&mut self) -> Vec<FlowRecord> {
        let mut ended: Vec<FlowRecord> = self.flows.values().map(FlowState::finish).collect();
        self.flows.clear();
        ended.sort_by_key(|record| record.first_seen);
        ended
    }

    /// Number of flows being tracked right now.
    pub fn active(&self) -> usize {
        self.flows.len()
    }

    /// Number of new flows that were not tracked because the table was full.
    pub fn untracked(&self) -> u64 {
        self.untracked
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
