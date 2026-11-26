//! What the flow meter reports: a flow start, and a finished flow record.

use super::key::{Endpoint, Protocol};
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};

/// How the first packet of a flow looked. Detectors only count real
/// connection attempts (for example a TCP SYN), not traffic picked up mid-way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartKind {
    /// TCP SYN without ACK: someone asks to open a connection.
    TcpSyn,
    /// Any other TCP packet: we joined a connection that already existed.
    TcpMidstream,
    Udp,
    IcmpEchoRequest,
    /// Any other ICMP message (replies, errors).
    Icmp,
    Other,
}

/// Emitted the moment a new flow appears. Detectors react to this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowStart {
    pub ts: Timestamp,
    pub protocol: Protocol,
    /// The side that sent the first packet.
    pub initiator: Endpoint,
    pub responder: Endpoint,
    pub kind: StartKind,
}

/// How a TCP conversation turned out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpOutcome {
    /// The three-way handshake completed (SYN, SYN-ACK, ACK).
    Established,
    /// The responder accepted (SYN-ACK) but the initiator never finished the
    /// handshake. Typical of an nmap SYN scan hitting an open port.
    HalfOpen,
    /// The responder refused with a reset: the port is closed.
    Rejected,
    /// The SYN got no answer: the port is filtered or the host is down.
    Unanswered,
    /// We never saw the start of this connection.
    Midstream,
}

impl TcpOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            TcpOutcome::Established => "established",
            TcpOutcome::HalfOpen => "half_open",
            TcpOutcome::Rejected => "rejected",
            TcpOutcome::Unanswered => "unanswered",
            TcpOutcome::Midstream => "midstream",
        }
    }
}

/// A finished flow: who talked to whom, for how long, and how much.
/// "fwd" counts packets from the initiator, "rev" packets from the responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub protocol: Protocol,
    pub initiator: Endpoint,
    pub responder: Endpoint,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    /// Only set for TCP flows.
    pub tcp_outcome: Option<TcpOutcome>,
}
