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

/// Why the flow meter stopped following a flow. The idea comes from IPFIX,
/// the standard flow export format, which has a field for it
/// (`flowEndReason`, element 136 of the IANA IPFIX registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEnd {
    /// No packet for the idle timeout.
    Idle,
    /// TCP closed the connection: FIN in both directions, or a reset.
    /// This wins over the other reasons: a connection that TCP had already
    /// closed is reported as closed, even if the table let it go early.
    Closed,
    /// It ran longer than the active timeout; what follows is a new record.
    ActiveTimeout,
    /// The table was full and this flow was one of the least recently active,
    /// so it was ended early to make room.
    Evicted,
    /// The replay ended or the sensor stopped while the flow was still open.
    Stopped,
}

impl FlowEnd {
    /// The name used in files and logs, the same as in JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowEnd::Idle => "idle",
            FlowEnd::Closed => "closed",
            FlowEnd::ActiveTimeout => "active_timeout",
            FlowEnd::Evicted => "evicted",
            FlowEnd::Stopped => "stopped",
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
    /// Why the record was closed. Not stored in the database yet.
    pub end: FlowEnd,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_reasons_have_the_same_names_as_in_json() {
        let all = [
            FlowEnd::Idle,
            FlowEnd::Closed,
            FlowEnd::ActiveTimeout,
            FlowEnd::Evicted,
            FlowEnd::Stopped,
        ];
        for end in all {
            let json = serde_json::to_string(&end).unwrap();
            assert_eq!(json, format!("\"{}\"", end.as_str()));
        }
    }
}
