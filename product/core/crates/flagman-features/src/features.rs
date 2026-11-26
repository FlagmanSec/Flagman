//! The finished feature vector of one flow.
//!
//! Every value here is computed from the flow's packets, never from who
//! sent them or when: no address, no exact port, no clock time, no raw TTL.
//! The schema ([`crate::schema`]) gives each value its name, unit and type.

use crate::direction::DirectionStats;
use crate::port_class::PortClass;
use flagman_core::flow::{FlowRecord, Protocol, TcpOutcome};

/// The statistics of one side of the flow. Values are `None` when they are
/// not defined: sizes when that side sent nothing, gaps when it sent fewer
/// than two packets.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SideFeatures {
    pub packets: u64,
    pub payload_bytes: u64,
    pub payload_min: Option<u32>,
    pub payload_max: Option<u32>,
    pub payload_mean: Option<f64>,
    pub payload_std: Option<f64>,
    pub gap_min_ms: Option<u32>,
    pub gap_max_ms: Option<u32>,
    pub gap_mean_ms: Option<f64>,
    pub gap_std_ms: Option<f64>,
    pub syn: u16,
    pub fin: u16,
    pub rst: u16,
    pub empty_packets: u32,
    pub ttl_changed: bool,
}

impl SideFeatures {
    fn from_stats(packets: u64, side: &DirectionStats) -> SideFeatures {
        SideFeatures {
            packets,
            payload_bytes: side.payload_bytes,
            payload_min: side.payload.min(),
            payload_max: side.payload.max(),
            payload_mean: side.payload.mean(),
            payload_std: side.payload.std(),
            gap_min_ms: side.gaps.min(),
            gap_max_ms: side.gaps.max(),
            gap_mean_ms: side.gaps.mean(),
            gap_std_ms: side.gaps.std(),
            syn: side.syn,
            fin: side.fin,
            rst: side.rst,
            empty_packets: side.empty,
            ttl_changed: side.ttl_changed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FlowFeatures {
    pub protocol: Protocol,
    /// The responder's port, as a class.
    pub dst_port_class: PortClass,
    /// `None` for flows that are not TCP.
    pub tcp_outcome: Option<TcpOutcome>,
    pub duration_ms: u64,
    /// From the initiator.
    pub fwd: SideFeatures,
    /// From the responder.
    pub rev: SideFeatures,
    /// The responder's share of the packets, from 0 to 1.
    pub packets_share_rev: f64,
    /// The responder's share of the data bytes; `None` when there were none.
    pub payload_share_rev: Option<f64>,
    /// From the first packet to the responder's first packet; `None` when
    /// the responder never sent anything.
    pub first_response_ms: Option<u64>,
}

impl FlowFeatures {
    pub fn new(
        record: &FlowRecord,
        fwd: &DirectionStats,
        rev: &DirectionStats,
        first_response_ms: Option<u64>,
    ) -> FlowFeatures {
        let fwd = SideFeatures::from_stats(record.packets_fwd, fwd);
        let rev = SideFeatures::from_stats(record.packets_rev, rev);
        let duration = record.last_seen.millis_since(record.first_seen).max(0);
        FlowFeatures {
            protocol: record.protocol,
            dst_port_class: PortClass::of(record.protocol, record.responder.port),
            tcp_outcome: record.tcp_outcome,
            duration_ms: u64::try_from(duration).unwrap_or(0),
            packets_share_rev: share(rev.packets, fwd.packets).unwrap_or(0.0),
            payload_share_rev: share(rev.payload_bytes, fwd.payload_bytes),
            first_response_ms,
            fwd,
            rev,
        }
    }
}

/// `part / (part + other)`, or `None` when both are 0.
fn share(part: u64, other: u64) -> Option<f64> {
    let total = part as f64 + other as f64;
    (total > 0.0).then(|| part as f64 / total)
}

/// A finished flow: its record (who, when, how it ended), kept for
/// labelling and splitting, and its features, the only model inputs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FeatureFlow {
    pub record: FlowRecord,
    pub features: FlowFeatures,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_are_between_zero_and_one() {
        assert_eq!(share(1, 3), Some(0.25));
        assert_eq!(share(0, 5), Some(0.0));
        assert_eq!(share(0, 0), None);
    }
}
