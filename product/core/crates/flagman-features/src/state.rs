//! The feature builder's state, kept next to each flow by the flow table.
//!
//! `FlowTable<FeatureState>` (from `flagman-core`) calls
//! [`FeatureState::add_packet`] for every packet of a flow, and
//! [`FeatureState::finish`] when the flow ends. Memory per flow is constant,
//! whatever the number of packets: see the crate README for the measurement.

use crate::direction::DirectionStats;
use crate::features::{FeatureFlow, FlowFeatures};
use flagman_core::flow::{FlowExtra, FlowPacket, FlowRecord};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FeatureState {
    fwd: DirectionStats,
    rev: DirectionStats,
    /// Milliseconds from the flow's first packet to the responder's first.
    first_response_ms: Option<u32>,
}

impl FlowExtra for FeatureState {
    type Finished = FeatureFlow;

    fn add_packet(&mut self, packet: &FlowPacket<'_>) {
        if packet.forward {
            self.fwd.add(packet.ts, packet.ip);
            return;
        }
        if self.first_response_ms.is_none() {
            let wait = packet.ts.millis_since(packet.record.first_seen).max(0);
            self.first_response_ms = Some(u32::try_from(wait).unwrap_or(u32::MAX));
        }
        self.rev.add(packet.ts, packet.ip);
    }

    fn finish(self, record: FlowRecord) -> FeatureFlow {
        let first_response = self.first_response_ms.map(u64::from);
        FeatureFlow {
            features: FlowFeatures::new(&record, &self.fwd, &self.rev, first_response),
            record,
        }
    }

    fn record(finished: &FeatureFlow) -> &FlowRecord {
        &finished.record
    }
}
