//! Room for extra state next to each flow, updated with every packet.
//!
//! The sensor keeps nothing extra today: its flow table is a
//! `FlowTable<()>`, and [`FlowExtra`] for `()` does nothing. The feature
//! builder (`flagman-features`) keeps its per-flow statistics here instead,
//! so the features of a flow are computed by the same flow table, packet by
//! packet, in live mode and when a capture file is replayed.

use super::record::FlowRecord;
use crate::packet::IpPacket;
use crate::time::Timestamp;

/// One packet, as a flow extension sees it.
#[derive(Clone, Copy, Debug)]
pub struct FlowPacket<'a> {
    pub ts: Timestamp,
    /// True when the packet comes from the flow's initiator.
    pub forward: bool,
    pub ip: &'a IpPacket,
    /// The flow's record, already counting this packet.
    pub record: &'a FlowRecord,
}

/// Extra state kept for each flow. It starts as `Default::default()` when
/// the flow starts.
pub trait FlowExtra: Default {
    /// What the flow table hands out when a flow ends.
    type Finished;

    /// Called for every packet of the flow, the first one included, in the
    /// order the packets arrive.
    fn add_packet(&mut self, packet: &FlowPacket<'_>);

    /// Called once, when the flow ends, with its final record.
    fn finish(self, record: FlowRecord) -> Self::Finished;

    /// The record inside a finished flow.
    fn record(finished: &Self::Finished) -> &FlowRecord;
}

/// No extra state: a finished flow is just its record.
impl FlowExtra for () {
    type Finished = FlowRecord;

    fn add_packet(&mut self, _packet: &FlowPacket<'_>) {}

    fn finish(self, record: FlowRecord) -> FlowRecord {
        record
    }

    fn record(finished: &FlowRecord) -> &FlowRecord {
        finished
    }
}

#[cfg(test)]
#[path = "extra_tests.rs"]
mod tests;
