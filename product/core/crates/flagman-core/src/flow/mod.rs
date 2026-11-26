//! The flow meter: groups packets into conversations ("flows").

mod extra;
mod key;
mod record;
mod table;

pub use extra::{FlowExtra, FlowPacket};
pub use key::{Endpoint, FlowKey, Protocol, endpoints_of};
pub use record::{FlowEnd, FlowRecord, FlowStart, StartKind, TcpOutcome};
pub use table::{FlowTable, FlowTableConfig};
