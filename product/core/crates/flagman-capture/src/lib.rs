//! Packet sources for Flagman.
//!
//! - [`LiveSource`] reads packets from a network interface through libpcap.
//! - [`FileSource`] reads a `.pcap` file, for replay mode and tests.
//!
//! Both implement [`PacketSource`], so the daemon's capture loop does not
//! care where packets come from. Only the first bytes of each packet (the
//! headers) are captured in live mode: see [`LiveOptions::snaplen`].

mod file;
mod live;
pub mod pcap_writer;
mod source;

pub use file::FileSource;
pub use live::{InterfaceInfo, LiveOptions, LiveSource, default_interface, list_interfaces};
pub use source::{CaptureError, CaptureStats, Frame, NextFrame, PacketSource};
