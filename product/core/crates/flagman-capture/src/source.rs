//! The interface every packet source implements.

use flagman_core::packet::LinkType;
use flagman_core::time::Timestamp;

/// One captured packet. `data` may be shorter than `wire_len` when only the
/// headers were captured.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub ts: Timestamp,
    pub wire_len: u32,
    pub data: &'a [u8],
}

/// What asking a source for the next packet can give.
#[derive(Debug)]
pub enum NextFrame<'a> {
    Packet(Frame<'a>),
    /// Live capture only: no packet arrived within the read timeout.
    /// The caller uses this pause to run timeouts and update its health.
    Timeout,
    /// File only: the file has no more packets.
    End,
}

/// Counters reported by the kernel for a live capture.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureStats {
    pub received: u64,
    /// Packets lost because Flagman did not read them fast enough.
    pub dropped: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("could not open {target}: {message}")]
    Open { target: String, message: String },
    #[error("unsupported link type {0}: Flagman reads Ethernet, Linux cooked and raw IP captures")]
    UnsupportedLink(i32),
    #[error("reading packets failed: {0}")]
    Read(String),
}

pub trait PacketSource {
    /// How the captured bytes start (Ethernet header, cooked header...).
    fn link_type(&self) -> LinkType;

    /// Waits for the next packet (live) or reads it (file).
    fn next_frame(&mut self) -> Result<NextFrame<'_>, CaptureError>;

    /// Kernel counters, for live captures. Files return `None`.
    fn stats(&mut self) -> Option<CaptureStats>;

    /// A short name for the dashboard: the interface or the file name.
    fn describe(&self) -> String;
}

/// Converts libpcap's capture time to a [`Timestamp`]. The `timeval` field
/// types differ between platforms (32 or 64 bits), so the conversion lives
/// in one place.
#[allow(clippy::useless_conversion)]
pub(crate) fn timestamp_of(header: &pcap::PacketHeader) -> Timestamp {
    Timestamp::from_secs_micros(i64::from(header.ts.tv_sec), i64::from(header.ts.tv_usec))
}
