//! Packet decoding: raw captured bytes in, [`PacketMeta`] out.

mod decode;
mod types;

pub use decode::decode;
pub use types::{
    ArpOperation, ArpPacket, DecodeError, IcmpKind, IpPacket, LinkType, Network, PacketMeta,
    TcpFlags, Transport,
};
