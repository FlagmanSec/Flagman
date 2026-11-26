//! How packets are matched to flows.
//!
//! A flow is identified by its protocol and its two endpoints (IP + port).
//! Both directions of a conversation must land in the same flow, so the key
//! stores the endpoints in a fixed order ("low" before "high").

use crate::packet::{IpPacket, Transport};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    /// Any other IP protocol (IGMP, GRE, ESP...). Flagman only counts these.
    Other,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Other => "other",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One side of a conversation. The port is 0 for ICMP and other protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// The lookup key of a flow. Built with [`FlowKey::new`] so both directions match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: Protocol,
    pub low: Endpoint,
    pub high: Endpoint,
}

impl FlowKey {
    pub fn new(protocol: Protocol, x: Endpoint, y: Endpoint) -> FlowKey {
        let (low, high) = if x <= y { (x, y) } else { (y, x) };
        FlowKey {
            protocol,
            low,
            high,
        }
    }
}

/// The protocol, source and destination of a packet, as flow endpoints.
pub fn endpoints_of(packet: &IpPacket) -> (Protocol, Endpoint, Endpoint) {
    let (protocol, src_port, dst_port) = match packet.transport {
        Transport::Tcp {
            src_port, dst_port, ..
        } => (Protocol::Tcp, src_port, dst_port),
        Transport::Udp { src_port, dst_port } => (Protocol::Udp, src_port, dst_port),
        Transport::Icmp { .. } => (Protocol::Icmp, 0, 0),
        Transport::Other { .. } => (Protocol::Other, 0, 0),
    };
    let src = Endpoint {
        ip: packet.src,
        port: src_port,
    };
    let dst = Endpoint {
        ip: packet.dst,
        port: dst_port,
    };
    (protocol, src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ip;

    #[test]
    fn both_directions_give_the_same_key() {
        let client = Endpoint {
            ip: ip("192.168.1.50"),
            port: 40_000,
        };
        let server = Endpoint {
            ip: ip("192.168.1.10"),
            port: 22,
        };
        assert_eq!(
            FlowKey::new(Protocol::Tcp, client, server),
            FlowKey::new(Protocol::Tcp, server, client)
        );
        assert_ne!(
            FlowKey::new(Protocol::Tcp, client, server),
            FlowKey::new(Protocol::Udp, client, server)
        );
    }
}
