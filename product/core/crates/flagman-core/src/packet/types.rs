//! The decoded view of one packet. Only headers are kept, never payload.

use crate::time::Timestamp;
use std::net::{IpAddr, Ipv4Addr};

/// How the captured bytes start, as reported by libpcap ("data link type").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet II frames: the usual case for a wired or Wi-Fi interface.
    Ethernet,
    /// Linux "cooked" capture v1, used when capturing on the `any` interface.
    LinuxSll,
    /// Linux "cooked" capture v2.
    LinuxSll2,
    /// Raw IP packets with no link header (VPN and tunnel interfaces).
    RawIp,
}

impl LinkType {
    /// Maps a libpcap DLT/LINKTYPE number to a link type Flagman understands.
    pub fn from_dlt(dlt: i32) -> Option<LinkType> {
        match dlt {
            1 => Some(LinkType::Ethernet),
            113 => Some(LinkType::LinuxSll),
            276 => Some(LinkType::LinuxSll2),
            12 | 14 | 101 | 228 | 229 => Some(LinkType::RawIp),
            _ => None,
        }
    }
}

/// The TCP flags that matter for detection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpFlags {
    /// A connection request: SYN without ACK. This is what a port scanner sends.
    pub fn is_connection_request(self) -> bool {
        self.syn && !self.ack
    }
}

/// The ICMP messages that matter for detection (IPv4 and IPv6 mapped together).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKind {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    Other { icmp_type: u8, code: u8 },
}

/// The transport layer: TCP, UDP, ICMP or something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: TcpFlags,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    Icmp {
        kind: IcmpKind,
    },
    /// Any other IP protocol, or a fragment without a transport header.
    Other {
        protocol: u8,
    },
}

/// An IPv4 or IPv6 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport,
    /// IPv4 time-to-live or IPv6 hop limit. The detectors ignore it; the
    /// feature builder only notes whether it changes inside a flow, because
    /// the raw value says which system sent the packet and how many routers
    /// it crossed: a classic lab shortcut.
    pub ttl: u8,
    /// Bytes of application data after the IP and transport headers, read
    /// from the headers' length fields, so it is right even when the capture
    /// kept only the first bytes of the packet.
    pub payload_len: u32,
}

/// ARP request ("who has 192.168.1.7?") or reply ("192.168.1.7 is at aa:bb:...").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Other,
}

/// An ARP packet for IPv4 over Ethernet, the only kind found on home networks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

/// What the network layer of a packet contained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Ip(IpPacket),
    Arp(ArpPacket),
}

/// One decoded packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketMeta {
    pub ts: Timestamp,
    /// Size of the packet on the wire, even if only its first bytes were captured.
    pub wire_len: u32,
    pub network: Network,
}

/// Why a packet could not be decoded. These packets are counted, not analysed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The captured bytes end before the headers do.
    Truncated,
    /// Neither IP nor ARP (for example LLDP or a spanning-tree frame).
    OtherProtocol,
}
