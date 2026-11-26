//! Builds a small TCP conversation as captured frames, with a knob for each
//! thing a model must NOT learn from: addresses, ports, TTL, the link layer,
//! the clock time and the sender's TCP options.
//!
//! Each test file uses only part of this module, hence `allow(dead_code)`.
#![allow(dead_code)]

use etherparse::{PacketBuilder, TcpOptionElement};
use flagman_core::flow::{FlowTable, FlowTableConfig};
use flagman_core::packet::{LinkType, Network, decode};
use flagman_core::time::Timestamp;
use flagman_features::{FeatureFlow, FeatureState};

#[derive(Clone, Copy, Debug)]
pub enum Link {
    Ethernet,
    /// Ethernet with an 802.1Q VLAN tag (4 more bytes per frame).
    EthernetVlan,
    /// No link header at all.
    RawIp,
    /// Linux "cooked" capture, what `tcpdump -i any` records.
    LinuxCooked,
}

#[derive(Clone, Copy, Debug)]
pub enum Addresses {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

/// How the conversation was captured.
#[derive(Clone, Copy, Debug)]
pub struct Capture {
    pub addresses: Addresses,
    pub client_port: u16,
    pub server_port: u16,
    pub client_ttl: u8,
    pub server_ttl: u8,
    pub link: Link,
    /// Clock time of the first packet, in ms since 1970.
    pub start_ms: i64,
    /// The TCP timestamps option (12 bytes in every TCP header), which Linux
    /// uses by default and Windows does not.
    pub tcp_timestamps: bool,
}

impl Default for Capture {
    fn default() -> Capture {
        Capture {
            addresses: Addresses::V4([192, 168, 1, 50], [192, 168, 1, 10]),
            client_port: 40_000,
            server_port: 22,
            client_ttl: 64,
            server_ttl: 64,
            link: Link::Ethernet,
            start_ms: 1_700_000_000_000,
            tcp_timestamps: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Flags {
    Syn,
    SynAck,
    Ack,
    PshAck,
    FinAck,
}

/// One packet: when (ms after the start), who sent it, its flags, its data.
#[derive(Clone, Copy, Debug)]
pub struct Step {
    pub at_ms: i64,
    pub from_client: bool,
    pub flags: Flags,
    pub data: usize,
}

const fn step(at_ms: i64, from_client: bool, flags: Flags, data: usize) -> Step {
    Step {
        at_ms,
        from_client,
        flags,
        data,
    }
}

/// A short login-like exchange: handshake, a few messages, then a close.
pub const CONVERSATION: [Step; 10] = [
    step(0, true, Flags::Syn, 0),
    step(12, false, Flags::SynAck, 0),
    step(13, true, Flags::Ack, 0),
    step(20, false, Flags::PshAck, 41),
    step(25, true, Flags::PshAck, 41),
    step(40, true, Flags::PshAck, 1_200),
    step(52, false, Flags::PshAck, 600),
    step(90, true, Flags::Ack, 0),
    step(3_100, false, Flags::FinAck, 0),
    step(3_101, true, Flags::FinAck, 0),
];

impl Capture {
    pub fn link_type(&self) -> LinkType {
        match self.link {
            Link::Ethernet | Link::EthernetVlan => LinkType::Ethernet,
            Link::RawIp => LinkType::RawIp,
            Link::LinuxCooked => LinkType::LinuxSll,
        }
    }

    /// The frames of `steps`, with their clock time in ms.
    pub fn frames(&self, steps: &[Step]) -> Vec<(i64, Vec<u8>)> {
        steps
            .iter()
            .map(|step| (self.start_ms + step.at_ms, self.frame(step)))
            .collect()
    }

    fn frame(&self, step: &Step) -> Vec<u8> {
        let (ports, ttl) = if step.from_client {
            ((self.client_port, self.server_port), self.client_ttl)
        } else {
            ((self.server_port, self.client_port), self.server_ttl)
        };
        let ip = match self.addresses {
            Addresses::V4(client, server) => {
                let (src, dst) = if step.from_client {
                    (client, server)
                } else {
                    (server, client)
                };
                PacketBuilder::ipv4(src, dst, ttl)
            }
            Addresses::V6(client, server) => {
                let (src, dst) = if step.from_client {
                    (client, server)
                } else {
                    (server, client)
                };
                PacketBuilder::ipv6(src, dst, ttl)
            }
        };
        let mut tcp = ip.tcp(ports.0, ports.1, 1_000, 64_240);
        tcp = match step.flags {
            Flags::Syn => tcp.syn(),
            Flags::SynAck => tcp.syn().ack(1),
            Flags::Ack => tcp.ack(1),
            Flags::PshAck => tcp.psh().ack(1),
            Flags::FinAck => tcp.fin().ack(1),
        };
        if self.tcp_timestamps {
            let options = [
                TcpOptionElement::Noop,
                TcpOptionElement::Noop,
                TcpOptionElement::Timestamp(7, 8),
            ];
            tcp = tcp.options(&options).expect("12 bytes of options fit");
        }
        let mut packet = Vec::new();
        tcp.write(&mut packet, &vec![0x61; step.data])
            .expect("writing to a Vec cannot fail");
        let ether_type: [u8; 2] = match self.addresses {
            Addresses::V4(..) => [0x08, 0x00],
            Addresses::V6(..) => [0x86, 0xdd],
        };
        let mut frame = match self.link {
            Link::RawIp => Vec::new(),
            Link::Ethernet => [[2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]].concat(),
            Link::EthernetVlan => [
                &[2, 0, 0, 0, 0, 1][..],
                &[2, 0, 0, 0, 0, 2],
                &[0x81, 0x00, 0x00, 0x0a],
            ]
            .concat(),
            // Packet type, ARP hardware type, address length, address (8 bytes).
            Link::LinuxCooked => [&[0, 0, 0, 1, 0, 6][..], &[2, 0, 0, 0, 0, 1, 0, 0]].concat(),
        };
        if !matches!(self.link, Link::RawIp) {
            frame.extend_from_slice(&ether_type);
        }
        frame.extend_from_slice(&packet);
        frame
    }
}

/// Runs the frames of `steps` through the real decoder and a
/// `FlowTable<FeatureState>`.
pub fn features_of(capture: &Capture, steps: &[Step]) -> Vec<FeatureFlow> {
    run(capture.link_type(), capture.frames(steps))
}

/// Runs frames (clock time in ms, bytes) through the decoder and the table.
pub fn run(link: LinkType, frames: Vec<(i64, Vec<u8>)>) -> Vec<FeatureFlow> {
    let mut table: FlowTable<FeatureState> = FlowTable::with_extra(FlowTableConfig::default());
    let mut ended = Vec::new();
    for (ms, frame) in frames {
        let meta =
            decode(link, Timestamp(ms), frame.len() as u32, &frame).expect("test frames decode");
        if let Network::Ip(ip) = meta.network {
            table.observe(meta.ts, meta.wire_len, &ip, &mut ended);
        }
    }
    ended.extend(table.drain());
    ended
}

/// The features of the one flow in `steps`.
pub fn one_flow(capture: &Capture, steps: &[Step]) -> FeatureFlow {
    let mut flows = features_of(capture, steps);
    assert_eq!(flows.len(), 1, "expected one flow");
    flows.remove(0)
}
