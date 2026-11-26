//! Helpers for tests: build real Ethernet frames, the same bytes a capture would give.

use crate::packet::{LinkType, PacketMeta, TcpFlags, decode};
use crate::time::Timestamp;
use etherparse::PacketBuilder;
use std::net::{IpAddr, Ipv4Addr};

pub const SYN: TcpFlags = TcpFlags {
    syn: true,
    ack: false,
    fin: false,
    rst: false,
};
pub const SYN_ACK: TcpFlags = TcpFlags {
    syn: true,
    ack: true,
    fin: false,
    rst: false,
};
pub const ACK: TcpFlags = TcpFlags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
};
pub const RST: TcpFlags = TcpFlags {
    syn: false,
    ack: false,
    fin: false,
    rst: true,
};
pub const RST_ACK: TcpFlags = TcpFlags {
    syn: false,
    ack: true,
    fin: false,
    rst: true,
};
pub const FIN_ACK: TcpFlags = TcpFlags {
    syn: false,
    ack: true,
    fin: true,
    rst: false,
};

const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

pub fn ip(text: &str) -> IpAddr {
    text.parse().expect("valid IP address in test")
}

fn v4(text: &str) -> [u8; 4] {
    let addr: Ipv4Addr = text.parse().expect("valid IPv4 address in test");
    addr.octets()
}

pub fn tcp_frame(src: &str, src_port: u16, dst: &str, dst_port: u16, flags: TcpFlags) -> Vec<u8> {
    let mut step = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(v4(src), v4(dst), 64)
        .tcp(src_port, dst_port, 1_000, 64_240);
    if flags.syn {
        step = step.syn();
    }
    if flags.ack {
        step = step.ack(1);
    }
    if flags.fin {
        step = step.fin();
    }
    if flags.rst {
        step = step.rst();
    }
    let mut frame = Vec::with_capacity(step.size(0));
    step.write(&mut frame, &[])
        .expect("writing to a Vec cannot fail");
    frame
}

pub fn udp_frame(src: &str, src_port: u16, dst: &str, dst_port: u16) -> Vec<u8> {
    let step = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(v4(src), v4(dst), 64)
        .udp(src_port, dst_port);
    let mut frame = Vec::with_capacity(step.size(4));
    step.write(&mut frame, &[0u8; 4])
        .expect("writing to a Vec cannot fail");
    frame
}

pub fn icmp_echo_frame(src: &str, dst: &str) -> Vec<u8> {
    let step = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(v4(src), v4(dst), 64)
        .icmpv4_echo_request(1, 1);
    let mut frame = Vec::with_capacity(step.size(0));
    step.write(&mut frame, &[])
        .expect("writing to a Vec cannot fail");
    frame
}

/// An ARP request "who has `target`? tell `sender`", built byte by byte.
pub fn arp_request_frame(sender: &str, target: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]); // destination: broadcast
    frame.extend_from_slice(&MAC_A); // source MAC
    frame.extend_from_slice(&[0x08, 0x06]); // EtherType ARP
    frame.extend_from_slice(&[0x00, 0x01]); // hardware type: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // protocol type: IPv4
    frame.extend_from_slice(&[6, 4]); // address sizes
    frame.extend_from_slice(&[0x00, 0x01]); // operation: request
    frame.extend_from_slice(&MAC_A); // sender MAC
    frame.extend_from_slice(&v4(sender)); // sender IP
    frame.extend_from_slice(&[0; 6]); // target MAC (unknown)
    frame.extend_from_slice(&v4(target)); // target IP
    frame
}

/// Decodes an Ethernet frame built by the helpers above, at time `ms`.
pub fn packet_at(ms: i64, frame: &[u8]) -> PacketMeta {
    decode(LinkType::Ethernet, Timestamp(ms), frame.len() as u32, frame)
        .expect("test frames always decode")
}
