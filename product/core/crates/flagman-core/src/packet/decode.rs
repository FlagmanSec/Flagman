//! Turns captured bytes into a [`PacketMeta`].
//!
//! Parsing is done by the `etherparse` crate in its "lax" mode, which accepts
//! packets that were cut short by the capture length (we only capture headers).
//! Nothing here can panic on hostile input: every length is checked by
//! etherparse or by `try_into`, and errors are returned as [`DecodeError`].

use super::lengths::payload_len;
use super::types::{
    ArpOperation, ArpPacket, DecodeError, IcmpKind, IpPacket, LinkType, Network, PacketMeta,
    TcpFlags, Transport,
};
use crate::time::Timestamp;
use etherparse::{
    ArpHardwareId, ArpPacketSlice, EtherType, LaxNetSlice, LaxSlicedPacket, TransportSlice,
};
use std::net::Ipv4Addr;

/// Decodes one captured frame.
pub fn decode(
    link: LinkType,
    ts: Timestamp,
    wire_len: u32,
    data: &[u8],
) -> Result<PacketMeta, DecodeError> {
    let LaxSlicedPacket {
        net,
        transport,
        stop_err,
        ..
    } = slice_by_link_type(link, data)?;
    // Bytes of the frame that the capture did not keep.
    let cut_off = usize::try_from(wire_len)
        .unwrap_or(usize::MAX)
        .saturating_sub(data.len());

    let network = match &net {
        Some(net @ LaxNetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            Network::Ip(IpPacket {
                src: header.source_addr().into(),
                dst: header.destination_addr().into(),
                transport: transport_of(transport.as_ref(), ipv4.payload().ip_number.0),
                ttl: header.ttl(),
                payload_len: payload_len(net, transport.as_ref(), cut_off),
            })
        }
        Some(net @ LaxNetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            Network::Ip(IpPacket {
                src: header.source_addr().into(),
                dst: header.destination_addr().into(),
                transport: transport_of(transport.as_ref(), ipv6.payload().ip_number.0),
                ttl: header.hop_limit(),
                payload_len: payload_len(net, transport.as_ref(), cut_off),
            })
        }
        Some(LaxNetSlice::Arp(arp)) => Network::Arp(arp_of(arp)?),
        None if stop_err.is_some() => return Err(DecodeError::Truncated),
        None => return Err(DecodeError::OtherProtocol),
    };

    Ok(PacketMeta {
        ts,
        wire_len,
        network,
    })
}

fn slice_by_link_type(link: LinkType, data: &[u8]) -> Result<LaxSlicedPacket<'_>, DecodeError> {
    match link {
        LinkType::Ethernet => {
            LaxSlicedPacket::from_ethernet(data).map_err(|_| DecodeError::Truncated)
        }
        // Cooked v1: 16-byte header, protocol (EtherType) in bytes 14-15.
        LinkType::LinuxSll => slice_cooked(data, 16, 14),
        // Cooked v2: 20-byte header, protocol (EtherType) in bytes 0-1.
        LinkType::LinuxSll2 => slice_cooked(data, 20, 0),
        LinkType::RawIp => LaxSlicedPacket::from_ip(data).map_err(|error| match error {
            etherparse::err::ip::LaxHeaderSliceError::Len(_) => DecodeError::Truncated,
            etherparse::err::ip::LaxHeaderSliceError::Content(_) => DecodeError::OtherProtocol,
        }),
    }
}

fn slice_cooked(
    data: &[u8],
    header_len: usize,
    protocol_offset: usize,
) -> Result<LaxSlicedPacket<'_>, DecodeError> {
    if data.len() < header_len {
        return Err(DecodeError::Truncated);
    }
    let ether_type = u16::from_be_bytes([data[protocol_offset], data[protocol_offset + 1]]);
    Ok(LaxSlicedPacket::from_ether_type(
        EtherType(ether_type),
        &data[header_len..],
    ))
}

fn transport_of(transport: Option<&TransportSlice<'_>>, ip_protocol: u8) -> Transport {
    match transport {
        Some(TransportSlice::Tcp(tcp)) => Transport::Tcp {
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            flags: TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            },
        },
        Some(TransportSlice::Udp(udp)) => Transport::Udp {
            src_port: udp.source_port(),
            dst_port: udp.destination_port(),
        },
        Some(TransportSlice::Icmpv4(icmp)) => Transport::Icmp {
            kind: icmp_kind(icmp.type_u8(), icmp.code_u8(), IcmpNumbers::V4),
        },
        Some(TransportSlice::Icmpv6(icmp)) => Transport::Icmp {
            kind: icmp_kind(icmp.type_u8(), icmp.code_u8(), IcmpNumbers::V6),
        },
        _ => Transport::Other {
            protocol: ip_protocol,
        },
    }
}

/// ICMP type numbers differ between IPv4 and IPv6.
struct IcmpNumbers {
    echo_request: u8,
    echo_reply: u8,
    unreachable: u8,
}

impl IcmpNumbers {
    const V4: IcmpNumbers = IcmpNumbers {
        echo_request: 8,
        echo_reply: 0,
        unreachable: 3,
    };
    const V6: IcmpNumbers = IcmpNumbers {
        echo_request: 128,
        echo_reply: 129,
        unreachable: 1,
    };
}

fn icmp_kind(icmp_type: u8, code: u8, numbers: IcmpNumbers) -> IcmpKind {
    if icmp_type == numbers.echo_request {
        IcmpKind::EchoRequest
    } else if icmp_type == numbers.echo_reply {
        IcmpKind::EchoReply
    } else if icmp_type == numbers.unreachable {
        IcmpKind::DestinationUnreachable
    } else {
        IcmpKind::Other { icmp_type, code }
    }
}

fn arp_of(arp: &ArpPacketSlice<'_>) -> Result<ArpPacket, DecodeError> {
    let is_ethernet_ipv4 =
        arp.hw_addr_type() == ArpHardwareId::ETHERNET && arp.proto_addr_type() == EtherType::IPV4;
    if !is_ethernet_ipv4 {
        return Err(DecodeError::OtherProtocol);
    }
    let operation = match arp.operation() {
        op if op == etherparse::ArpOperation::REQUEST => ArpOperation::Request,
        op if op == etherparse::ArpOperation::REPLY => ArpOperation::Reply,
        _ => ArpOperation::Other,
    };
    let sender_mac: [u8; 6] = arp
        .sender_hw_addr()
        .try_into()
        .map_err(|_| DecodeError::OtherProtocol)?;
    Ok(ArpPacket {
        operation,
        sender_mac,
        sender_ip: ipv4_from(arp.sender_protocol_addr())?,
        target_ip: ipv4_from(arp.target_protocol_addr())?,
    })
}

fn ipv4_from(bytes: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    let octets: [u8; 4] = bytes.try_into().map_err(|_| DecodeError::OtherProtocol)?;
    Ok(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{SYN, arp_request_frame, icmp_echo_frame, ip, tcp_frame, udp_frame};

    fn decode_ethernet(frame: &[u8]) -> Result<PacketMeta, DecodeError> {
        decode(
            LinkType::Ethernet,
            Timestamp(1_000),
            frame.len() as u32,
            frame,
        )
    }

    #[test]
    fn decodes_a_tcp_syn() {
        let frame = tcp_frame("192.168.1.50", 40_000, "192.168.1.10", 22, SYN);
        let packet = decode_ethernet(&frame).unwrap();
        let Network::Ip(ip_packet) = packet.network else {
            panic!("expected an IP packet");
        };
        assert_eq!(ip_packet.src, ip("192.168.1.50"));
        assert_eq!(ip_packet.dst, ip("192.168.1.10"));
        assert_eq!(
            ip_packet.transport,
            Transport::Tcp {
                src_port: 40_000,
                dst_port: 22,
                flags: SYN
            }
        );
    }

    #[test]
    fn decodes_udp_and_icmp() {
        let udp = decode_ethernet(&udp_frame("10.0.0.2", 5353, "10.0.0.3", 53)).unwrap();
        assert!(matches!(
            udp.network,
            Network::Ip(IpPacket {
                transport: Transport::Udp { dst_port: 53, .. },
                ..
            })
        ));
        let icmp = decode_ethernet(&icmp_echo_frame("10.0.0.2", "10.0.0.3")).unwrap();
        assert!(matches!(
            icmp.network,
            Network::Ip(IpPacket {
                transport: Transport::Icmp {
                    kind: IcmpKind::EchoRequest
                },
                ..
            })
        ));
    }

    #[test]
    fn decodes_an_arp_request() {
        let frame = arp_request_frame("192.168.1.50", "192.168.1.77");
        let packet = decode_ethernet(&frame).unwrap();
        let Network::Arp(arp) = packet.network else {
            panic!("expected ARP");
        };
        assert_eq!(arp.operation, ArpOperation::Request);
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 77));
    }

    #[test]
    fn decodes_linux_cooked_capture() {
        let ethernet = tcp_frame("192.168.1.50", 40_000, "192.168.1.10", 80, SYN);
        // Replace the 14-byte Ethernet header with a 16-byte SLL header.
        let mut cooked = vec![0u8; 14];
        cooked.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        cooked.extend_from_slice(&ethernet[14..]);
        let packet = decode(LinkType::LinuxSll, Timestamp(0), 60, &cooked).unwrap();
        assert!(matches!(packet.network, Network::Ip(_)));
    }

    #[test]
    fn reports_truncated_and_foreign_frames_without_panicking() {
        assert_eq!(decode_ethernet(&[0u8; 6]), Err(DecodeError::Truncated));
        let mut lldp = vec![0u8; 12];
        lldp.extend_from_slice(&[0x88, 0xcc]); // EtherType LLDP
        lldp.extend_from_slice(&[0u8; 30]);
        assert_eq!(decode_ethernet(&lldp), Err(DecodeError::OtherProtocol));
        // Random bytes must never crash the decoder.
        for length in 0..80 {
            let noise: Vec<u8> = (0..length).map(|i| (i * 37 % 251) as u8).collect();
            let _ = decode_ethernet(&noise);
            let _ = decode(LinkType::RawIp, Timestamp(0), length as u32, &noise);
        }
    }
}
