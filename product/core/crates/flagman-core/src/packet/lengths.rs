//! How many bytes of application data a packet carries.
//!
//! Flagman keeps only the first 160 bytes of each packet, so the data itself
//! is usually cut off. Its size is still known: the IP header says how long
//! the packet is, and the TCP header how long the TCP header is. Counting
//! data bytes instead of whole frames gives the same number whatever the link
//! layer (Ethernet, Linux "cooked" capture, VLAN tags) and whatever TCP
//! options the sender's system adds. The feature builder relies on this.

use etherparse::{LaxNetSlice, TransportSlice};

/// UDP headers are 8 bytes, and so are ICMP headers for the common messages
/// (echo, unreachable, time exceeded).
const SHORT_HEADER: usize = 8;

/// Data bytes after the IP and transport headers.
///
/// `cut_off` is how many bytes of the frame the capture dropped. It is only
/// used when the IP length field cannot be trusted (0, or smaller than the
/// header, as in some captures taken on the sending machine).
pub(super) fn payload_len(
    net: &LaxNetSlice<'_>,
    transport: Option<&TransportSlice<'_>>,
    cut_off: usize,
) -> u32 {
    let transport_header = match transport {
        Some(TransportSlice::Tcp(tcp)) => tcp.header_slice().len(),
        Some(TransportSlice::Udp(_) | TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_)) => {
            SHORT_HEADER
        }
        _ => 0,
    };
    let data = ip_payload_len(net, cut_off).saturating_sub(transport_header);
    u32::try_from(data).unwrap_or(u32::MAX)
}

/// Bytes after the IP header and its extension headers.
fn ip_payload_len(net: &LaxNetSlice<'_>, cut_off: usize) -> usize {
    match net {
        LaxNetSlice::Ipv4(ipv4) => {
            let auth = ipv4.extensions().auth.map_or(0, |auth| auth.slice().len());
            let headers = ipv4.header().slice().len() + auth;
            let total = usize::from(ipv4.header().total_len());
            if total >= headers {
                total - headers
            } else {
                ipv4.payload().payload.len() + cut_off
            }
        }
        LaxNetSlice::Ipv6(ipv6) => {
            // Counts everything after the fixed 40-byte header. 0 means a
            // "jumbogram" or a capture taken before the network card split
            // the data: the real size is then unknown from the header.
            let after_fixed = usize::from(ipv6.header().payload_length());
            let extensions = ipv6.extensions().slice().len();
            if after_fixed > 0 && after_fixed >= extensions {
                after_fixed - extensions
            } else {
                ipv6.payload().payload.len() + cut_off
            }
        }
        LaxNetSlice::Arp(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{LinkType, Network, decode};
    use crate::time::Timestamp;
    use etherparse::PacketBuilder;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const A: [u8; 4] = [192, 168, 1, 50];
    const B: [u8; 4] = [192, 168, 1, 10];

    fn write(step: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut frame = Vec::new();
        step(&mut frame);
        frame
    }

    fn tcp_with(data: &[u8], ttl: u8) -> Vec<u8> {
        write(|frame| {
            PacketBuilder::ethernet2(MAC, MAC)
                .ipv4(A, B, ttl)
                .tcp(40_000, 443, 1, 64_240)
                .ack(1)
                .write(frame, data)
                .unwrap();
        })
    }

    /// Decodes the first `captured` bytes of `frame`, as a capture with a
    /// short snap length would, and returns (data bytes, TTL).
    fn seen(frame: &[u8], captured: usize) -> (u32, u8) {
        let kept = &frame[..captured.min(frame.len())];
        let packet = decode(LinkType::Ethernet, Timestamp(0), frame.len() as u32, kept).unwrap();
        let Network::Ip(ip) = packet.network else {
            panic!("expected IP");
        };
        (ip.payload_len, ip.ttl)
    }

    #[test]
    fn counts_the_data_of_a_whole_tcp_packet() {
        let frame = tcp_with(&[7; 100], 64);
        assert_eq!(seen(&frame, frame.len()), (100, 64));
    }

    #[test]
    fn a_packet_cut_by_the_capture_keeps_its_real_size() {
        // Flagman keeps 160 bytes: the 1,000 data bytes are mostly cut off.
        let frame = tcp_with(&[7; 1_000], 128);
        assert_eq!(seen(&frame, 160), (1_000, 128));
    }

    #[test]
    fn an_empty_tcp_packet_carries_no_data_even_with_ethernet_padding() {
        let mut frame = tcp_with(&[], 64);
        frame.resize(60, 0); // the shortest Ethernet frame
        assert_eq!(seen(&frame, frame.len()).0, 0);
    }

    #[test]
    fn udp_and_ipv6_data_are_counted_after_their_headers() {
        let udp = write(|frame| {
            PacketBuilder::ethernet2(MAC, MAC)
                .ipv4(A, B, 64)
                .udp(5353, 53)
                .write(frame, &[1; 30])
                .unwrap();
        });
        assert_eq!(seen(&udp, udp.len()).0, 30);
        let v6 = write(|frame| {
            PacketBuilder::ethernet2(MAC, MAC)
                .ipv6([0xfe; 16], [0xfd; 16], 55)
                .tcp(40_000, 22, 1, 64_240)
                .write(frame, &[1; 50])
                .unwrap();
        });
        assert_eq!(seen(&v6, 80), (50, 55));
    }

    #[test]
    fn a_zero_length_field_falls_back_to_the_frame_size() {
        // Captures taken on the sending machine can carry an IPv4 length of 0.
        let mut frame = tcp_with(&[7; 300], 64);
        frame[16] = 0; // IPv4 total length, high byte
        frame[17] = 0; // low byte
        assert_eq!(seen(&frame, 160).0, 300);
    }
}
