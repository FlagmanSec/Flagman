//! What one side of a flow sent, updated packet by packet.
//!
//! "Forward" is the side that sent the flow's first packet (the initiator),
//! "reverse" the other side (the responder), as in the flow record.

use crate::stats::RunningStats;
use flagman_core::packet::{IpPacket, Transport};
use flagman_core::time::Timestamp;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DirectionStats {
    /// Data bytes per packet (after the IP and transport headers).
    pub payload: RunningStats,
    /// Data bytes in total.
    pub payload_bytes: u64,
    /// Milliseconds between two packets in a row from this side.
    pub gaps: RunningStats,
    /// When this side's latest packet arrived, in milliseconds.
    last_ms: i64,
    pub syn: u16,
    pub fin: u16,
    pub rst: u16,
    /// Packets that carried no data (handshakes, plain ACKs, probes).
    pub empty: u32,
    /// TTL of this side's first packet; kept only to notice a change.
    first_ttl: u8,
    pub ttl_changed: bool,
}

impl DirectionStats {
    pub fn add(&mut self, ts: Timestamp, ip: &IpPacket) {
        if self.packets() == 0 {
            self.first_ttl = ip.ttl;
        } else {
            // A packet stamped earlier than the previous one (captures are
            // sometimes slightly out of order) counts as a gap of 0.
            let gap = ts.millis().saturating_sub(self.last_ms).max(0);
            self.gaps.add(u32::try_from(gap).unwrap_or(u32::MAX));
            self.ttl_changed |= ip.ttl != self.first_ttl;
        }
        self.last_ms = self.last_ms.max(ts.millis());
        self.payload.add(ip.payload_len);
        self.payload_bytes += u64::from(ip.payload_len);
        if ip.payload_len == 0 {
            self.empty = self.empty.saturating_add(1);
        }
        if let Transport::Tcp { flags, .. } = ip.transport {
            self.syn = self.syn.saturating_add(u16::from(flags.syn));
            self.fin = self.fin.saturating_add(u16::from(flags.fin));
            self.rst = self.rst.saturating_add(u16::from(flags.rst));
        }
    }

    /// Packets from this side so far.
    pub fn packets(&self) -> u32 {
        self.payload.count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flagman_core::packet::TcpFlags;
    use std::net::{IpAddr, Ipv4Addr};

    fn packet(payload_len: u32, ttl: u8, flags: TcpFlags) -> IpPacket {
        let any = IpAddr::V4(Ipv4Addr::LOCALHOST);
        IpPacket {
            src: any,
            dst: any,
            transport: Transport::Tcp {
                src_port: 1,
                dst_port: 2,
                flags,
            },
            ttl,
            payload_len,
        }
    }

    #[test]
    fn a_worked_example() {
        let ack = TcpFlags {
            ack: true,
            ..TcpFlags::default()
        };
        let syn = TcpFlags {
            syn: true,
            ..TcpFlags::default()
        };
        let mut side = DirectionStats::default();
        side.add(Timestamp(1_000), &packet(0, 64, syn));
        side.add(Timestamp(1_030), &packet(100, 64, ack));
        side.add(Timestamp(1_090), &packet(300, 64, ack));
        assert_eq!(side.packets(), 3);
        assert_eq!(side.payload_bytes, 400);
        assert_eq!(side.empty, 1);
        assert_eq!(side.syn, 1);
        // Gaps of 30 ms and 60 ms.
        assert_eq!(side.gaps.mean(), Some(45.0));
        assert_eq!((side.gaps.min(), side.gaps.max()), (Some(30), Some(60)));
        assert!(!side.ttl_changed);
    }

    #[test]
    fn only_a_change_of_ttl_is_kept() {
        let mut side = DirectionStats::default();
        side.add(Timestamp(0), &packet(10, 64, TcpFlags::default()));
        side.add(Timestamp(5), &packet(10, 63, TcpFlags::default()));
        assert!(side.ttl_changed);
    }

    #[test]
    fn an_out_of_order_packet_is_a_gap_of_zero() {
        let mut side = DirectionStats::default();
        side.add(Timestamp(100), &packet(1, 64, TcpFlags::default()));
        side.add(Timestamp(90), &packet(1, 64, TcpFlags::default()));
        side.add(Timestamp(130), &packet(1, 64, TcpFlags::default()));
        assert_eq!((side.gaps.min(), side.gaps.max()), (Some(0), Some(30)));
    }
}
