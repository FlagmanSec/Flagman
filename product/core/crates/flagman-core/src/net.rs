//! Small helpers about IP addresses that several detectors need.

use std::net::IpAddr;

/// True for addresses that belong to a local network: private ranges
/// (10/8, 172.16/12, 192.168/16, fc00::/7), link-local and loopback.
///
/// Host sweeps are only counted towards local addresses. A browser opens
/// connections to dozens of public servers every minute, and that is normal.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            let unique_local = (first & 0xfe00) == 0xfc00;
            let link_local = (first & 0xffc0) == 0xfe80;
            unique_local || link_local || v6.is_loopback()
        }
    }
}

/// True when a packet to this address goes to exactly one host
/// (not broadcast, not multicast, not "unspecified").
///
/// IPv4 addresses ending in `.255` are treated as broadcast, which is right for
/// the /24 networks that almost every home router uses.
pub fn is_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified())
                && v4.octets()[3] != 255
        }
        IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn recognises_local_networks() {
        assert!(is_local(ip("192.168.1.20")));
        assert!(is_local(ip("10.0.0.5")));
        assert!(is_local(ip("fe80::1")));
        assert!(!is_local(ip("8.8.8.8")));
        assert!(!is_local(ip("2001:4860::8888")));
    }

    #[test]
    fn rejects_broadcast_and_multicast() {
        assert!(is_unicast(ip("192.168.1.20")));
        assert!(!is_unicast(ip("255.255.255.255")));
        assert!(!is_unicast(ip("192.168.1.255")));
        assert!(!is_unicast(ip("224.0.0.251")));
        assert!(!is_unicast(ip("ff02::fb")));
    }
}
