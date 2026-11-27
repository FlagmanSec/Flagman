//! The kind of service a flow went to, without its exact port number.
//!
//! The exact number is left out of the features: source ports are picked at
//! random by the operating system, and which server port an attack used is a
//! property of one lab, not of attacks in general. The three ranges are
//! IANA's ([port registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml),
//! following [RFC 6335, section 8.1.2](https://www.rfc-editor.org/rfc/rfc6335#section-8.1.2)),
//! which names them System Ports, User Ports, and Dynamic and/or Private
//! Ports. Many documents call the first two "well-known" and "registered".

use flagman_core::flow::Protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortClass {
    /// 0 to 1023, IANA's "system ports": SSH, web, mail, DNS...
    WellKnown,
    /// 1024 to 49151, IANA's "user ports": registered services, and the
    /// temporary client ports of some systems.
    Registered,
    /// 49152 to 65535, IANA's "dynamic and/or private ports", never assigned.
    Dynamic,
    /// ICMP and other protocols have no ports.
    None,
}

impl PortClass {
    pub fn of(protocol: Protocol, port: u16) -> PortClass {
        match (protocol, port) {
            (Protocol::Tcp | Protocol::Udp, 0..=1023) => PortClass::WellKnown,
            (Protocol::Tcp | Protocol::Udp, 1024..=49151) => PortClass::Registered,
            (Protocol::Tcp | Protocol::Udp, _) => PortClass::Dynamic,
            (Protocol::Icmp | Protocol::Other, _) => PortClass::None,
        }
    }

    pub const NAMES: [&'static str; 4] = ["well_known", "registered", "dynamic", "none"];

    pub fn as_str(self) -> &'static str {
        match self {
            PortClass::WellKnown => "well_known",
            PortClass::Registered => "registered",
            PortClass::Dynamic => "dynamic",
            PortClass::None => "none",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_iana_ranges() {
        assert_eq!(PortClass::of(Protocol::Tcp, 22), PortClass::WellKnown);
        assert_eq!(PortClass::of(Protocol::Udp, 1023), PortClass::WellKnown);
        assert_eq!(PortClass::of(Protocol::Tcp, 1024), PortClass::Registered);
        assert_eq!(PortClass::of(Protocol::Tcp, 49151), PortClass::Registered);
        assert_eq!(PortClass::of(Protocol::Udp, 49152), PortClass::Dynamic);
        assert_eq!(PortClass::of(Protocol::Icmp, 0), PortClass::None);
    }
}
