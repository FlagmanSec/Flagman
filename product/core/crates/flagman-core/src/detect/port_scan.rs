//! Port scan: one host tries many different ports on one other host.
//!
//! This is what `nmap 192.168.1.10` does: it sends a TCP SYN to 1,000 ports to
//! see which ones answer. A normal program connects to one or two ports of a
//! machine, so 20 different ports in 60 seconds is a strong signal.

use super::attack;
use super::config::PortScanConfig;
use super::tracker::{Finding, Tracker, TrackerConfig};
use crate::alert::{Alert, AlertDetails, AlertKind, Severity};
use crate::flow::{FlowStart, Protocol, StartKind};
use crate::ids::IdGenerator;
use crate::net::is_unicast;
use crate::time::Timestamp;
use std::net::IpAddr;

/// (scanner, target)
type Key = (IpAddr, IpAddr);

pub struct PortScanDetector {
    tcp: Tracker<Key, u16>,
    udp: Tracker<Key, u16>,
    window_secs: i64,
}

impl PortScanDetector {
    pub fn new(
        config: &PortScanConfig,
        idle_secs: i64,
        update_every_secs: i64,
    ) -> PortScanDetector {
        let tracker_config = |threshold| TrackerConfig {
            window_secs: config.window_secs,
            threshold,
            finding_idle_secs: idle_secs,
            update_every_secs,
        };
        PortScanDetector {
            tcp: Tracker::new(tracker_config(config.min_tcp_ports)),
            udp: Tracker::new(tracker_config(config.min_udp_ports)),
            window_secs: config.window_secs,
        }
    }

    pub fn on_flow_start(
        &mut self,
        start: &FlowStart,
        ids: &mut IdGenerator,
        out: &mut Vec<Alert>,
    ) {
        if !is_unicast(start.responder.ip) {
            return;
        }
        let key = (start.initiator.ip, start.responder.ip);
        let port = start.responder.port;
        let found = match start.kind {
            StartKind::TcpSyn => self
                .tcp
                .record(key, port, start.ts, ids)
                .map(|finding| (finding, Protocol::Tcp)),
            StartKind::Udp => self
                .udp
                .record(key, port, start.ts, ids)
                .map(|finding| (finding, Protocol::Udp)),
            _ => None,
        };
        if let Some((finding, protocol)) = found {
            out.push(self.alert_from(finding, protocol));
        }
    }

    pub fn expire(&mut self, now: Timestamp, out: &mut Vec<Alert>) {
        for finding in self.tcp.expire(now) {
            out.push(self.alert_from(finding, Protocol::Tcp));
        }
        for finding in self.udp.expire(now) {
            out.push(self.alert_from(finding, Protocol::Udp));
        }
    }

    fn alert_from(&self, finding: Finding<Key, u16>, protocol: Protocol) -> Alert {
        let (scanner, target) = finding.key;
        let mut ports_sample = finding.sample;
        ports_sample.sort_unstable();
        Alert {
            id: finding.alert_id,
            incident_id: None,
            kind: AlertKind::PortScan,
            severity: Severity::Medium,
            first_seen: finding.first_seen,
            last_seen: finding.last_seen,
            src_ip: scanner,
            dst_ip: Some(target),
            dst_port: None,
            count: finding.count,
            details: AlertDetails::PortScan {
                protocol,
                ports_sample,
                window_secs: self.window_secs,
            },
            attack: Some(attack::network_service_discovery()),
        }
    }
}
