//! Host sweep: one host probes many machines of the local network.
//!
//! This is what `nmap -sn 192.168.1.0/24` does to find which machines are up.
//! On a home network nmap uses ARP for this. ARP requests are broadcast, so
//! Flagman sees a sweep even when it runs on a single PC.
//!
//! Only local destinations count: browsing the web contacts many public
//! servers every minute, and that is normal.

use super::attack;
use super::config::HostSweepConfig;
use super::tracker::{Finding, Tracker, TrackerConfig};
use crate::alert::{Alert, AlertDetails, AlertKind, Severity, SweepMethod};
use crate::flow::{FlowStart, StartKind};
use crate::ids::IdGenerator;
use crate::net::{is_local, is_unicast};
use crate::packet::{ArpOperation, ArpPacket};
use crate::time::Timestamp;
use std::net::IpAddr;

/// (prober, method)
type Key = (IpAddr, SweepMethod);

pub struct HostSweepDetector {
    tracker: Tracker<Key, IpAddr>,
    window_secs: i64,
}

impl HostSweepDetector {
    pub fn new(
        config: &HostSweepConfig,
        idle_secs: i64,
        update_every_secs: i64,
    ) -> HostSweepDetector {
        HostSweepDetector {
            tracker: Tracker::new(TrackerConfig {
                window_secs: config.window_secs,
                threshold: config.min_hosts,
                finding_idle_secs: idle_secs,
                update_every_secs,
            }),
            window_secs: config.window_secs,
        }
    }

    pub fn on_flow_start(
        &mut self,
        start: &FlowStart,
        ids: &mut IdGenerator,
        out: &mut Vec<Alert>,
    ) {
        let method = match start.kind {
            StartKind::TcpSyn => SweepMethod::Tcp,
            StartKind::Udp => SweepMethod::Udp,
            StartKind::IcmpEchoRequest => SweepMethod::Icmp,
            _ => return,
        };
        let target = start.responder.ip;
        if !is_local(target) || !is_unicast(target) {
            return;
        }
        let key = (start.initiator.ip, method);
        if let Some(finding) = self.tracker.record(key, target, start.ts, ids) {
            out.push(self.alert_from(finding));
        }
    }

    /// ARP requests: "who has 192.168.1.7?"
    pub fn on_arp(
        &mut self,
        ts: Timestamp,
        arp: &ArpPacket,
        ids: &mut IdGenerator,
        out: &mut Vec<Alert>,
    ) {
        let is_probe_or_announcement =
            arp.sender_ip.is_unspecified() || arp.sender_ip == arp.target_ip;
        if arp.operation != ArpOperation::Request || is_probe_or_announcement {
            return;
        }
        let key = (IpAddr::V4(arp.sender_ip), SweepMethod::Arp);
        if let Some(finding) = self.tracker.record(key, IpAddr::V4(arp.target_ip), ts, ids) {
            out.push(self.alert_from(finding));
        }
    }

    pub fn expire(&mut self, now: Timestamp, out: &mut Vec<Alert>) {
        for finding in self.tracker.expire(now) {
            out.push(self.alert_from(finding));
        }
    }

    fn alert_from(&self, finding: Finding<Key, IpAddr>) -> Alert {
        let (prober, method) = finding.key;
        let mut hosts_sample = finding.sample;
        hosts_sample.sort_unstable();
        Alert {
            id: finding.alert_id,
            incident_id: None,
            kind: AlertKind::HostSweep,
            severity: Severity::Medium,
            first_seen: finding.first_seen,
            last_seen: finding.last_seen,
            src_ip: prober,
            dst_ip: None,
            dst_port: None,
            count: finding.count,
            details: AlertDetails::HostSweep {
                method,
                hosts_sample,
                window_secs: self.window_secs,
            },
            attack: Some(attack::remote_system_discovery()),
        }
    }
}
