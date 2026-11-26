//! Detectors: they watch new flows, finished flows, ARP requests and
//! Suricata hits, and produce [`Alert`]s. Each detector lives in its own
//! file; [`Detectors`] simply forwards every event to the ones that need it.

mod attack;
mod brute_force;
mod config;
mod host_sweep;
mod port_scan;
mod signature;
mod tracker;
mod window;

pub use config::{BruteForceConfig, DetectConfig, HostSweepConfig, PortScanConfig};
pub use signature::SignatureHit;
pub use tracker::{Evictions, Finding, Tracker, TrackerConfig};
pub use window::DistinctWindow;

use crate::alert::Alert;
use crate::flow::{FlowRecord, FlowStart};
use crate::ids::IdGenerator;
use crate::packet::ArpPacket;
use crate::time::Timestamp;
use brute_force::BruteForceDetector;
use host_sweep::HostSweepDetector;
use port_scan::PortScanDetector;
use signature::SignatureDetector;
use std::collections::HashSet;
use std::net::IpAddr;

pub struct Detectors {
    port_scan: PortScanDetector,
    host_sweep: HostSweepDetector,
    brute_force: BruteForceDetector,
    signatures: SignatureDetector,
    ignored_sources: HashSet<IpAddr>,
    alert_ids: IdGenerator,
}

impl Detectors {
    pub fn new(config: &DetectConfig, alert_ids: IdGenerator) -> Detectors {
        let idle = config.finding_idle_secs;
        let every = config.update_every_secs;
        Detectors {
            port_scan: PortScanDetector::new(&config.port_scan, idle, every),
            host_sweep: HostSweepDetector::new(&config.host_sweep, idle, every),
            brute_force: BruteForceDetector::new(&config.brute_force, idle, every),
            signatures: SignatureDetector::new(idle, every),
            ignored_sources: config.ignore_sources.iter().copied().collect(),
            alert_ids,
        }
    }

    pub fn on_flow_start(&mut self, start: &FlowStart, out: &mut Vec<Alert>) {
        if self.ignored_sources.contains(&start.initiator.ip) {
            return;
        }
        let ids = &mut self.alert_ids;
        self.port_scan.on_flow_start(start, ids, out);
        self.host_sweep.on_flow_start(start, ids, out);
    }

    /// A flow has ended (closed, timed out, or pushed out of a full table).
    pub fn on_flow_end(&mut self, flow: &FlowRecord, out: &mut Vec<Alert>) {
        if self.ignored_sources.contains(&flow.initiator.ip) {
            return;
        }
        self.brute_force.on_flow_end(flow, &mut self.alert_ids, out);
    }

    pub fn on_arp(&mut self, ts: Timestamp, arp: &ArpPacket, out: &mut Vec<Alert>) {
        if self.ignored_sources.contains(&IpAddr::V4(arp.sender_ip)) {
            return;
        }
        self.host_sweep.on_arp(ts, arp, &mut self.alert_ids, out);
    }

    pub fn on_signature(&mut self, hit: SignatureHit, out: &mut Vec<Alert>) {
        self.signatures.on_hit(hit, &mut self.alert_ids, out);
    }

    /// Closes quiet findings. Call it regularly (the engine does, every second).
    pub fn expire(&mut self, now: Timestamp, out: &mut Vec<Alert>) {
        self.port_scan.expire(now, out);
        self.host_sweep.expire(now, out);
        self.brute_force.expire(now, out);
        self.signatures.expire(now, out);
    }

    /// Keys all detectors had to forget because they were full.
    pub fn evictions(&self) -> Evictions {
        self.port_scan
            .evictions()
            .merge(self.host_sweep.evictions())
            .merge(self.brute_force.evictions())
            .merge(self.signatures.evictions())
    }
}

#[cfg(test)]
#[path = "detectors_tests.rs"]
mod tests;
