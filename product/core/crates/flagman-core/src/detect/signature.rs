//! Signature hits from Suricata, grouped so that one rule firing 500 times
//! between the same two hosts is one alert with a count of 500.

use super::tracker::{Evictions, Finding, Tracker, TrackerConfig};
use crate::alert::{Alert, AlertDetails, AlertKind, AttackRef, Severity};
use crate::flow::Protocol;
use crate::ids::IdGenerator;
use crate::time::Timestamp;
use std::collections::HashMap;
use std::net::IpAddr;

/// One rule match, as read from Suricata's EVE JSON log.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureHit {
    pub ts: Timestamp,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub signature_id: u64,
    pub signature: String,
    pub category: String,
    /// Suricata severity: 1 is the most severe, 3 the least.
    pub severity: u8,
    pub attack: Option<AttackRef>,
    pub engine: String,
}

/// (rule id, source, destination)
type Key = (u64, IpAddr, IpAddr);

pub struct SignatureDetector {
    tracker: Tracker<Key, u64>,
    latest_hit: HashMap<Key, SignatureHit>,
    hits_seen: u64,
}

impl SignatureDetector {
    pub fn new(idle_secs: i64, update_every_secs: i64) -> SignatureDetector {
        SignatureDetector {
            tracker: Tracker::new(TrackerConfig {
                window_secs: idle_secs,
                threshold: 1,
                finding_idle_secs: idle_secs,
                update_every_secs,
            }),
            latest_hit: HashMap::new(),
            hits_seen: 0,
        }
    }

    pub fn on_hit(&mut self, hit: SignatureHit, ids: &mut IdGenerator, out: &mut Vec<Alert>) {
        let key = (hit.signature_id, hit.src_ip, hit.dst_ip);
        // Each hit gets its own number, so "distinct values" counts hits.
        self.hits_seen += 1;
        let finding = self.tracker.record(key, self.hits_seen, hit.ts, ids);
        self.latest_hit.insert(key, hit);
        if let Some(finding) = finding
            && let Some(alert) = self.alert_from(finding)
        {
            out.push(alert);
        }
    }

    pub fn expire(&mut self, now: Timestamp, out: &mut Vec<Alert>) {
        for finding in self.tracker.expire(now) {
            if let Some(alert) = self.alert_from(finding) {
                out.push(alert);
            }
        }
        let tracker = &self.tracker;
        self.latest_hit.retain(|key, _| tracker.contains(key));
    }

    pub fn evictions(&self) -> Evictions {
        self.tracker.evictions()
    }

    fn alert_from(&self, finding: Finding<Key, u64>) -> Option<Alert> {
        let hit = self.latest_hit.get(&finding.key)?;
        Some(Alert {
            id: finding.alert_id,
            incident_id: None,
            kind: AlertKind::Signature,
            severity: severity_from_suricata(hit.severity),
            first_seen: finding.first_seen,
            last_seen: finding.last_seen,
            src_ip: hit.src_ip,
            dst_ip: Some(hit.dst_ip),
            dst_port: hit.dst_port,
            count: finding.count,
            details: AlertDetails::Signature {
                signature_id: hit.signature_id,
                signature: hit.signature.clone(),
                category: hit.category.clone(),
                engine: hit.engine.clone(),
            },
            attack: hit.attack.clone(),
        })
    }
}

fn severity_from_suricata(severity: u8) -> Severity {
    match severity {
        1 => Severity::High,
        2 => Severity::Medium,
        _ => Severity::Low,
    }
}
