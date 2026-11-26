//! Groups alerts into incidents.
//!
//! Rule: alerts about the same host belong to the same incident as long as
//! the gap between them stays under `gap_secs` (30 minutes by default).
//! The incident severity is the highest alert severity, raised one level when
//! the host moved through two or more ATT&CK tactics (for example discovery,
//! then credential access), because that looks like an attack in progress.
//!
//! "The host" is usually the alert's source: the scanner, the guesser. One
//! exception: a Suricata alert on traffic that came from the internet to one
//! of your devices is filed under your device. Suricata rules often match the
//! answer of a server (for example a web page your PC downloaded), so the
//! source is then an outside server, and filing the alert under that server
//! would split one PC's story across many incidents.

use super::model::{Incident, MAX_TARGETS};
use crate::alert::{Alert, AlertKind, Severity};
use crate::ids::IdGenerator;
use crate::net::is_local;
use crate::time::Timestamp;
use std::collections::HashMap;
use std::net::IpAddr;

struct OpenIncident {
    incident: Incident,
    /// Severity of each alert id in this incident.
    alert_severities: HashMap<u64, Severity>,
}

pub struct IncidentEngine {
    gap_ms: i64,
    open: HashMap<IpAddr, OpenIncident>,
    ids: IdGenerator,
}

impl IncidentEngine {
    pub fn new(gap_secs: i64, ids: IdGenerator) -> IncidentEngine {
        IncidentEngine {
            gap_ms: gap_secs * 1_000,
            open: HashMap::new(),
            ids,
        }
    }

    /// Adds an alert (new or updated) to its incident and returns the
    /// incident as it is now.
    pub fn on_alert(&mut self, alert: &Alert) -> Incident {
        let host = incident_host(alert);
        let too_old = self.open.get(&host).is_some_and(|open| {
            let is_new_alert = !open.alert_severities.contains_key(&alert.id);
            is_new_alert && alert.first_seen.millis_since(open.incident.last_seen) > self.gap_ms
        });
        if too_old {
            self.open.remove(&host);
        }
        let ids = &mut self.ids;
        let open = self
            .open
            .entry(host)
            .or_insert_with(|| new_incident(ids.next_id(), host, alert));
        add_alert(open, alert);
        open.incident.clone()
    }

    /// Forgets incidents that have been quiet for longer than the gap.
    /// They are already stored; a new alert from the same host starts a new one.
    pub fn expire(&mut self, now: Timestamp) {
        let gap_ms = self.gap_ms;
        self.open
            .retain(|_, open| now.millis_since(open.incident.last_seen) <= gap_ms);
    }
}

/// The host an alert is filed under (see the module comment).
fn incident_host(alert: &Alert) -> IpAddr {
    match alert.dst_ip {
        Some(device)
            if alert.kind == AlertKind::Signature
                && !is_local(alert.src_ip)
                && is_local(device) =>
        {
            device
        }
        _ => alert.src_ip,
    }
}

fn new_incident(id: u64, host: IpAddr, alert: &Alert) -> OpenIncident {
    OpenIncident {
        incident: Incident {
            id,
            first_seen: alert.first_seen,
            last_seen: alert.last_seen,
            src_ip: host,
            severity: alert.severity,
            alert_count: 0,
            kinds: Vec::new(),
            tactics: Vec::new(),
            targets: Vec::new(),
        },
        alert_severities: HashMap::new(),
    }
}

fn add_alert(open: &mut OpenIncident, alert: &Alert) {
    open.alert_severities.insert(alert.id, alert.severity);
    let incident = &mut open.incident;
    incident.first_seen = incident.first_seen.min(alert.first_seen);
    incident.last_seen = incident.last_seen.max(alert.last_seen);
    incident.alert_count = open.alert_severities.len() as u64;
    if !incident.kinds.contains(&alert.kind) {
        incident.kinds.push(alert.kind);
    }
    if let Some(attack) = &alert.attack
        && !incident.tactics.contains(&attack.tactic)
    {
        incident.tactics.push(attack.tactic.clone());
    }
    if let Some(target) = alert.dst_ip
        && target != incident.src_ip
        && !incident.targets.contains(&target)
        && incident.targets.len() < MAX_TARGETS
    {
        incident.targets.push(target);
    }
    let highest = open
        .alert_severities
        .values()
        .copied()
        .max()
        .unwrap_or(Severity::Low);
    incident.severity = if incident.tactics.len() >= 2 {
        highest.raised()
    } else {
        highest
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{AlertDetails, AlertKind, AttackRef};
    use crate::testutil::ip;

    fn alert(id: u64, kind: AlertKind, severity: Severity, at_ms: i64, tactic: &str) -> Alert {
        Alert {
            id,
            incident_id: None,
            kind,
            severity,
            first_seen: Timestamp(at_ms),
            last_seen: Timestamp(at_ms + 1_000),
            src_ip: ip("192.168.1.66"),
            dst_ip: Some(ip("192.168.1.10")),
            dst_port: None,
            count: 1,
            details: AlertDetails::BruteForce {
                service_port: 22,
                window_secs: 60,
                outbound: false,
            },
            attack: Some(AttackRef {
                tactic_id: String::new(),
                tactic: tactic.to_string(),
                technique_id: String::new(),
                technique: String::new(),
            }),
        }
    }

    #[test]
    fn a_scan_then_brute_force_is_one_escalated_incident() {
        let mut engine = IncidentEngine::new(1_800, IdGenerator::starting_after(0));
        let first = engine.on_alert(&alert(
            1,
            AlertKind::PortScan,
            Severity::Medium,
            0,
            "Discovery",
        ));
        assert_eq!(first.severity, Severity::Medium);
        let second = engine.on_alert(&alert(
            2,
            AlertKind::BruteForce,
            Severity::High,
            60_000,
            "Credential Access",
        ));
        assert_eq!(second.id, first.id);
        assert_eq!(second.alert_count, 2);
        assert_eq!(
            second.kinds,
            vec![AlertKind::PortScan, AlertKind::BruteForce]
        );
        assert_eq!(
            second.severity,
            Severity::Critical,
            "high, raised for two tactics"
        );
    }

    #[test]
    fn an_updated_alert_is_not_counted_twice() {
        let mut engine = IncidentEngine::new(1_800, IdGenerator::starting_after(0));
        engine.on_alert(&alert(
            7,
            AlertKind::PortScan,
            Severity::Medium,
            0,
            "Discovery",
        ));
        let again = engine.on_alert(&alert(
            7,
            AlertKind::PortScan,
            Severity::Medium,
            5_000,
            "Discovery",
        ));
        assert_eq!(again.alert_count, 1);
    }

    fn suricata_alert(id: u64, src: &str, dst: &str) -> Alert {
        Alert {
            kind: AlertKind::Signature,
            severity: Severity::High,
            src_ip: ip(src),
            dst_ip: Some(ip(dst)),
            details: AlertDetails::Signature {
                signature_id: 2_100_498,
                signature: "GPL ATTACK_RESPONSE id check returned root".to_string(),
                category: "Potentially Bad Traffic".to_string(),
                engine: "suricata".to_string(),
            },
            attack: None,
            ..alert(id, AlertKind::Signature, Severity::High, 0, "")
        }
    }

    #[test]
    fn a_suricata_alert_from_the_internet_is_filed_under_the_home_device() {
        let mut engine = IncidentEngine::new(1_800, IdGenerator::starting_after(0));
        // The answer of a web server on the internet matched a rule.
        let first = engine.on_alert(&suricata_alert(1, "203.0.113.7", "192.168.1.10"));
        assert_eq!(first.src_ip, ip("192.168.1.10"));
        assert!(
            first.targets.is_empty(),
            "the device is the subject, not a target"
        );
        // Another server's answer to the same PC joins the same incident.
        let second = engine.on_alert(&suricata_alert(2, "198.51.100.9", "192.168.1.10"));
        assert_eq!(second.id, first.id);
        // Traffic sent by the PC itself is filed under the PC too.
        let third = engine.on_alert(&suricata_alert(3, "192.168.1.10", "198.51.100.9"));
        assert_eq!(third.id, first.id);
        assert_eq!(third.targets, vec![ip("198.51.100.9")]);
    }

    #[test]
    fn behaviour_alerts_stay_with_their_source_even_from_the_internet() {
        let mut engine = IncidentEngine::new(1_800, IdGenerator::starting_after(0));
        let scan = Alert {
            src_ip: ip("203.0.113.7"),
            ..alert(1, AlertKind::PortScan, Severity::Medium, 0, "Discovery")
        };
        assert_eq!(engine.on_alert(&scan).src_ip, ip("203.0.113.7"));
    }

    #[test]
    fn a_long_silence_starts_a_new_incident() {
        let mut engine = IncidentEngine::new(1_800, IdGenerator::starting_after(10));
        let first = engine.on_alert(&alert(
            1,
            AlertKind::PortScan,
            Severity::Medium,
            0,
            "Discovery",
        ));
        let later = engine.on_alert(&alert(
            2,
            AlertKind::PortScan,
            Severity::Medium,
            3_600_000,
            "Discovery",
        ));
        assert_eq!(first.id, 11);
        assert_eq!(later.id, 12);
    }
}
