//! Parsing Suricata EVE JSON alert lines.
//! Format reference: <https://docs.suricata.io/en/latest/output/eve/eve-json-format.html>

use chrono::DateTime;
use flagman_core::alert::AttackRef;
use flagman_core::detect::SignatureHit;
use flagman_core::flow::Protocol;
use flagman_core::time::Timestamp;
use serde::Deserialize;
use std::net::IpAddr;

/// The fields of an EVE event that Flagman uses. Everything else is ignored.
#[derive(Deserialize)]
struct EveEvent {
    timestamp: String,
    event_type: String,
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<u16>,
    proto: Option<String>,
    alert: Option<EveAlert>,
}

#[derive(Deserialize)]
struct EveAlert {
    signature_id: u64,
    signature: String,
    #[serde(default)]
    category: String,
    severity: u8,
    #[serde(default)]
    metadata: Option<EveMetadata>,
}

/// Emerging Threats rules tag many signatures with MITRE ATT&CK ids.
#[derive(Deserialize, Default)]
struct EveMetadata {
    #[serde(default)]
    mitre_tactic_id: Vec<String>,
    #[serde(default)]
    mitre_tactic_name: Vec<String>,
    #[serde(default)]
    mitre_technique_id: Vec<String>,
    #[serde(default)]
    mitre_technique_name: Vec<String>,
}

/// Returns the alert in `line`, or `None` for other event types (flows, DNS,
/// stats...) and for lines that are not valid alerts.
pub fn parse_alert_line(line: &str) -> Option<SignatureHit> {
    let event: EveEvent = serde_json::from_str(line).ok()?;
    if event.event_type != "alert" {
        return None;
    }
    let alert = event.alert?;
    let ts = DateTime::parse_from_str(&event.timestamp, "%Y-%m-%dT%H:%M:%S%.f%z").ok()?;
    Some(SignatureHit {
        ts: Timestamp(ts.timestamp_millis()),
        src_ip: event.src_ip?,
        dst_ip: event.dest_ip?,
        src_port: event.src_port,
        dst_port: event.dest_port,
        protocol: event.proto.as_deref().map(protocol_of),
        signature_id: alert.signature_id,
        attack: alert.metadata.as_ref().and_then(attack_of),
        signature: alert.signature,
        category: alert.category,
        severity: alert.severity,
        engine: "suricata".to_string(),
    })
}

fn protocol_of(proto: &str) -> Protocol {
    match proto.to_ascii_uppercase().as_str() {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        "ICMP" | "IPV6-ICMP" => Protocol::Icmp,
        _ => Protocol::Other,
    }
}

fn attack_of(metadata: &EveMetadata) -> Option<AttackRef> {
    let readable = |names: &[String]| {
        names
            .first()
            .map(|name| name.replace('_', " "))
            .unwrap_or_default()
    };
    Some(AttackRef {
        tactic_id: metadata.mitre_tactic_id.first()?.clone(),
        tactic: readable(&metadata.mitre_tactic_name),
        technique_id: metadata
            .mitre_technique_id
            .first()
            .cloned()
            .unwrap_or_default(),
        technique: readable(&metadata.mitre_technique_name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALERT: &str = r#"{"timestamp":"2026-11-26T17:02:16.250000+0000","flow_id":1,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.66","src_port":51234,"dest_ip":"192.168.1.10","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":20,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2,"metadata":{"mitre_tactic_id":["TA0043"],"mitre_tactic_name":["Reconnaissance"],"mitre_technique_id":["T1595"],"mitre_technique_name":["Active_Scanning"]}}}"#;

    #[test]
    fn reads_an_alert_with_its_attack_tags() {
        let hit = parse_alert_line(ALERT).expect("an alert");
        assert_eq!(hit.signature_id, 2_001_219);
        assert_eq!(hit.src_ip, "192.168.1.66".parse::<IpAddr>().unwrap());
        assert_eq!(hit.dst_port, Some(22));
        assert_eq!(hit.protocol, Some(Protocol::Tcp));
        assert_eq!(hit.severity, 2);
        assert_eq!(hit.ts, Timestamp(1_795_712_536_250));
        let attack = hit.attack.expect("attack tags");
        assert_eq!(attack.tactic_id, "TA0043");
        assert_eq!(attack.technique, "Active Scanning");
    }

    #[test]
    fn ignores_other_events_and_garbage() {
        let flow = r#"{"timestamp":"2026-11-26T17:02:16.250000+0000","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"10.0.0.2"}"#;
        assert!(parse_alert_line(flow).is_none());
        assert!(parse_alert_line("not json").is_none());
        assert!(parse_alert_line("{}").is_none());
    }
}
