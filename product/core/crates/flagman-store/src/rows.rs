//! The shapes the store returns to the API. They are serialised to JSON as
//! they are, so the field names here are the field names the UI sees.
//! Times are milliseconds since the Unix epoch; severities are words.

use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct SeverityCounts {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

impl SeverityCounts {
    pub(crate) fn add(&mut self, rank: i64, amount: u64) {
        match rank {
            ..=1 => self.low += amount,
            2 => self.medium += amount,
            3 => self.high += amount,
            _ => self.critical += amount,
        }
    }
}

/// The numbers in the dashboard's top row.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Overview {
    pub since: i64,
    pub until: i64,
    /// Incidents active in the range whose status is still "open".
    pub open_incidents: u64,
    pub incidents: u64,
    pub incidents_by_severity: SeverityCounts,
    pub alerts: u64,
    pub flows: u64,
    pub packets: u64,
    pub bytes: u64,
    /// Distinct local addresses seen in flows.
    pub local_hosts: u64,
}

/// Counts per protocol family.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ClassCounts {
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub arp: u64,
    pub other: u64,
}

impl ClassCounts {
    pub(crate) fn add(&mut self, class: &str, amount: u64) {
        match class {
            "tcp" => self.tcp += amount,
            "udp" => self.udp += amount,
            "icmp" => self.icmp += amount,
            "arp" => self.arp += amount,
            _ => self.other += amount,
        }
    }
}

/// Traffic in one time bucket (`t` is the bucket start).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct TrafficPoint {
    pub t: i64,
    pub bytes: ClassCounts,
    pub packets: ClassCounts,
}

/// Alerts that started in one time bucket, per severity.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct AlertPoint {
    pub t: i64,
    #[serde(flatten)]
    pub counts: SeverityCounts,
}

/// A host and how much it talked.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TalkerRow {
    pub ip: String,
    pub bytes: u64,
    pub flows: u64,
}

/// A generic "name and count" row for top lists (ports, alert types, protocols).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NamedCount {
    pub name: String,
    /// Extra label, for example the protocol of a port or a rule category.
    pub detail: Option<String>,
    pub count: u64,
    /// Bytes for traffic lists, highest severity word for alert lists.
    pub value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IncidentRow {
    pub id: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub src_ip: String,
    pub severity: String,
    pub alert_count: u64,
    pub kinds: Vec<String>,
    pub tactics: Vec<String>,
    pub targets: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AlertRow {
    pub id: u64,
    pub incident_id: Option<u64>,
    pub kind: String,
    pub severity: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub src_ip: String,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub count: u64,
    /// The kind-specific facts, exactly as the engine wrote them.
    pub details: serde_json::Value,
    pub attack: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FlowRow {
    pub id: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub tcp_outcome: Option<String>,
}

/// Everything the incident page needs in one answer.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IncidentDetail {
    pub incident: IncidentRow,
    /// Oldest first: this is the storyline.
    pub alerts: Vec<AlertRow>,
    /// Flows from or to the incident's host during the incident (capped).
    pub flows: Vec<FlowRow>,
    pub flows_truncated: bool,
}
