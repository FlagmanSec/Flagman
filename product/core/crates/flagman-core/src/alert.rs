//! Alerts: what a detector reports when it sees something suspicious.
//!
//! An alert is a "living" finding. A port scan of 1,000 ports produces one
//! alert whose `count` grows while the scan runs, not 1,000 alerts. The same
//! alert id is published again each time it grows; storage overwrites it.

use crate::flow::Protocol;
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// 1 (low) to 4 (critical). Stored in the database so it can be sorted.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn from_rank(rank: u8) -> Severity {
        match rank {
            0 | 1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// One level higher, stopping at critical.
    pub fn raised(self) -> Severity {
        Severity::from_rank(self.rank() + 1)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    PortScan,
    HostSweep,
    BruteForce,
    /// A rule match reported by Suricata.
    Signature,
}

impl AlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::PortScan => "port_scan",
            AlertKind::HostSweep => "host_sweep",
            AlertKind::BruteForce => "brute_force",
            AlertKind::Signature => "signature",
        }
    }
}

/// A MITRE ATT&CK reference: the attacker's goal (tactic) and method (technique).
/// See <https://attack.mitre.org/>.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackRef {
    pub tactic_id: String,
    pub tactic: String,
    pub technique_id: String,
    pub technique: String,
}

/// How a host sweep looked for other machines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SweepMethod {
    Arp,
    Icmp,
    Tcp,
    Udp,
}

/// Facts specific to each kind of alert. The UI turns these into sentences.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertDetails {
    PortScan {
        protocol: Protocol,
        /// Some of the ports that were tried, in ascending order.
        ports_sample: Vec<u16>,
        window_secs: i64,
    },
    HostSweep {
        method: SweepMethod,
        hosts_sample: Vec<IpAddr>,
        window_secs: i64,
    },
    BruteForce {
        service_port: u16,
        window_secs: i64,
    },
    Signature {
        signature_id: u64,
        signature: String,
        category: String,
        /// Which engine produced it, for example "suricata".
        engine: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    /// Set by the incident engine before the alert is stored.
    pub incident_id: Option<u64>,
    pub kind: AlertKind,
    pub severity: Severity,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// Who did it (the scanner, the password guesser...).
    pub src_ip: IpAddr,
    /// Who it was aimed at, when there is a single target.
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    /// Distinct ports (scan), distinct hosts (sweep), attempts (brute force)
    /// or rule hits (signature).
    pub count: u64,
    pub details: AlertDetails,
    pub attack: Option<AttackRef>,
}
