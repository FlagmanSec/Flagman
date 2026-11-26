//! An incident: every alert caused by one host, close together in time.

use crate::alert::{AlertKind, Severity};
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// The host behind every alert of this incident.
    pub src_ip: IpAddr,
    pub severity: Severity,
    /// Number of distinct alerts.
    pub alert_count: u64,
    /// Alert kinds in the order they first appeared: the storyline
    /// (for example port scan, then brute force).
    pub kinds: Vec<AlertKind>,
    /// MITRE ATT&CK tactics, in the order they first appeared.
    pub tactics: Vec<String>,
    /// Hosts that were targeted (at most [`MAX_TARGETS`]).
    pub targets: Vec<IpAddr>,
}

pub const MAX_TARGETS: usize = 50;
