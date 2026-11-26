//! An incident: every alert about one host, close together in time.

use crate::alert::{AlertKind, Severity};
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// The host this incident is about: the source of its alerts (the
    /// scanner, the guesser), except for Suricata alerts on traffic from the
    /// internet to one of your devices, which are filed under that device.
    /// The column keeps its old name, `src_ip`, so stored data stays valid.
    pub src_ip: IpAddr,
    pub severity: Severity,
    /// Number of distinct alerts.
    pub alert_count: u64,
    /// Alert kinds in the order they first appeared: the storyline
    /// (for example port scan, then brute force).
    pub kinds: Vec<AlertKind>,
    /// MITRE ATT&CK tactics, in the order they first appeared.
    pub tactics: Vec<String>,
    /// Hosts that were targeted (at most [`MAX_TARGETS`]), other than the
    /// incident's own host.
    pub targets: Vec<IpAddr>,
}

pub const MAX_TARGETS: usize = 50;
