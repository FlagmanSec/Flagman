//! Thresholds of the detectors. Every value can be changed in `flagman.toml`
//! under `[detect]`. The defaults are chosen for a home or small office network.

use serde::Deserialize;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortScanConfig {
    pub window_secs: i64,
    /// Distinct TCP ports one host must try on another within the window.
    pub min_tcp_ports: usize,
    /// UDP needs a higher bar: some applications use several UDP ports.
    pub min_udp_ports: usize,
}

impl Default for PortScanConfig {
    fn default() -> PortScanConfig {
        PortScanConfig {
            window_secs: 60,
            min_tcp_ports: 20,
            min_udp_ports: 30,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostSweepConfig {
    pub window_secs: i64,
    /// Distinct local machines one host must probe within the window.
    pub min_hosts: usize,
}

impl Default for HostSweepConfig {
    fn default() -> HostSweepConfig {
        HostSweepConfig {
            window_secs: 60,
            min_hosts: 15,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BruteForceConfig {
    pub window_secs: i64,
    /// New connections to the same login service within the window.
    pub min_attempts: usize,
    /// Services that ask for a password.
    pub ports: Vec<u16>,
}

impl Default for BruteForceConfig {
    fn default() -> BruteForceConfig {
        BruteForceConfig {
            window_secs: 60,
            min_attempts: 10,
            // FTP, SSH, Telnet, POP3, IMAP, SMB, MSSQL, MySQL, RDP, PostgreSQL, VNC
            ports: vec![21, 22, 23, 110, 143, 445, 1433, 3306, 3389, 5432, 5900],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectConfig {
    pub port_scan: PortScanConfig,
    pub host_sweep: HostSweepConfig,
    pub brute_force: BruteForceConfig,
    /// A finding closes after this many quiet seconds.
    pub finding_idle_secs: i64,
    /// A growing finding is re-published at most this often.
    pub update_every_secs: i64,
    /// Hosts whose behaviour is never reported (for example a router that
    /// sweeps the network on purpose to list devices).
    pub ignore_sources: Vec<IpAddr>,
}

impl Default for DetectConfig {
    fn default() -> DetectConfig {
        DetectConfig {
            port_scan: PortScanConfig::default(),
            host_sweep: HostSweepConfig::default(),
            brute_force: BruteForceConfig::default(),
            finding_idle_secs: 120,
            update_every_secs: 5,
            ignore_sources: Vec::new(),
        }
    }
}
