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
    /// Failed attempts on the same login service within the window: refused
    /// connections, or connections closed within `max_attempt_secs`.
    pub min_attempts: usize,
    /// A connection that stays open longer than this is a working session,
    /// not a failed attempt. 30 s covers a full round of six wrong passwords
    /// (17.8 s in the lab recording `lab-ssh-logins.pcap`), with room for
    /// slower servers.
    pub max_attempt_secs: i64,
    /// Failed attempts needed when the server is on the internet (outside the
    /// home network). Higher than `min_attempts`, because your own devices
    /// log in to internet servers all the time (git over SSH, backups), and a
    /// quick successful login looks like a failed one from packet headers.
    /// A device that guesses passwords on an internet server faster than
    /// this is reported; it may be infected and attacking others.
    pub outbound_min_attempts: usize,
    /// Only watch login services inside the home network (private addresses).
    /// When true, servers on the internet are never watched and
    /// `outbound_min_attempts` is not used.
    pub local_targets_only: bool,
    /// Services that ask for a password.
    pub ports: Vec<u16>,
    /// Login attempts that are never reported, each one a source, a target
    /// and a port: for example your own script that logs in to a machine at
    /// home again and again. Unlike `ignore_sources`, the source stays
    /// watched by every other detector, and for every other login.
    pub ignore_logins: Vec<LoginException>,
}

/// One login that the brute force detector must not report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginException {
    /// The device that logs in.
    pub source: IpAddr,
    /// The server it logs in to.
    pub target: IpAddr,
    /// The server's port, for example 22 for SSH.
    pub port: u16,
}

impl Default for BruteForceConfig {
    fn default() -> BruteForceConfig {
        BruteForceConfig {
            window_secs: 60,
            min_attempts: 10,
            max_attempt_secs: 30,
            outbound_min_attempts: 30,
            local_targets_only: false,
            // FTP, SSH, Telnet, POP3, IMAP, SMB, MSSQL, MySQL, RDP, PostgreSQL, VNC
            ports: vec![21, 22, 23, 110, 143, 445, 1433, 3306, 3389, 5432, 5900],
            ignore_logins: Vec::new(),
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
    /// Hosts whose behaviour is never reported, by any detector (for example
    /// a router that sweeps the network on purpose to list devices). To
    /// silence only one login, use `brute_force.ignore_logins` instead.
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
