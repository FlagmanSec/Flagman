//! The configuration file, `flagman.toml`.
//!
//! Every key is optional: a missing key takes its default, and the example
//! file `product/deploy/linux/flagman.toml` lists them all. Unknown keys are
//! refused, so a typo is reported instead of being silently ignored.

use anyhow::{Context, Result, bail};
use flagman_core::detect::DetectConfig;
use flagman_core::engine::EngineConfig;
use flagman_core::flow::FlowTableConfig;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Where `flagmand run` looks when no `--config` is given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/flagman/flagman.toml";

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub capture: CaptureConfig,
    pub storage: StorageConfig,
    pub api: ApiConfig,
    pub suricata: SuricataConfig,
    pub flows: FlowTableConfig,
    pub detect: DetectConfig,
    pub incidents: IncidentConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// Interface to watch. Empty: the first interface that is up.
    pub interface: String,
    /// See all traffic on the link, not only this machine's.
    pub promiscuous: bool,
    /// Kernel capture buffer, in MiB.
    pub buffer_mib: u32,
}

impl Default for CaptureConfig {
    fn default() -> CaptureConfig {
        CaptureConfig {
            interface: String::new(),
            promiscuous: true,
            buffer_mib: 8,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// The SQLite database file.
    pub path: PathBuf,
    /// Flows and traffic counts older than this are deleted.
    pub flow_retention_days: u32,
    /// Incidents and alerts older than this are deleted.
    pub incident_retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            path: PathBuf::from("/var/lib/flagman/flagman.db"),
            flow_retention_days: 7,
            incident_retention_days: 90,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    /// Address of the dashboard. Keep 127.0.0.1 unless you need to open the
    /// dashboard from another device (see docs/threat-model.md).
    pub listen: SocketAddr,
    /// File holding the dashboard's access token (created on first start).
    pub token_file: PathBuf,
    /// Folder holding the built dashboard. Empty: serve the API only.
    pub ui_dir: PathBuf,
}

impl Default for ApiConfig {
    fn default() -> ApiConfig {
        ApiConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 8750)),
            token_file: PathBuf::from("/var/lib/flagman/api-token"),
            ui_dir: PathBuf::from("/usr/share/flagman/ui"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SuricataConfig {
    /// Read Suricata's alerts, if Suricata is installed.
    pub enabled: bool,
    /// Suricata's EVE JSON log.
    pub eve_path: PathBuf,
}

impl Default for SuricataConfig {
    fn default() -> SuricataConfig {
        SuricataConfig {
            enabled: true,
            eve_path: PathBuf::from("/var/log/suricata/eve.json"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IncidentConfig {
    /// Alerts from the same host more than this many minutes apart start a
    /// new incident.
    pub gap_minutes: i64,
}

impl Default for IncidentConfig {
    fn default() -> IncidentConfig {
        IncidentConfig { gap_minutes: 30 }
    }
}

impl Config {
    /// Reads and checks a configuration file. `None` gives the defaults.
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let Some(path) = path else {
            return Ok(Config::default());
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read the configuration {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// The `--config` path if given, else the default file if it exists.
    pub fn default_path(given: Option<&Path>) -> Option<PathBuf> {
        match given {
            Some(path) => Some(path.to_path_buf()),
            None => {
                let default = PathBuf::from(DEFAULT_CONFIG_PATH);
                default.exists().then_some(default)
            }
        }
    }

    pub fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// The engine's part of the configuration.
    pub fn engine(&self) -> EngineConfig {
        EngineConfig {
            flows: self.flows.clone(),
            detect: self.detect.clone(),
            incident_gap_secs: self.incidents.gap_minutes * 60,
        }
    }

    /// Refuses values that would break detection or the daemon.
    fn validate(&self) -> Result<()> {
        let detect = &self.detect;
        let positive = [
            ("detect.port_scan.window_secs", detect.port_scan.window_secs),
            (
                "detect.host_sweep.window_secs",
                detect.host_sweep.window_secs,
            ),
            (
                "detect.brute_force.window_secs",
                detect.brute_force.window_secs,
            ),
            ("detect.finding_idle_secs", detect.finding_idle_secs),
            ("detect.update_every_secs", detect.update_every_secs),
            ("flows.tcp_idle_secs", self.flows.tcp_idle_secs),
            ("flows.udp_idle_secs", self.flows.udp_idle_secs),
            ("flows.other_idle_secs", self.flows.other_idle_secs),
            ("flows.closed_linger_secs", self.flows.closed_linger_secs),
            ("flows.active_timeout_secs", self.flows.active_timeout_secs),
            ("incidents.gap_minutes", self.incidents.gap_minutes),
        ];
        for (name, value) in positive {
            if value <= 0 {
                bail!("{name} must be more than 0 (got {value})");
            }
        }
        let at_least_two = [
            (
                "detect.port_scan.min_tcp_ports",
                detect.port_scan.min_tcp_ports,
            ),
            (
                "detect.port_scan.min_udp_ports",
                detect.port_scan.min_udp_ports,
            ),
            ("detect.host_sweep.min_hosts", detect.host_sweep.min_hosts),
            (
                "detect.brute_force.min_attempts",
                detect.brute_force.min_attempts,
            ),
        ];
        for (name, value) in at_least_two {
            if value < 2 {
                bail!("{name} must be at least 2 (got {value})");
            }
        }
        if self.flows.max_flows < 1_000 {
            bail!("flows.max_flows must be at least 1000");
        }
        if !(1..=1_024).contains(&self.capture.buffer_mib) {
            bail!("capture.buffer_mib must be between 1 and 1024");
        }
        if self.storage.flow_retention_days == 0 || self.storage.incident_retention_days == 0 {
            bail!("storage retention must be at least 1 day");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_gives_the_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.api.listen.to_string(), "127.0.0.1:8750");
        assert_eq!(config.engine(), EngineConfig::default());
    }

    #[test]
    fn values_can_be_changed_section_by_section() {
        let config = Config::parse(
            r#"
            [capture]
            interface = "enp3s0"
            [detect]
            ignore_sources = ["192.168.1.1"]
            [detect.port_scan]
            min_tcp_ports = 50
            [incidents]
            gap_minutes = 10
            "#,
        )
        .unwrap();
        assert_eq!(config.capture.interface, "enp3s0");
        assert_eq!(config.detect.port_scan.min_tcp_ports, 50);
        assert_eq!(
            config.detect.port_scan.window_secs, 60,
            "others keep defaults"
        );
        assert_eq!(config.engine().incident_gap_secs, 600);
        assert_eq!(config.detect.ignore_sources.len(), 1);
    }

    #[test]
    fn the_example_file_parses_and_shows_the_real_defaults() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../deploy/linux/flagman.toml");
        let example = Config::load(Some(&path)).unwrap();
        let defaults = Config::default();
        assert_eq!(example.engine(), defaults.engine());
        assert_eq!(example.api.listen, defaults.api.listen);
        assert_eq!(example.api.token_file, defaults.api.token_file);
        assert_eq!(example.api.ui_dir, defaults.api.ui_dir);
        assert_eq!(example.storage.path, defaults.storage.path);
        assert_eq!(example.capture.buffer_mib, defaults.capture.buffer_mib);
        assert_eq!(example.suricata.eve_path, defaults.suricata.eve_path);
    }

    #[test]
    fn typos_and_bad_values_are_reported() {
        let typo = Config::parse("[detect.port_scan]\nmin_tcp_port = 5").unwrap_err();
        assert!(format!("{typo:#}").contains("min_tcp_port"));
        let bad = Config::parse("[detect.host_sweep]\nmin_hosts = 1").unwrap_err();
        assert!(bad.to_string().contains("min_hosts"));
        assert!(Config::parse("[capture]\nbuffer_mib = 0").is_err());
    }
}
