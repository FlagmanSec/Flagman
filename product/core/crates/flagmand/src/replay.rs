//! `flagmand replay capture.pcap`: replay mode.
//!
//! Runs the same engine as live mode on a capture file, saves the results in
//! a database file, prints a summary, and (with `--serve`) opens the results
//! in the dashboard. Use it to test the detectors on known traffic, or to
//! look at a capture someone sent you.
//!
//! In the dashboard, "last hour" means the last hour of the capture, not of
//! the wall clock ([`Clock::LatestData`]).

use crate::cli::ReplayArgs;
use crate::config::Config;
use crate::pipeline::{self, OutputSink};
use crate::server;
use crate::shutdown::Shutdown;
use crate::token;
use anyhow::{Context, Result, bail};
use flagman_api::{ApiState, Clock};
use flagman_capture::{FileSource, PacketSource};
use flagman_core::engine::{Engine, EngineCounters, Output, StartIds};
use flagman_core::health::SensorHealth;
use flagman_core::time::Timestamp;
use flagman_store::{AlertRow, IncidentFilter, Store};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

pub fn replay(args: &ReplayArgs) -> Result<()> {
    let config = Config::load(args.config.as_deref())?;
    prepare_database(&args.db, args.overwrite)?;
    let mut store =
        Store::open(&args.db).with_context(|| format!("could not create {}", args.db.display()))?;
    let summary = analyse(&args.pcap, &config, &mut store)?;
    print_summary(&summary, &store)?;
    println!("Results saved in {}.", args.db.display());
    if args.serve {
        let ui_dir = args.ui_dir.clone().unwrap_or(config.api.ui_dir);
        serve(args, &ui_dir, store, &summary)?;
    }
    Ok(())
}

/// What a replay went through.
pub struct Summary {
    pub source: String,
    pub counters: EngineCounters,
    pub seconds: f64,
}

/// Runs the whole capture file through the engine into `store`.
pub fn analyse(pcap: &Path, config: &Config, store: &mut Store) -> Result<Summary> {
    let mut source = FileSource::open(pcap)?;
    let (last_alert_id, last_incident_id) = store.last_ids()?;
    let mut engine = Engine::new(
        &config.engine(),
        StartIds {
            last_alert_id,
            last_incident_id,
        },
    );
    let started = Instant::now();
    pipeline::capture_loop(&mut source, &mut engine, &mut StoreSink { store }, None)?;
    Ok(Summary {
        source: source.describe(),
        counters: engine.counters(),
        seconds: started.elapsed().as_secs_f64(),
    })
}

/// Replay writes straight to the database: there is no capture to protect.
struct StoreSink<'a> {
    store: &'a mut Store,
}

impl OutputSink for StoreSink<'_> {
    fn send(&mut self, batch: Vec<Output>) -> Result<()> {
        self.store.write_outputs(&batch)?;
        Ok(())
    }
}

/// A replay starts from an empty database, so results never mix.
fn prepare_database(path: &Path, overwrite: bool) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if !overwrite {
        bail!(
            "{} already exists; add --overwrite to replace it, or choose another file with --db",
            path.display()
        );
    }
    for suffix in ["", "-wal", "-shm"] {
        let file = format!("{}{suffix}", path.display());
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("could not delete {file}")),
        }
    }
    Ok(())
}

fn print_summary(summary: &Summary, store: &Store) -> Result<()> {
    let counters = summary.counters;
    println!(
        "Replayed {}: {} packets ({} unreadable) in {:.2} s.",
        summary.source, counters.packets, counters.packets_skipped, summary.seconds
    );
    let incidents = store.incidents(&IncidentFilter {
        limit: 100,
        ..IncidentFilter::default()
    })?;
    match incidents.len() {
        0 => println!("No incidents found."),
        1 => println!("1 incident found:"),
        n => println!("{n} incidents found:"),
    }
    for incident in incidents.iter().rev() {
        println!(
            "  #{} {} from {}, {} to {}",
            incident.id,
            incident.severity,
            incident.src_ip,
            format_time(incident.first_seen),
            format_time(incident.last_seen)
        );
        let Some(detail) = store.incident_detail(incident.id)? else {
            continue;
        };
        for alert in detail.alerts.iter().rev() {
            println!("      {}", describe_alert(alert));
        }
    }
    Ok(())
}

/// One line per alert: "port scan of 192.168.1.10: 1000 ports".
fn describe_alert(alert: &AlertRow) -> String {
    let (name, unit) = match alert.kind.as_str() {
        "port_scan" => ("port scan", "ports"),
        "host_sweep" => ("host sweep", "hosts"),
        "brute_force" => ("login attempts", "connections"),
        "signature" => ("Suricata rule", "matches"),
        other => (other, "events"),
    };
    let target = match (&alert.dst_ip, alert.dst_port) {
        (Some(ip), Some(port)) => format!(" on {ip} port {port}"),
        (Some(ip), None) => format!(" of {ip}"),
        _ => String::new(),
    };
    format!(
        "{name}{target}: {} {unit} [{}]",
        alert.count, alert.severity
    )
}

fn format_time(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| millis.to_string())
}

/// Serves the results until Ctrl-C, with a one-time token.
fn serve(args: &ReplayArgs, ui_dir: &Path, store: Store, summary: &Summary) -> Result<()> {
    let listener = server::bind(args.listen)?;
    let shutdown = Shutdown::install()?;
    let token = token::generate()?;
    let counters = summary.counters;
    let health = SensorHealth {
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: "replay".to_string(),
        source: summary.source.clone(),
        started_at: Timestamp::now(),
        last_packet_at: counters.last_packet_at,
        packets: counters.packets,
        bytes: counters.bytes,
        packets_skipped: counters.packets_skipped,
        flows_untracked: counters.flows_untracked,
        ..SensorHealth::default()
    };
    let state = ApiState {
        store: Arc::new(Mutex::new(store)),
        health: Arc::new(RwLock::new(health)),
        token: Arc::from(token.as_str()),
        clock: Clock::LatestData,
    };
    let web = server::start(
        listener,
        state,
        server::usable_ui_dir(ui_dir),
        shutdown.notify.clone(),
    )?;
    println!(
        "Dashboard: {}  (Ctrl-C to stop)",
        token::dashboard_url(args.listen, &token)
    );
    web.join()
}

#[cfg(test)]
mod tests;
