//! `flagmand run`: live mode.
//!
//! Threads:
//!
//! | Thread | Job |
//! |---|---|
//! | main | capture packets, run the engine (`pipeline.rs`) |
//! | storage | write results to SQLite, delete old data (`writer.rs`) |
//! | suricata | read Suricata's alerts, if enabled (`suricata.rs`) |
//! | web | serve the API and the dashboard (`server.rs`) |
//!
//! Start-up checks everything that can fail (configuration, database, port,
//! token, interface) before any thread starts, so errors are immediate.

use crate::config::Config;
use crate::pipeline::{self, LiveHooks};
use crate::server;
use crate::shutdown::Shutdown;
use crate::suricata;
use crate::token;
use crate::writer::{Retention, Writer};
use anyhow::{Context, Result};
use flagman_api::{ApiState, Clock};
use flagman_capture::{LiveOptions, LiveSource, default_interface, list_interfaces};
use flagman_core::engine::{Engine, StartIds};
use flagman_core::health::{SensorHealth, SuricataHealth};
use flagman_core::time::Timestamp;
use flagman_store::Store;
use std::path::Path;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, RwLock};

/// Suricata alerts waiting for the capture thread, at most.
const HIT_QUEUE: usize = 4_096;

pub fn run(config_path: Option<&Path>, interface: Option<String>) -> Result<()> {
    let config_path = Config::default_path(config_path);
    let config = Config::load(config_path.as_deref())?;
    match &config_path {
        Some(path) => tracing::info!("configuration: {}", path.display()),
        None => tracing::info!("no configuration file: using the defaults"),
    }
    let interface = interface
        .or_else(|| Some(config.capture.interface.clone()).filter(|name| !name.is_empty()))
        .or_else(default_interface)
        .context(
            "no network interface found; choose one with --interface (see `flagmand interfaces`)",
        )?;

    // 1. Storage: one connection for the writer, one for the web server.
    if let Some(parent) = config.storage.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let open = || {
        Store::open(&config.storage.path)
            .with_context(|| format!("could not open {}", config.storage.path.display()))
    };
    let writer_store = open()?;
    let api_store = open()?;
    let (last_alert_id, last_incident_id) = writer_store.last_ids()?;

    // 2. Web server address and token.
    let listener = server::bind(config.api.listen)?;
    let token = token::load_or_create(&config.api.token_file)?;

    // 3. The interface. This is the step that needs CAP_NET_RAW.
    let mut options = LiveOptions::for_interface(&interface);
    options.promiscuous = config.capture.promiscuous;
    options.buffer_bytes = i32::try_from(config.capture.buffer_mib * 1024 * 1024)?;
    let mut source = LiveSource::open(&options).context(
        "capturing needs the CAP_NET_RAW capability: start flagmand with sudo, \
         or through the systemd unit in product/deploy/linux",
    )?;

    // Everything is ready: start the threads.
    let shutdown = Shutdown::install()?;
    let health = Arc::new(RwLock::new(SensorHealth {
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: "live".to_string(),
        source: interface.clone(),
        started_at: Timestamp::now(),
        running: true,
        suricata: SuricataHealth {
            enabled: config.suricata.enabled,
            eve_path: config
                .suricata
                .enabled
                .then(|| config.suricata.eve_path.display().to_string()),
            ..SuricataHealth::default()
        },
        ..SensorHealth::default()
    }));
    let api_state = ApiState {
        store: Arc::new(Mutex::new(api_store)),
        health: health.clone(),
        token: Arc::from(token.as_str()),
        clock: Clock::Live,
    };
    let web = server::start(
        listener,
        api_state,
        server::usable_ui_dir(&config.api.ui_dir),
        shutdown.notify.clone(),
    )?;
    let writer = Writer::spawn(
        writer_store,
        Retention {
            flow_days: config.storage.flow_retention_days,
            incident_days: config.storage.incident_retention_days,
        },
        health.clone(),
    )?;
    let (hit_sender, hit_receiver) = sync_channel(HIT_QUEUE);
    let reader = if config.suricata.enabled {
        Some(suricata::spawn(
            config.suricata.eve_path.clone(),
            hit_sender,
            health.clone(),
            shutdown.stop.clone(),
        )?)
    } else {
        drop(hit_sender);
        None
    };

    tracing::info!("watching {interface}");
    tracing::info!(
        "dashboard: {}",
        token::dashboard_url(config.api.listen, &token)
    );

    let mut engine = Engine::new(
        &config.engine(),
        StartIds {
            last_alert_id,
            last_incident_id,
        },
    );
    let mut sink = writer.sink();
    let result = pipeline::capture_loop(
        &mut source,
        &mut engine,
        &mut sink,
        Some(LiveHooks {
            stop: &shutdown.stop,
            hits: Some(&hit_receiver),
            health: &health,
        }),
    );

    // Stop in order: readers first, then flush storage, then the web server.
    tracing::debug!("capture stopped; stopping the other threads");
    shutdown.trigger();
    if let Ok(mut health) = health.write() {
        health.running = false;
    }
    drop(hit_receiver);
    if let Some(reader) = reader {
        reader.join().ok();
        tracing::debug!("Suricata reader stopped");
    }
    drop(sink);
    writer.finish()?;
    tracing::debug!("storage flushed");
    web.join()?;
    tracing::info!("stopped");
    result
}

/// `flagmand interfaces`
pub fn print_interfaces() -> Result<()> {
    let default = default_interface();
    let interfaces = list_interfaces()?;
    if interfaces.is_empty() {
        println!("No interfaces found. Listing them may need sudo.");
        return Ok(());
    }
    println!("Interfaces Flagman can watch:");
    for interface in interfaces {
        let state = if interface.is_up { "up" } else { "down" };
        let mut notes = Vec::new();
        if interface.is_loopback {
            notes.push("loopback");
        }
        if default.as_deref() == Some(interface.name.as_str()) {
            notes.push("default");
        }
        let addresses = interface.addresses.join(", ");
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        println!("  {:<16} {state:<5} {addresses}{notes}", interface.name);
    }
    Ok(())
}

/// `flagmand token`
pub fn print_token(config_path: Option<&Path>) -> Result<()> {
    let config = Config::load(Config::default_path(config_path).as_deref())?;
    let token = token::load(&config.api.token_file).with_context(|| {
        "the token file is created when flagmand runs for the first time \
         (reading it may need sudo)"
    })?;
    println!("{}", token::dashboard_url(config.api.listen, &token));
    Ok(())
}
