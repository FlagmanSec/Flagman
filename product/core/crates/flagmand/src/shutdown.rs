//! Stopping cleanly on Ctrl-C, or on SIGTERM (what `systemctl stop` sends).
//!
//! The first signal asks every thread to finish, so flows and alerts still in
//! memory are saved. A second signal quits at once.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct Shutdown {
    /// Read by the capture and Suricata threads.
    pub stop: Arc<AtomicBool>,
    /// Awaited by the web server.
    pub notify: Arc<Notify>,
}

impl Shutdown {
    /// Installs the signal handler. Call once, early in `main`'s command.
    pub fn install() -> Result<Shutdown> {
        let shutdown = Shutdown {
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        };
        let handler = shutdown.clone();
        ctrlc::set_handler(move || {
            if handler.stop.swap(true, Ordering::SeqCst) {
                eprintln!("flagmand: stopping now");
                std::process::exit(130);
            }
            tracing::info!("stopping (press Ctrl-C again to quit at once)");
            handler.notify.notify_one();
        })
        .context("could not install the Ctrl-C handler")?;
        Ok(shutdown)
    }

    /// Asks everything to stop, as a signal would (used when capture fails).
    pub fn trigger(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }
}
