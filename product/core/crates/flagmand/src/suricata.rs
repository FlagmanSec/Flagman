//! The Suricata reader thread (live mode).
//!
//! Every half second it reads the lines Suricata appended to `eve.json`,
//! keeps the alerts, and hands them to the capture thread, which feeds them
//! to the engine. Suricata does not need to be installed: the health strip
//! then shows that Flagman is waiting for the file.

use flagman_core::detect::SignatureHit;
use flagman_core::health::SensorHealth;
use flagman_suricata::{EveTailer, parse_alert_line};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

const POLL_EVERY: Duration = Duration::from_millis(500);

pub fn spawn(
    eve_path: PathBuf,
    hits: SyncSender<SignatureHit>,
    health: Arc<RwLock<SensorHealth>>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("suricata".to_string())
        .spawn(move || follow(&eve_path, &hits, &health, &stop))
}

fn follow(
    eve_path: &std::path::Path,
    hits: &SyncSender<SignatureHit>,
    health: &RwLock<SensorHealth>,
    stop: &AtomicBool,
) {
    // Live mode: alerts already in the file are old news.
    let mut tailer = EveTailer::new(eve_path, true);
    while !stop.load(Ordering::Relaxed) {
        let (reading, error, mut found) = match tailer.read_new_lines() {
            Ok(lines) => (true, None, lines),
            Err(error) if error.kind() == ErrorKind::NotFound => (
                false,
                Some(format!(
                    "waiting for {}: is Suricata installed and running?",
                    eve_path.display()
                )),
                Vec::new(),
            ),
            Err(error) => (false, Some(error.to_string()), Vec::new()),
        };
        let mut new_hits = 0;
        for line in found.drain(..) {
            if let Some(hit) = parse_alert_line(&line) {
                new_hits += 1;
                if hits.send(hit).is_err() {
                    return; // the capture loop has stopped
                }
            }
        }
        if let Ok(mut health) = health.write() {
            health.suricata.reading = reading;
            health.suricata.hits += new_hits;
            health.suricata.last_error = error;
        }
        std::thread::sleep(POLL_EVERY);
    }
}
