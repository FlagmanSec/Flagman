//! The capture loop, shared by live mode and replay mode.
//!
//! ```text
//! packet source ──> engine ──> batches of outputs ──> sink (storage)
//!                     ^
//!   Suricata hits ────┘ (live mode only)
//! ```
//!
//! Outputs are sent in batches (at most every half second, or every 1,000
//! outputs), so the database sees a few transactions per second instead of
//! one per packet.

use anyhow::Result;
use flagman_capture::{NextFrame, PacketSource};
use flagman_core::detect::SignatureHit;
use flagman_core::engine::{Engine, Output};
use flagman_core::health::SensorHealth;
use flagman_core::time::Timestamp;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

const FLUSH_AT_OUTPUTS: usize = 1_000;
const FLUSH_EVERY: Duration = Duration::from_millis(500);
const HEALTH_EVERY: Duration = Duration::from_secs(1);

/// Where batches of outputs go: the writer thread (live) or the database
/// directly (replay).
pub trait OutputSink {
    fn send(&mut self, batch: Vec<Output>) -> Result<()>;
}

/// What only live mode has.
pub struct LiveHooks<'a> {
    /// Set by Ctrl-C or SIGTERM.
    pub stop: &'a AtomicBool,
    /// Rule matches from the Suricata reader, if enabled.
    pub hits: Option<&'a Receiver<SignatureHit>>,
    pub health: &'a RwLock<SensorHealth>,
}

/// Reads packets until the source ends (file) or `stop` is set (live), then
/// flushes everything the engine still holds.
pub fn capture_loop(
    source: &mut dyn PacketSource,
    engine: &mut Engine,
    sink: &mut dyn OutputSink,
    live: Option<LiveHooks<'_>>,
) -> Result<()> {
    let link = source.link_type();
    let mut out = Vec::new();
    let mut last_flush = Instant::now();
    let mut last_health: Option<Instant> = None;
    loop {
        if live
            .as_ref()
            .is_some_and(|hooks| hooks.stop.load(Ordering::Relaxed))
        {
            break;
        }
        match source.next_frame()? {
            NextFrame::Packet(frame) => {
                engine.process_frame(link, frame.ts, frame.wire_len, frame.data, &mut out);
            }
            // A quiet moment on a live interface: run the timeouts anyway.
            NextFrame::Timeout => engine.tick(Timestamp::now(), &mut out),
            NextFrame::End => break,
        }
        if let Some(hooks) = &live {
            if let Some(hits) = hooks.hits {
                while let Ok(hit) = hits.try_recv() {
                    engine.process_signature(hit, &mut out);
                }
            }
            if last_health.is_none_or(|at| at.elapsed() >= HEALTH_EVERY) {
                update_health(hooks.health, source, engine);
                last_health = Some(Instant::now());
            }
        }
        let due = !out.is_empty() && last_flush.elapsed() >= FLUSH_EVERY;
        if out.len() >= FLUSH_AT_OUTPUTS || due {
            sink.send(std::mem::take(&mut out))?;
            last_flush = Instant::now();
        }
    }
    engine.finish(&mut out);
    if let Some(hooks) = &live {
        update_health(hooks.health, source, engine);
    }
    sink.send(out)
}

/// Copies the engine's and the kernel's counters into the shared health.
fn update_health(health: &RwLock<SensorHealth>, source: &mut dyn PacketSource, engine: &Engine) {
    let counters = engine.counters();
    let stats = source.stats();
    let Ok(mut health) = health.write() else {
        return;
    };
    health.packets = counters.packets;
    health.bytes = counters.bytes;
    health.packets_skipped = counters.packets_skipped;
    health.flows_active = counters.flows_active;
    health.flows_evicted = counters.flows_evicted;
    health.detector_evicted = counters.detector_evicted;
    health.saturated_at = counters.saturated_at;
    health.last_packet_at = counters.last_packet_at;
    health.kernel_received = stats.map(|stats| stats.received);
    health.kernel_dropped = stats.map(|stats| stats.dropped);
}
