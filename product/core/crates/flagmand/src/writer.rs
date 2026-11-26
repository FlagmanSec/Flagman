//! The storage writer thread (live mode).
//!
//! The capture thread must never wait for the disk, or the kernel would drop
//! packets. So batches go through a channel to this thread, which writes
//! them to SQLite and deletes old data once an hour.
//!
//! The channel holds at most `QUEUE_BATCHES` batches. If the disk is so slow
//! that it fills up, the capture thread waits: packets are then dropped by
//! the kernel and counted in the health strip, never lost silently.

use crate::pipeline::OutputSink;
use anyhow::{Context, Result, anyhow};
use flagman_core::engine::Output;
use flagman_core::health::SensorHealth;
use flagman_core::time::Timestamp;
use flagman_store::Store;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const QUEUE_BATCHES: usize = 64;
/// Batches merged into one transaction at most, when several are waiting.
const MERGE_BATCHES: usize = 16;
const PRUNE_EVERY: Duration = Duration::from_secs(3_600);
const DAY_MS: i64 = 24 * 3_600 * 1_000;

/// How long data is kept.
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    pub flow_days: u32,
    pub incident_days: u32,
}

pub struct Writer {
    sender: SyncSender<Vec<Output>>,
    handle: JoinHandle<()>,
}

/// The capture loop's end of the channel.
pub struct ChannelSink(SyncSender<Vec<Output>>);

impl OutputSink for ChannelSink {
    fn send(&mut self, batch: Vec<Output>) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        self.0
            .send(batch)
            .map_err(|_| anyhow!("the storage writer stopped unexpectedly"))
    }
}

impl Writer {
    pub fn spawn(
        store: Store,
        retention: Retention,
        health: Arc<RwLock<SensorHealth>>,
    ) -> Result<Writer> {
        let (sender, receiver) = sync_channel(QUEUE_BATCHES);
        let handle = std::thread::Builder::new()
            .name("storage".to_string())
            .spawn(move || write_until_closed(store, &receiver, retention, &health))
            .context("could not start the storage thread")?;
        Ok(Writer { sender, handle })
    }

    pub fn sink(&self) -> ChannelSink {
        ChannelSink(self.sender.clone())
    }

    /// Waits until every queued batch is written. Every `ChannelSink` must
    /// have been dropped first, or this waits forever.
    pub fn finish(self) -> Result<()> {
        drop(self.sender);
        self.handle
            .join()
            .map_err(|_| anyhow!("the storage thread crashed"))
    }
}

fn write_until_closed(
    mut store: Store,
    receiver: &Receiver<Vec<Output>>,
    retention: Retention,
    health: &RwLock<SensorHealth>,
) {
    prune(&mut store, retention);
    let mut next_prune = Instant::now() + PRUNE_EVERY;
    loop {
        match receiver.recv_timeout(Duration::from_secs(60)) {
            Ok(mut batch) => {
                for _ in 1..MERGE_BATCHES {
                    match receiver.try_recv() {
                        Ok(more) => batch.extend(more),
                        Err(_) => break,
                    }
                }
                if let Err(error) = store.write_outputs(&batch) {
                    tracing::error!("could not save {} results: {error}", batch.len());
                    if let Ok(mut health) = health.write() {
                        health.storage_errors += 1;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if Instant::now() >= next_prune {
            prune(&mut store, retention);
            next_prune = Instant::now() + PRUNE_EVERY;
        }
    }
}

fn prune(store: &mut Store, retention: Retention) {
    let now = Timestamp::now().millis();
    let flows_before = Timestamp(now - i64::from(retention.flow_days) * DAY_MS);
    let incidents_before = Timestamp(now - i64::from(retention.incident_days) * DAY_MS);
    if let Err(error) = store.prune(flows_before, incidents_before) {
        tracing::warn!("could not delete old data: {error}");
    }
}
