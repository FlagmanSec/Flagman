//! The sensor's health, shown in the dashboard's health strip.
//! The daemon updates it every second; the API reads it.

use crate::time::Timestamp;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct SuricataHealth {
    pub enabled: bool,
    pub eve_path: Option<String>,
    /// True once the EVE file has been opened successfully.
    pub reading: bool,
    pub hits: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SensorHealth {
    pub version: String,
    /// "live" or "replay".
    pub mode: String,
    /// The interface name (live) or the capture file name (replay).
    pub source: String,
    pub started_at: Timestamp,
    pub last_packet_at: Option<Timestamp>,
    pub packets: u64,
    pub bytes: u64,
    /// Packets that were neither IP nor ARP, or cut too short to read.
    pub packets_skipped: u64,
    /// Packets the kernel handed to us, and packets it had to drop because
    /// Flagman was too slow (live mode only).
    pub kernel_received: Option<u64>,
    pub kernel_dropped: Option<u64>,
    pub flows_active: u64,
    /// Flows ended early because the flow table was full.
    pub flows_evicted: u64,
    /// Entries the detectors forgot because they were full (the least active
    /// ones). Above zero, the dashboard shows "Detector saturated".
    pub detector_evicted: u64,
    /// The last time the flow table or a detector was full.
    pub saturated_at: Option<Timestamp>,
    pub suricata: SuricataHealth,
    /// Batches the storage writer failed to save (for example, disk full).
    pub storage_errors: u64,
    /// True while the capture loop is running.
    pub running: bool,
}
