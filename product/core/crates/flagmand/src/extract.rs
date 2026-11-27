//! `flagmand extract capture.pcap --out flows.parquet`: the features of
//! every flow in a capture, one row per flow, to train models (phase 3).
//!
//! It runs the sensor's own capture loop ([`pipeline::capture_loop`]) and
//! engine on the file, like `flagmand replay`, with one difference: the
//! flow table also computes each flow's features (`Engine<FeatureState>`,
//! see `flagman-features`). The detectors run too, exactly as in a replay,
//! but their alerts are not written. So the features of a recorded flow
//! come from the same code, packet by packet, as in the live sensor.
//!
//! The same capture always gives a byte-identical file (`tests/extract.rs`
//! checks it): the packets' own timestamps drive every timeout, and the
//! flow table breaks ties by flow key. Rows come in the order flows ended.
//!
//! The file is written under a temporary name (`.partial` added) and only
//! renamed once complete, so a failed run never leaves a half-written file
//! that looks finished.

use crate::cli::ExtractArgs;
use crate::config::Config;
use crate::pipeline::{self, OutputSink};
use anyhow::{Context, Result, bail};
use flagman_capture::{FileSource, PacketSource};
use flagman_core::engine::{Engine, EngineConfig, EngineCounters, Output, StartIds};
use flagman_features::{FeatureFlow, FeatureState, SCHEMA_VERSION};
use flagman_parquet::{FeatureFileWriter, FileInfo};
use std::fs::File;
use std::io::{BufWriter, IntoInnerError, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The program and version stored in every file.
const WRITER: &str = concat!("flagmand ", env!("CARGO_PKG_VERSION"));

pub fn extract(args: &ExtractArgs) -> Result<()> {
    let config = Config::load(args.config.as_deref())?;
    if args.out.exists() && !args.overwrite {
        bail!(
            "{} already exists; add --overwrite to replace it, or choose another file with --out",
            args.out.display()
        );
    }
    let started = Instant::now();
    let report = extract_to(&args.pcap, &config.engine(), &args.out)?;
    print_report(&report, &args.out, started.elapsed().as_secs_f64());
    Ok(())
}

/// What an extraction went through.
pub struct Report {
    pub source: String,
    pub counters: EngineCounters,
    pub flows: u64,
}

/// Writes the features of every flow in `pcap` to `out`.
pub fn extract_to(pcap: &Path, engine: &EngineConfig, out: &Path) -> Result<Report> {
    let partial = partial_path(out);
    match write_file(pcap, engine, &partial) {
        Ok(report) => {
            std::fs::rename(&partial, out).with_context(|| {
                format!(
                    "could not rename {} to {}",
                    partial.display(),
                    out.display()
                )
            })?;
            Ok(report)
        }
        Err(error) => {
            // Nothing useful is left in a file that stopped half way.
            let _ = std::fs::remove_file(&partial);
            Err(error)
        }
    }
}

fn write_file(pcap: &Path, config: &EngineConfig, path: &Path) -> Result<Report> {
    let mut source = FileSource::open(pcap)?;
    let name = source.describe();
    let file =
        File::create(path).with_context(|| format!("could not create {}", path.display()))?;
    let info = FileInfo {
        source: &name,
        flow_table: &config.flows,
        writer: WRITER,
    };
    let mut sink = FeatureSink {
        writer: FeatureFileWriter::new(BufWriter::new(file), &info)?,
    };
    let mut engine = Engine::<FeatureState>::with_extra(config, StartIds::default());
    pipeline::capture_loop(&mut source, &mut engine, &mut sink, None)?;
    let (buffer, flows) = sink.writer.finish()?;
    let file = buffer.into_inner().map_err(IntoInnerError::into_error)?;
    file.sync_all()
        .with_context(|| format!("could not save {}", path.display()))?;
    Ok(Report {
        source: name,
        counters: engine.counters(),
        flows,
    })
}

/// Keeps the finished flows. Alerts, incidents and traffic counts are not
/// part of a feature file.
struct FeatureSink<W: Write + Send> {
    writer: FeatureFileWriter<W>,
}

impl<W: Write + Send> OutputSink<FeatureFlow> for FeatureSink<W> {
    fn send(&mut self, batch: Vec<Output<FeatureFlow>>) -> Result<()> {
        for output in batch {
            if let Output::Flow(flow) = output {
                self.writer.write(flow)?;
            }
        }
        Ok(())
    }
}

/// `flows.parquet` is written as `flows.parquet.partial` until complete.
fn partial_path(out: &Path) -> PathBuf {
    let mut name = out.as_os_str().to_owned();
    name.push(".partial");
    PathBuf::from(name)
}

fn print_report(report: &Report, out: &Path, seconds: f64) {
    let counters = report.counters;
    println!(
        "Extracted {} flows from {}: {} packets ({} unreadable) in {seconds:.2} s.",
        report.flows, report.source, counters.packets, counters.packets_skipped
    );
    if counters.flows_evicted > 0 {
        println!(
            "The flow table was full: {} flows were ended early to make room \
             (end_reason \"evicted\"), so their features are cut short. A larger \
             flows.max_flows in the configuration avoids it.",
            counters.flows_evicted
        );
    }
    println!(
        "Features saved in {} (feature schema version {SCHEMA_VERSION}).",
        out.display()
    );
}

#[cfg(test)]
mod tests;
