//! Extraction tests on the lab captures (see `product/core/testdata/pcap`).

use super::*;
use flagman_core::flow::FlowRecord;
use flagman_parquet::summary;

/// Each lab capture and its number of flows (see the captures' README):
/// 1,000 scanned ports and 15 SSH connections; 40 page loads, the UDP
/// packets to port 5353 and the pings (one flow each); 24 SSH connections.
const CAPTURES: [(&str, usize); 3] = [
    ("lab-attack-chain.pcap", 1_015),
    ("lab-normal-traffic.pcap", 42),
    ("lab-ssh-logins.pcap", 24),
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pcap")
        .join(name)
}

/// Keeps every finished flow, whatever its type.
struct Collect<F>(Vec<F>);

impl<F> OutputSink<F> for Collect<F> {
    fn send(&mut self, batch: Vec<Output<F>>) -> Result<()> {
        for output in batch {
            if let Output::Flow(flow) = output {
                self.0.push(flow);
            }
        }
        Ok(())
    }
}

#[test]
fn features_come_from_exactly_the_flows_the_sensor_sees() {
    let config = Config::default().engine();
    for (name, count) in CAPTURES {
        let mut sensor = Engine::new(&config, StartIds::default());
        let mut records = Collect(Vec::new());
        let mut source = FileSource::open(&fixture(name)).unwrap();
        pipeline::capture_loop(&mut source, &mut sensor, &mut records, None).unwrap();

        let mut extractor = Engine::<FeatureState>::with_extra(&config, StartIds::default());
        let mut flows: Collect<FeatureFlow> = Collect(Vec::new());
        let mut source = FileSource::open(&fixture(name)).unwrap();
        pipeline::capture_loop(&mut source, &mut extractor, &mut flows, None).unwrap();

        let extracted: Vec<FlowRecord> = flows.0.iter().map(|flow| flow.record).collect();
        assert_eq!(records.0.len(), count, "{name}");
        assert_eq!(records.0, extracted, "{name}: same flows, same order");
    }
}

#[test]
fn a_file_has_one_row_per_flow_and_says_where_it_comes_from() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("flows.parquet");
    let report = extract_to(
        &fixture("lab-ssh-logins.pcap"),
        &Config::default().engine(),
        &out,
    )
    .unwrap();
    assert_eq!(report.counters.packets, 649);
    assert_eq!(report.flows, 24, "the capture's 24 SSH connections");

    let summary = summary(File::open(&out).unwrap()).unwrap();
    assert_eq!(summary.rows, report.flows);
    let footer = &summary.key_values;
    assert_eq!(footer[flagman_parquet::keys::SOURCE], "lab-ssh-logins.pcap");
    assert_eq!(footer[flagman_parquet::keys::WRITER], WRITER);
    assert!(!partial_path(&out).exists(), "the temporary file is gone");
}

#[test]
fn a_failed_extraction_leaves_no_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.pcap");
    std::fs::write(&broken, b"this is not a capture file").unwrap();
    let out = dir.path().join("flows.parquet");

    assert!(extract_to(&broken, &Config::default().engine(), &out).is_err());
    assert!(!out.exists());
    assert!(!partial_path(&out).exists());
}

#[test]
fn an_existing_file_is_never_replaced_without_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("flows.parquet");
    std::fs::write(&out, b"earlier results").unwrap();
    let mut args = ExtractArgs {
        pcap: fixture("lab-normal-traffic.pcap"),
        out: out.clone(),
        overwrite: false,
        config: None,
    };

    let error = extract(&args).unwrap_err().to_string();
    assert!(error.contains("--overwrite"), "{error}");
    assert_eq!(std::fs::read(&out).unwrap(), b"earlier results");

    args.overwrite = true;
    extract(&args).unwrap();
    assert!(summary(File::open(&out).unwrap()).unwrap().rows > 0);
}
