//! Tests for feature files: write a few flows, read them back.

use super::*;
use crate::columns::META;
use crate::read::summary;
use flagman_core::flow::{Endpoint, FlowEnd, FlowRecord, Protocol, TcpOutcome};
use flagman_core::time::Timestamp;
use flagman_features::schema::{METADATA, features};
use flagman_features::{FlowFeatures, PortClass, SideFeatures};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
use tempfile::NamedTempFile;

/// One side of a flow that sent `packets` packets and `bytes` data bytes.
fn side(packets: u64, bytes: u32) -> SideFeatures {
    let sent = packets > 0;
    let gaps = packets > 1;
    SideFeatures {
        packets,
        payload_bytes: u64::from(bytes),
        payload_min: sent.then_some(0),
        payload_max: sent.then_some(bytes),
        payload_mean: sent.then(|| f64::from(bytes) / packets as f64),
        payload_std: sent.then_some(1.5),
        gap_min_ms: gaps.then_some(1),
        gap_max_ms: gaps.then_some(40),
        gap_mean_ms: gaps.then_some(12.5),
        gap_std_ms: gaps.then_some(3.0),
        syn: u16::from(sent),
        fin: 0,
        rst: 0,
        empty_packets: u32::from(sent),
        ttl_changed: false,
    }
}

/// A flow from `src` to `dst`, with or without an answer.
fn flow(protocol: Protocol, src: &str, dst: &str, dst_port: u16, answered: bool) -> FeatureFlow {
    let record = FlowRecord {
        protocol,
        initiator: Endpoint {
            ip: src.parse().unwrap(),
            port: 40_000,
        },
        responder: Endpoint {
            ip: dst.parse().unwrap(),
            port: dst_port,
        },
        first_seen: Timestamp(1_700_000_000_000),
        last_seen: Timestamp(1_700_000_003_101),
        packets_fwd: 6,
        packets_rev: if answered { 4 } else { 0 },
        bytes_fwd: 1_600,
        bytes_rev: if answered { 900 } else { 0 },
        tcp_outcome: (protocol == Protocol::Tcp).then_some(TcpOutcome::Established),
        end: FlowEnd::Closed,
    };
    let features = FlowFeatures {
        protocol,
        dst_port_class: PortClass::of(protocol, dst_port),
        tcp_outcome: record.tcp_outcome,
        duration_ms: 3_101,
        fwd: side(6, 1_241),
        rev: if answered { side(4, 641) } else { side(0, 0) },
        packets_share_rev: if answered { 0.4 } else { 0.0 },
        payload_share_rev: answered.then_some(641.0 / 1_882.0),
        first_response_ms: answered.then_some(12),
    };
    FeatureFlow { record, features }
}

fn ssh() -> FeatureFlow {
    flow(Protocol::Tcp, "192.168.1.50", "192.168.1.10", 22, true)
}

fn info(config: &FlowTableConfig) -> FileInfo<'_> {
    FileInfo {
        source: "lab.pcap",
        flow_table: config,
        writer: "flagmand test",
    }
}

fn write_file(rows: &[FeatureFlow], rows_per_group: usize) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    let config = FlowTableConfig::default();
    let out = file.reopen().unwrap();
    let mut writer =
        FeatureFileWriter::with_group_size(out, &info(&config), rows_per_group).unwrap();
    for row in rows {
        writer.write(*row).unwrap();
    }
    writer.finish().unwrap();
    file
}

#[test]
fn the_metadata_columns_are_those_of_the_feature_schema() {
    assert_eq!(META.map(|meta| meta.name()), METADATA.map(|(name, _)| name));
}

#[test]
fn a_file_lists_the_metadata_then_the_features_and_stores_its_schema() {
    let file = write_file(&[ssh()], ROWS_PER_GROUP);
    let summary = summary(file.reopen().unwrap()).unwrap();

    let names = METADATA.iter().map(|(name, _)| *name);
    let expected: Vec<&str> = names.chain(features().iter().map(|f| f.name)).collect();
    assert_eq!(summary.columns, expected);
    assert_eq!(summary.rows, 1);

    let footer = &summary.key_values;
    assert_eq!(footer[keys::SCHEMA_VERSION], "1");
    let schema: serde_json::Value = serde_json::from_str(&footer[keys::SCHEMA]).unwrap();
    assert_eq!(schema, schema_json());
    let flow_table: FlowTableConfig = serde_json::from_str(&footer[keys::FLOW_TABLE]).unwrap();
    assert_eq!(flow_table, FlowTableConfig::default());
    assert_eq!(footer[keys::SOURCE], "lab.pcap");
    assert_eq!(footer[keys::WRITER], "flagmand test");
}

#[test]
fn values_read_back_as_written_and_undefined_values_are_null() {
    let one_way = flow(Protocol::Udp, "fe80::1", "fe80::2", 50_000, false);
    let file = write_file(&[ssh(), one_way], ROWS_PER_GROUP);
    let reader = SerializedFileReader::new(file.reopen().unwrap()).unwrap();
    let rows: Vec<_> = reader
        .get_row_iter(None)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let field = |row: usize, name: &str| {
        let mut columns = rows[row].get_column_iter();
        columns
            .find(|(column, _)| column.as_str() == name)
            .unwrap()
            .1
            .clone()
    };
    let text = |value: &str| Field::Str(value.to_string());

    assert_eq!(field(0, "flow_start_ms"), Field::Long(1_700_000_000_000));
    assert_eq!(field(0, "src_ip"), text("192.168.1.50"));
    assert_eq!(field(0, "dst_port"), Field::Int(22));
    assert_eq!(field(0, "end_reason"), text("closed"));
    assert_eq!(field(0, "protocol"), text("tcp"));
    assert_eq!(field(0, "dst_port_class"), text("well_known"));
    assert_eq!(field(0, "tcp_outcome"), text("established"));
    assert_eq!(field(0, "duration_ms"), Field::Long(3_101));
    assert_eq!(field(0, "payload_bytes_rev"), Field::Long(641));
    assert_eq!(field(0, "packets_share_rev"), Field::Double(0.4));
    assert_eq!(field(0, "first_response_ms"), Field::Double(12.0));

    assert_eq!(field(1, "src_ip"), text("fe80::1"));
    assert_eq!(field(1, "protocol"), text("udp"));
    assert_eq!(field(1, "tcp_outcome"), text("none"));
    assert_eq!(field(1, "dst_port_class"), text("dynamic"));
    assert_eq!(field(1, "packets_rev"), Field::Long(0));
    assert_eq!(field(1, "payload_mean_rev"), Field::Null);
    assert_eq!(field(1, "first_response_ms"), Field::Null);
}

#[test]
fn the_same_rows_always_give_the_same_bytes() {
    let config = FlowTableConfig::default();
    let rows: Vec<FeatureFlow> = (0..100u16)
        .map(|i| flow(Protocol::Tcp, "10.0.0.1", "10.0.0.2", 1 + i, i % 3 != 0))
        .collect();
    let bytes = || {
        let mut writer = FeatureFileWriter::new(Vec::new(), &info(&config)).unwrap();
        for row in &rows {
            writer.write(*row).unwrap();
        }
        writer.finish().unwrap().0
    };
    assert_eq!(bytes(), bytes());
}

#[test]
fn rows_are_stored_in_groups_of_a_fixed_size() {
    let file = write_file(&[ssh(); 25], 10);
    let summary = summary(file.reopen().unwrap()).unwrap();
    assert_eq!(summary.rows, 25);
    assert_eq!(summary.row_groups, 3, "10 + 10 + 5 rows");
}

#[test]
fn a_capture_without_flows_gives_a_valid_empty_file() {
    let file = write_file(&[], ROWS_PER_GROUP);
    let summary = summary(file.reopen().unwrap()).unwrap();
    assert_eq!(summary.rows, 0);
    assert_eq!(summary.row_groups, 0);
    assert_eq!(summary.columns.len(), METADATA.len() + features().len());
}
