//! The feature schema: the name, unit, type and meaning of every feature,
//! in the order they are written, with a version number.
//!
//! Every output file stores [`SCHEMA_VERSION`] and [`schema_json`], so a
//! model always knows which features it was trained on. Change the version
//! whenever a feature is added, removed, renamed or computed differently.
//!
//! Columns that are **not** features (addresses, ports, times, how the flow
//! ended) are listed in [`METADATA`], with the reason they must never be
//! model inputs. They are kept only to label flows and split data by day.

use crate::features::{FlowFeatures, SideFeatures};
use crate::port_class::PortClass;
use flagman_core::flow::TcpOutcome;
use serde_json::{Value as Json, json};

pub const SCHEMA_VERSION: u32 = 1;

/// One feature value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    Count(u64),
    /// `None` when not defined for this flow (for example the mean size of
    /// a side that sent nothing).
    Real(Option<f64>),
    Category(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Count,
    Real,
    Category(&'static [&'static str]),
}

pub struct Feature {
    pub name: &'static str,
    pub unit: &'static str,
    pub kind: Kind,
    /// Why this feature could still carry a lab shortcut, for the audit.
    /// `None` when it only describes the traffic's own behaviour.
    pub watch: Option<&'static str>,
    source: Source,
}

/// Where a feature's value comes from: the whole flow, or one side of it.
#[derive(Clone, Copy)]
enum Source {
    Flow(fn(&FlowFeatures) -> Value),
    Fwd(fn(&SideFeatures) -> Value),
    Rev(fn(&SideFeatures) -> Value),
}

impl Feature {
    pub fn value(&self, features: &FlowFeatures) -> Value {
        match self.source {
            Source::Flow(get) => get(features),
            Source::Fwd(get) => get(&features.fwd),
            Source::Rev(get) => get(&features.rev),
        }
    }
}

const PROTOCOLS: &[&str] = &["tcp", "udp", "icmp", "other"];
const OUTCOMES: &[&str] = &[
    "established",
    "half_open",
    "rejected",
    "unanswered",
    "midstream",
    "none",
];

const MSS: &str = "the largest size follows the maximum segment size, which depends on the operating system and the network";
const TIMING: &str = "timing depends on the speed and load of the network where it was recorded";
const DISTANCE: &str =
    "the wait for an answer is the network distance: a lab is much shorter than the internet";

fn flow(
    name: &'static str,
    unit: &'static str,
    kind: Kind,
    watch: Option<&'static str>,
    get: fn(&FlowFeatures) -> Value,
) -> Feature {
    Feature {
        name,
        unit,
        kind,
        watch,
        source: Source::Flow(get),
    }
}

/// The same feature for the initiator (`_fwd`) and the responder (`_rev`).
fn both(
    fwd: &'static str,
    rev: &'static str,
    unit: &'static str,
    kind: Kind,
    watch: Option<&'static str>,
    get: fn(&SideFeatures) -> Value,
) -> [Feature; 2] {
    [
        Feature {
            name: fwd,
            unit,
            kind,
            watch,
            source: Source::Fwd(get),
        },
        Feature {
            name: rev,
            unit,
            kind,
            watch,
            source: Source::Rev(get),
        },
    ]
}

fn real(value: Option<u32>) -> Value {
    Value::Real(value.map(f64::from))
}

fn count(value: impl Into<u64>) -> Value {
    Value::Count(value.into())
}

/// The features, in output order. Kept as a table, one feature per line.
#[rustfmt::skip]
pub fn features() -> Vec<Feature> {
    let mut list = vec![
        flow("protocol", "", Kind::Category(PROTOCOLS), None, |f| Value::Category(f.protocol.as_str())),
        flow("dst_port_class", "", Kind::Category(&PortClass::NAMES), None, |f| Value::Category(f.dst_port_class.as_str())),
        flow("tcp_outcome", "", Kind::Category(OUTCOMES), None, |f| Value::Category(f.tcp_outcome.map_or("none", TcpOutcome::as_str))),
        flow("duration_ms", "ms", Kind::Count, Some(TIMING), |f| count(f.duration_ms)),
        flow("packets_share_rev", "0-1", Kind::Real, None, |f| Value::Real(Some(f.packets_share_rev))),
        flow("payload_share_rev", "0-1", Kind::Real, None, |f| Value::Real(f.payload_share_rev)),
        flow("first_response_ms", "ms", Kind::Real, Some(DISTANCE), |f| Value::Real(f.first_response_ms.map(|ms| ms as f64))),
    ];
    let sides = [
        both("packets_fwd", "packets_rev", "packets", Kind::Count, None, |s| count(s.packets)),
        both("payload_bytes_fwd", "payload_bytes_rev", "bytes", Kind::Count, None, |s| count(s.payload_bytes)),
        both("payload_min_fwd", "payload_min_rev", "bytes", Kind::Real, None, |s| real(s.payload_min)),
        both("payload_max_fwd", "payload_max_rev", "bytes", Kind::Real, Some(MSS), |s| real(s.payload_max)),
        both("payload_mean_fwd", "payload_mean_rev", "bytes", Kind::Real, None, |s| Value::Real(s.payload_mean)),
        both("payload_std_fwd", "payload_std_rev", "bytes", Kind::Real, None, |s| Value::Real(s.payload_std)),
        both("gap_min_ms_fwd", "gap_min_ms_rev", "ms", Kind::Real, Some(TIMING), |s| real(s.gap_min_ms)),
        both("gap_max_ms_fwd", "gap_max_ms_rev", "ms", Kind::Real, Some(TIMING), |s| real(s.gap_max_ms)),
        both("gap_mean_ms_fwd", "gap_mean_ms_rev", "ms", Kind::Real, Some(TIMING), |s| Value::Real(s.gap_mean_ms)),
        both("gap_std_ms_fwd", "gap_std_ms_rev", "ms", Kind::Real, Some(TIMING), |s| Value::Real(s.gap_std_ms)),
        both("syn_fwd", "syn_rev", "packets", Kind::Count, None, |s| count(s.syn)),
        both("fin_fwd", "fin_rev", "packets", Kind::Count, None, |s| count(s.fin)),
        both("rst_fwd", "rst_rev", "packets", Kind::Count, None, |s| count(s.rst)),
        both("empty_packets_fwd", "empty_packets_rev", "packets", Kind::Count, None, |s| count(s.empty_packets)),
        both("ttl_changed_fwd", "ttl_changed_rev", "0/1", Kind::Count, None, |s| count(s.ttl_changed)),
    ];
    list.extend(sides.into_iter().flatten());
    list
}

/// Columns written next to the features, and why each one must never be a
/// model input.
pub const METADATA: [(&str, &str); 7] = [
    (
        "flow_start_ms",
        "clock time: a model would learn the lab's attack schedule, not the attack",
    ),
    ("flow_end_ms", "clock time, as above"),
    (
        "src_ip",
        "an address names one machine of one network, such as the lab's attacker",
    ),
    (
        "src_port",
        "chosen at random by the sender's operating system",
    ),
    (
        "dst_ip",
        "an address names one machine of one network, such as the lab's victim",
    ),
    (
        "dst_port",
        "which port a lab attacked is a property of that lab; the class is a feature",
    ),
    (
        "end_reason",
        "evicted and stopped describe the sensor (full table, end of the capture), not the traffic",
    ),
];

/// The schema as JSON, stored in every output file.
pub fn schema_json() -> Json {
    let features: Vec<Json> = features()
        .iter()
        .map(|f| {
            let (kind, categories) = match f.kind {
                Kind::Count => ("count", None),
                Kind::Real => ("real", None),
                Kind::Category(names) => ("category", Some(names)),
            };
            json!({"name": f.name, "unit": f.unit, "kind": kind, "categories": categories, "watch": f.watch})
        })
        .collect();
    let metadata: Vec<Json> = METADATA
        .iter()
        .map(|(name, why)| json!({"name": name, "never_an_input_because": why}))
        .collect();
    json!({"schema_version": SCHEMA_VERSION, "features": features, "metadata": metadata})
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
