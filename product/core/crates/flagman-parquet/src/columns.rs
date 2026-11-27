//! The columns of a feature file, in order: the metadata first (never model
//! inputs), then the features, in the order of the feature schema.
//!
//! | Column | Parquet type | Empty values |
//! |---|---|---|
//! | `flow_start_ms`, `flow_end_ms` | INT64, milliseconds since 1970-01-01 UTC | never |
//! | `src_ip`, `dst_ip` | STRING | never |
//! | `src_port`, `dst_port` | INT32 (0 for ICMP and other protocols) | never |
//! | `end_reason` and the category features | STRING | never |
//! | count features | INT64 | never |
//! | real features | DOUBLE | null when not defined for the flow |

use flagman_core::flow::FlowRecord;
use flagman_features::FeatureFlow;
use flagman_features::schema::{self, Feature, Kind, Value};
use parquet::basic::{LogicalType, Repetition, Type as Physical};
use parquet::data_type::{ByteArray, ByteArrayType, DoubleType, Int32Type, Int64Type};
use parquet::errors::{ParquetError, Result};
use parquet::file::writer::SerializedColumnWriter;
use parquet::schema::types::{Type, TypePtr};
use std::sync::Arc;

/// A metadata column: who talked to whom, when, and how the flow ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Meta {
    FlowStartMs,
    FlowEndMs,
    SrcIp,
    SrcPort,
    DstIp,
    DstPort,
    EndReason,
}

/// In the order of `flagman_features::schema::METADATA` (a test checks).
pub(crate) const META: [Meta; 7] = [
    Meta::FlowStartMs,
    Meta::FlowEndMs,
    Meta::SrcIp,
    Meta::SrcPort,
    Meta::DstIp,
    Meta::DstPort,
    Meta::EndReason,
];

impl Meta {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Meta::FlowStartMs => "flow_start_ms",
            Meta::FlowEndMs => "flow_end_ms",
            Meta::SrcIp => "src_ip",
            Meta::SrcPort => "src_port",
            Meta::DstIp => "dst_ip",
            Meta::DstPort => "dst_port",
            Meta::EndReason => "end_reason",
        }
    }
}

const INT32: Physical = Physical::INT32;
const INT64: Physical = Physical::INT64;
const DOUBLE: Physical = Physical::DOUBLE;
/// Text is stored as bytes, marked as UTF-8 strings.
const TEXT: Physical = Physical::BYTE_ARRAY;
const REQUIRED: Repetition = Repetition::REQUIRED;
const OPTIONAL: Repetition = Repetition::OPTIONAL;

pub(crate) enum Column {
    Meta(Meta),
    Feature(Feature),
}

impl Column {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Column::Meta(meta) => meta.name(),
            Column::Feature(feature) => feature.name,
        }
    }

    fn parquet_type(&self) -> Result<TypePtr> {
        let (physical, repetition) = match self {
            Column::Meta(Meta::FlowStartMs | Meta::FlowEndMs) => (INT64, REQUIRED),
            Column::Meta(Meta::SrcPort | Meta::DstPort) => (INT32, REQUIRED),
            Column::Meta(Meta::SrcIp | Meta::DstIp | Meta::EndReason) => (TEXT, REQUIRED),
            Column::Feature(feature) => match feature.kind {
                Kind::Count => (INT64, REQUIRED),
                Kind::Real => (DOUBLE, OPTIONAL),
                Kind::Category(_) => (TEXT, REQUIRED),
            },
        };
        let text = (physical == TEXT).then_some(LogicalType::String);
        let column = Type::primitive_type_builder(self.name(), physical)
            .with_repetition(repetition)
            .with_logical_type(text)
            .build()?;
        Ok(Arc::new(column))
    }

    /// Writes this column's values for a batch of rows.
    pub(crate) fn write(
        &self,
        rows: &[FeatureFlow],
        out: &mut SerializedColumnWriter<'_>,
    ) -> Result<()> {
        match self {
            Column::Meta(meta) => write_meta(*meta, rows.iter().map(|row| &row.record), out),
            Column::Feature(feature) => write_feature(feature, rows, out),
        }
    }
}

/// Every column, in file order.
pub(crate) fn all() -> Vec<Column> {
    let meta = META.into_iter().map(Column::Meta);
    let features = schema::features().into_iter().map(Column::Feature);
    meta.chain(features).collect()
}

/// The file's schema: one flat list of columns.
pub(crate) fn message_type(columns: &[Column]) -> Result<Type> {
    let fields = columns
        .iter()
        .map(Column::parquet_type)
        .collect::<Result<Vec<_>>>()?;
    Type::group_type_builder("flagman_flows")
        .with_fields(fields)
        .build()
}

fn write_meta<'a>(
    meta: Meta,
    records: impl Iterator<Item = &'a FlowRecord>,
    out: &mut SerializedColumnWriter<'_>,
) -> Result<()> {
    match meta {
        Meta::FlowStartMs => int64(out, records.map(|r| r.first_seen.0).collect()),
        Meta::FlowEndMs => int64(out, records.map(|r| r.last_seen.0).collect()),
        Meta::SrcIp => text(out, records.map(|r| r.initiator.ip.to_string())),
        Meta::SrcPort => int32(out, records.map(|r| i32::from(r.initiator.port)).collect()),
        Meta::DstIp => text(out, records.map(|r| r.responder.ip.to_string())),
        Meta::DstPort => int32(out, records.map(|r| i32::from(r.responder.port)).collect()),
        Meta::EndReason => text(out, records.map(|r| r.end.as_str())),
    }
}

fn write_feature(
    feature: &Feature,
    rows: &[FeatureFlow],
    out: &mut SerializedColumnWriter<'_>,
) -> Result<()> {
    let values = rows.iter().map(|row| feature.value(&row.features));
    let wrong = |value: Value| {
        ParquetError::General(format!(
            "feature {}: the value {value:?} does not match its kind",
            feature.name
        ))
    };
    match feature.kind {
        Kind::Count => {
            let counts = values
                .map(|value| match value {
                    // Counts never come near i64::MAX; saturate rather than wrap.
                    Value::Count(n) => Ok(i64::try_from(n).unwrap_or(i64::MAX)),
                    other => Err(wrong(other)),
                })
                .collect::<Result<Vec<i64>>>()?;
            int64(out, counts)
        }
        Kind::Real => {
            // Parquet stores only the present values, plus one "definition
            // level" per row: 1 when the value is there, 0 for a null.
            let mut present = Vec::with_capacity(rows.len());
            let mut levels = Vec::with_capacity(rows.len());
            for value in values {
                match value {
                    Value::Real(Some(x)) => {
                        present.push(x);
                        levels.push(1);
                    }
                    Value::Real(None) => levels.push(0),
                    other => return Err(wrong(other)),
                }
            }
            out.typed::<DoubleType>()
                .write_batch(&present, Some(&levels), None)?;
            Ok(())
        }
        Kind::Category(_) => {
            let names = values
                .map(|value| match value {
                    Value::Category(name) => Ok(name),
                    other => Err(wrong(other)),
                })
                .collect::<Result<Vec<&str>>>()?;
            text(out, names.into_iter())
        }
    }
}

fn int64(out: &mut SerializedColumnWriter<'_>, values: Vec<i64>) -> Result<()> {
    out.typed::<Int64Type>().write_batch(&values, None, None)?;
    Ok(())
}

fn int32(out: &mut SerializedColumnWriter<'_>, values: Vec<i32>) -> Result<()> {
    out.typed::<Int32Type>().write_batch(&values, None, None)?;
    Ok(())
}

fn text<S: AsRef<str>>(
    out: &mut SerializedColumnWriter<'_>,
    values: impl Iterator<Item = S>,
) -> Result<()> {
    let values: Vec<ByteArray> = values.map(|s| ByteArray::from(s.as_ref())).collect();
    out.typed::<ByteArrayType>()
        .write_batch(&values, None, None)?;
    Ok(())
}
