//! Feature files: the features of every flow, one row per flow, in the
//! Parquet format that Python's data tools read directly.
//!
//! Only `flagmand extract` uses this crate, and only when flagmand is built
//! with its `parquet` feature: the sensor itself never writes Parquet, and
//! the router build (Edge) does not even contain this code.
//!
//! A file holds the metadata columns first (who, when, how the flow ended:
//! never model inputs), then the features, in the order of
//! `flagman_features::schema`. Its footer stores the schema version, the
//! schema as JSON, the flow table's settings, the capture's name and the
//! program that wrote it. The README describes every column.
//!
//! The same rows always give the same bytes: nothing in the file depends on
//! the clock or on the machine.

mod columns;
mod read;
mod writer;

pub use read::{FileSummary, summary};
pub use writer::{FeatureFileWriter, FileInfo, ROWS_PER_GROUP, keys};
