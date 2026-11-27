//! Writing a feature file. Rows go in one at a time; every
//! [`ROWS_PER_GROUP`] rows become one row group (Parquet's unit of
//! storage), so memory stays the same whatever the size of the capture.

use crate::columns::{self, Column};
use flagman_core::flow::FlowTableConfig;
use flagman_features::{FeatureFlow, SCHEMA_VERSION, schema_json};
use parquet::basic::Compression;
use parquet::errors::{ParquetError, Result};
use parquet::file::metadata::KeyValue;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use std::io::Write;
use std::sync::Arc;

/// Rows per row group: about 30 MB of rows waiting in memory at most.
pub const ROWS_PER_GROUP: usize = 65_536;

/// The names of the key-value pairs in the file's footer.
pub mod keys {
    /// The feature schema version, such as "1".
    pub const SCHEMA_VERSION: &str = "flagman.schema_version";
    /// The feature schema as JSON: every feature and metadata column.
    pub const SCHEMA: &str = "flagman.schema";
    /// The flow table's timeouts and limit, as JSON.
    pub const FLOW_TABLE: &str = "flagman.flow_table";
    /// The capture file's name.
    pub const SOURCE: &str = "flagman.source";
    /// The program that wrote the file, such as "flagmand 0.1.0".
    pub const WRITER: &str = "flagman.writer";
}

/// Where a feature file comes from, stored in its footer.
#[derive(Clone, Copy, Debug)]
pub struct FileInfo<'a> {
    /// The capture file's name, without its folder, so the file does not
    /// depend on where the capture was kept.
    pub source: &'a str,
    /// The flow table's settings: they decide where flows are cut, so a
    /// model must be used with the same values.
    pub flow_table: &'a FlowTableConfig,
    /// The program that wrote the file.
    pub writer: &'a str,
}

impl FileInfo<'_> {
    fn key_values(&self) -> Result<Vec<KeyValue>> {
        let flow_table = serde_json::to_string(self.flow_table)
            .map_err(|error| ParquetError::General(error.to_string()))?;
        let pairs = [
            (keys::SCHEMA_VERSION, SCHEMA_VERSION.to_string()),
            (keys::SCHEMA, schema_json().to_string()),
            (keys::FLOW_TABLE, flow_table),
            (keys::SOURCE, self.source.to_string()),
            (keys::WRITER, self.writer.to_string()),
        ];
        Ok(pairs
            .into_iter()
            .map(|(key, value)| KeyValue::new(key.to_string(), value))
            .collect())
    }
}

/// Writes finished flows to a Parquet file, one row per flow.
pub struct FeatureFileWriter<W: Write + Send> {
    file: SerializedFileWriter<W>,
    columns: Vec<Column>,
    rows: Vec<FeatureFlow>,
    rows_per_group: usize,
    written: u64,
}

impl<W: Write + Send> FeatureFileWriter<W> {
    pub fn new(out: W, info: &FileInfo<'_>) -> Result<FeatureFileWriter<W>> {
        FeatureFileWriter::with_group_size(out, info, ROWS_PER_GROUP)
    }

    pub(crate) fn with_group_size(
        out: W,
        info: &FileInfo<'_>,
        rows_per_group: usize,
    ) -> Result<FeatureFileWriter<W>> {
        let columns = columns::all();
        let schema = Arc::new(columns::message_type(&columns)?);
        // Not compressed: compression would need extra libraries in the
        // build, and Python can recompress a file if space matters.
        let properties = WriterProperties::builder()
            .set_compression(Compression::UNCOMPRESSED)
            .set_key_value_metadata(Some(info.key_values()?))
            .build();
        Ok(FeatureFileWriter {
            file: SerializedFileWriter::new(out, schema, Arc::new(properties))?,
            columns,
            rows: Vec::new(),
            rows_per_group: rows_per_group.max(1),
            written: 0,
        })
    }

    /// Adds one finished flow.
    pub fn write(&mut self, flow: FeatureFlow) -> Result<()> {
        self.rows.push(flow);
        if self.rows.len() >= self.rows_per_group {
            self.flush()?;
        }
        Ok(())
    }

    /// Writes the last rows and the footer. Returns the output (so a file
    /// can be synced to disk) and the number of rows written.
    pub fn finish(mut self) -> Result<(W, u64)> {
        self.flush()?;
        let written = self.written;
        Ok((self.file.into_inner()?, written))
    }

    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let mut group = self.file.next_row_group()?;
        for column in &self.columns {
            let Some(mut out) = group.next_column()? else {
                return Err(ParquetError::General(format!(
                    "the file has no room for column {}",
                    column.name()
                )));
            };
            column.write(&self.rows, &mut out)?;
            out.close()?;
        }
        group.close()?;
        self.written += self.rows.len() as u64;
        self.rows.clear();
        Ok(())
    }
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
