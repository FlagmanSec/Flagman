//! Reading back what a feature file says about itself: its rows, columns
//! and footer. `flagmand`'s tests use it; Python reads the files with its
//! own tools.

use parquet::errors::Result;
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::collections::BTreeMap;
use std::fs::File;

#[derive(Clone, Debug, PartialEq)]
pub struct FileSummary {
    pub rows: u64,
    pub row_groups: usize,
    /// Column names, in file order.
    pub columns: Vec<String>,
    /// The footer's key-value pairs (see [`crate::keys`]).
    pub key_values: BTreeMap<String, String>,
}

pub fn summary(file: File) -> Result<FileSummary> {
    let reader = SerializedFileReader::new(file)?;
    let metadata = reader.metadata();
    let file_metadata = metadata.file_metadata();
    let columns = file_metadata
        .schema_descr()
        .columns()
        .iter()
        .map(|column| column.name().to_string())
        .collect();
    let key_values = file_metadata
        .key_value_metadata()
        .into_iter()
        .flatten()
        .map(|pair| (pair.key.clone(), pair.value.clone().unwrap_or_default()))
        .collect();
    Ok(FileSummary {
        rows: u64::try_from(file_metadata.num_rows()).unwrap_or(0),
        row_groups: metadata.num_row_groups(),
        columns,
        key_values,
    })
}
