//! SQLite storage for Flagman.
//!
//! The daemon's writer thread calls [`Store::write_outputs`] with everything
//! the engine produced; the API calls the query methods to fill the dashboard.
//! Each side opens its own connection. SQLite's WAL mode lets the dashboard
//! read while the writer writes.
//!
//! All times are stored as milliseconds since the Unix epoch (UTC), and IP
//! addresses as text. No packet payload is ever stored.

mod query_dashboard;
mod query_flows;
mod query_incidents;
mod rows;
mod schema;
mod write;

pub use query_dashboard::TimeRange;
pub use query_flows::FlowFilter;
pub use query_incidents::{INCIDENT_STATUSES, IncidentFilter};
pub use rows::{
    AlertPoint, AlertRow, ClassCounts, FlowRow, IncidentDetail, IncidentRow, NamedCount, Overview,
    SeverityCounts, TalkerRow, TrafficPoint,
};

use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("could not encode or decode stored JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid value: {0}")]
    Invalid(String),
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (and creates if needed) the database file, then applies the schema.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Store::prepare(conn)
    }

    /// An empty database in memory, for tests.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Store::prepare(Connection::open_in_memory()?)
    }

    fn prepare(conn: Connection) -> Result<Store, StoreError> {
        // Wait up to 5 s if the other connection is writing, instead of failing.
        conn.busy_timeout(Duration::from_secs(5))?;
        schema::migrate(&conn)?;
        Ok(Store { conn })
    }
}

/// SQLite stores signed 64-bit integers; our counters are unsigned.
pub(crate) fn to_sql_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The reverse of [`to_sql_int`]: negative values (which we never write) become 0.
pub(crate) fn from_sql_int(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests;
