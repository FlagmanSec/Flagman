//! The traffic explorer's query: finished flows, filtered.

use crate::rows::FlowRow;
use crate::{Store, StoreError, from_sql_int};
use flagman_core::time::Timestamp;
use rusqlite::params;

#[derive(Clone, Debug, Default)]
pub struct FlowFilter {
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
    /// Flows where this address is the source or the destination.
    pub ip: Option<String>,
    /// Flows to this destination port.
    pub port: Option<u16>,
    /// "tcp", "udp", "icmp" or "other".
    pub protocol: Option<String>,
    pub limit: u32,
    /// Oldest first (incident pages) instead of newest first (explorer).
    pub oldest_first: bool,
}

impl Store {
    pub fn flows(&self, filter: &FlowFilter) -> Result<Vec<FlowRow>, StoreError> {
        let order = if filter.oldest_first { "ASC" } else { "DESC" };
        // The filter values are bound as parameters (never pasted into the SQL),
        // so a hostile value cannot change the query.
        let sql = format!(
            "SELECT id, first_seen, last_seen, protocol, src_ip, src_port, dst_ip, dst_port,
                    packets_fwd, packets_rev, bytes_fwd, bytes_rev, tcp_outcome
             FROM flows
             WHERE last_seen >= ?1 AND first_seen < ?2
               AND (?3 IS NULL OR src_ip = ?3 OR dst_ip = ?3)
               AND (?4 IS NULL OR dst_port = ?4)
               AND (?5 IS NULL OR protocol = ?5)
             ORDER BY first_seen {order}, id {order} LIMIT ?6"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                filter.since.map_or(i64::MIN, Timestamp::millis),
                filter.until.map_or(i64::MAX, Timestamp::millis),
                filter.ip,
                filter.port,
                filter.protocol,
                filter.limit,
            ],
            |row| {
                Ok(FlowRow {
                    id: from_sql_int(row.get(0)?),
                    first_seen: row.get(1)?,
                    last_seen: row.get(2)?,
                    protocol: row.get(3)?,
                    src_ip: row.get(4)?,
                    src_port: row.get(5)?,
                    dst_ip: row.get(6)?,
                    dst_port: row.get(7)?,
                    packets_fwd: from_sql_int(row.get(8)?),
                    packets_rev: from_sql_int(row.get(9)?),
                    bytes_fwd: from_sql_int(row.get(10)?),
                    bytes_rev: from_sql_int(row.get(11)?),
                    tcp_outcome: row.get(12)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}
