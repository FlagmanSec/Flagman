//! The database schema. `PRAGMA user_version` records which version a file
//! has, so future changes can be applied as numbered migrations.

use rusqlite::Connection;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    protocol     TEXT    NOT NULL,
    src_ip       TEXT    NOT NULL,
    src_port     INTEGER NOT NULL,
    dst_ip       TEXT    NOT NULL,
    dst_port     INTEGER NOT NULL,
    packets_fwd  INTEGER NOT NULL,
    packets_rev  INTEGER NOT NULL,
    bytes_fwd    INTEGER NOT NULL,
    bytes_rev    INTEGER NOT NULL,
    tcp_outcome  TEXT
);
CREATE INDEX IF NOT EXISTS flows_by_time ON flows (first_seen);
CREATE INDEX IF NOT EXISTS flows_by_src  ON flows (src_ip, first_seen);
CREATE INDEX IF NOT EXISTS flows_by_dst  ON flows (dst_ip, first_seen);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY,
    incident_id  INTEGER,
    kind         TEXT    NOT NULL,
    severity     INTEGER NOT NULL,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT,
    dst_port     INTEGER,
    count        INTEGER NOT NULL,
    details      TEXT    NOT NULL,
    attack       TEXT
);
CREATE INDEX IF NOT EXISTS alerts_by_time     ON alerts (last_seen);
CREATE INDEX IF NOT EXISTS alerts_by_incident ON alerts (incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    src_ip       TEXT    NOT NULL,
    severity     INTEGER NOT NULL,
    alert_count  INTEGER NOT NULL,
    kinds        TEXT    NOT NULL,
    tactics      TEXT    NOT NULL,
    targets      TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'open',
    status_changed_at INTEGER
);
CREATE INDEX IF NOT EXISTS incidents_by_time ON incidents (last_seen);

CREATE TABLE IF NOT EXISTS traffic_minutes (
    minute   INTEGER NOT NULL,
    class    TEXT    NOT NULL,
    packets  INTEGER NOT NULL,
    bytes    INTEGER NOT NULL,
    PRIMARY KEY (minute, class)
);
";

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
    }
    if version < SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}
