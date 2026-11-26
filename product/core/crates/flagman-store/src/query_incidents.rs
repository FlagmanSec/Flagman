//! Queries behind the incident pages, and the analyst's status changes.

use crate::query_flows::FlowFilter;
use crate::rows::{AlertRow, IncidentDetail, IncidentRow};
use crate::{Store, StoreError, from_sql_int, to_sql_int};
use flagman_core::alert::Severity;
use flagman_core::time::Timestamp;
use rusqlite::{OptionalExtension, Row, params};

/// The statuses an analyst can give an incident.
pub const INCIDENT_STATUSES: [&str; 4] = ["open", "confirmed", "false_positive", "resolved"];

/// Flows shown on an incident page at most.
const MAX_INCIDENT_FLOWS: u32 = 500;

#[derive(Clone, Debug, Default)]
pub struct IncidentFilter {
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
    /// Only incidents at least this severe.
    pub min_severity: Option<Severity>,
    pub status: Option<String>,
    pub limit: u32,
}

const INCIDENT_COLUMNS: &str =
    "id, first_seen, last_seen, src_ip, severity, alert_count, kinds, tactics, targets, status";

const ALERT_COLUMNS: &str = "id, incident_id, kind, severity, first_seen, last_seen, src_ip, \
                             dst_ip, dst_port, count, details, attack";

impl Store {
    pub fn incidents(&self, filter: &IncidentFilter) -> Result<Vec<IncidentRow>, StoreError> {
        let sql = format!(
            "SELECT {INCIDENT_COLUMNS} FROM incidents
             WHERE last_seen >= ?1 AND first_seen < ?2 AND severity >= ?3
               AND (?4 IS NULL OR status = ?4)
             ORDER BY last_seen DESC LIMIT ?5"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                filter.since.map_or(i64::MIN, Timestamp::millis),
                filter.until.map_or(i64::MAX, Timestamp::millis),
                filter.min_severity.map_or(0, Severity::rank),
                filter.status,
                filter.limit,
            ],
            raw_incident,
        )?;
        rows.map(|row| incident_from_raw(row?)).collect()
    }

    pub fn incident_detail(&self, id: u64) -> Result<Option<IncidentDetail>, StoreError> {
        let sql = format!("SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = ?1");
        let raw = self
            .conn
            .query_row(&sql, [to_sql_int(id)], raw_incident)
            .optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let incident = incident_from_raw(raw)?;

        let sql = format!(
            "SELECT {ALERT_COLUMNS} FROM alerts WHERE incident_id = ?1 ORDER BY first_seen, id"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let alerts = statement
            .query_map([to_sql_int(id)], raw_alert)?
            .map(|row| alert_from_raw(row?))
            .collect::<Result<Vec<_>, _>>()?;

        // Flows of the incident's host, one minute either side of the incident.
        let margin_ms = 60_000;
        let flow_filter = FlowFilter {
            since: Some(Timestamp(incident.first_seen - margin_ms)),
            until: Some(Timestamp(incident.last_seen + margin_ms)),
            ip: Some(incident.src_ip.clone()),
            port: None,
            protocol: None,
            limit: MAX_INCIDENT_FLOWS + 1,
            oldest_first: true,
        };
        let mut flows = self.flows(&flow_filter)?;
        let flows_truncated = flows.len() > MAX_INCIDENT_FLOWS as usize;
        flows.truncate(MAX_INCIDENT_FLOWS as usize);
        Ok(Some(IncidentDetail {
            incident,
            alerts,
            flows,
            flows_truncated,
        }))
    }

    pub fn recent_alerts(
        &self,
        since: Timestamp,
        until: Timestamp,
        limit: u32,
    ) -> Result<Vec<AlertRow>, StoreError> {
        let sql = format!(
            "SELECT {ALERT_COLUMNS} FROM alerts WHERE last_seen >= ?1 AND first_seen < ?2
             ORDER BY last_seen DESC LIMIT ?3"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows =
            statement.query_map(params![since.millis(), until.millis(), limit], raw_alert)?;
        rows.map(|row| alert_from_raw(row?)).collect()
    }

    /// Sets the analyst's status. Returns false when the incident does not exist.
    pub fn set_incident_status(
        &mut self,
        id: u64,
        status: &str,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        if !INCIDENT_STATUSES.contains(&status) {
            return Err(StoreError::Invalid(format!("unknown status {status:?}")));
        }
        let changed = self.conn.execute(
            "UPDATE incidents SET status = ?1, status_changed_at = ?2 WHERE id = ?3",
            params![status, now.millis(), to_sql_int(id)],
        )?;
        Ok(changed == 1)
    }
}

/// An incident row as SQLite returns it, before the JSON columns are decoded.
type RawIncident = (
    i64,
    i64,
    i64,
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
);

fn raw_incident(row: &Row<'_>) -> rusqlite::Result<RawIncident> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn incident_from_raw(raw: RawIncident) -> Result<IncidentRow, StoreError> {
    let (id, first_seen, last_seen, src_ip, severity, alert_count, kinds, tactics, targets, status) =
        raw;
    Ok(IncidentRow {
        id: from_sql_int(id),
        first_seen,
        last_seen,
        src_ip,
        severity: severity_word(severity),
        alert_count: from_sql_int(alert_count),
        kinds: serde_json::from_str(&kinds)?,
        tactics: serde_json::from_str(&tactics)?,
        targets: serde_json::from_str(&targets)?,
        status,
    })
}

type RawAlert = (
    i64,
    Option<i64>,
    String,
    i64,
    i64,
    i64,
    String,
    Option<String>,
    Option<u16>,
    i64,
    String,
    Option<String>,
);

fn raw_alert(row: &Row<'_>) -> rusqlite::Result<RawAlert> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    ))
}

fn alert_from_raw(raw: RawAlert) -> Result<AlertRow, StoreError> {
    let (
        id,
        incident_id,
        kind,
        severity,
        first_seen,
        last_seen,
        src_ip,
        dst_ip,
        dst_port,
        count,
        details,
        attack,
    ) = raw;
    Ok(AlertRow {
        id: from_sql_int(id),
        incident_id: incident_id.map(from_sql_int),
        kind,
        severity: severity_word(severity),
        first_seen,
        last_seen,
        src_ip,
        dst_ip,
        dst_port,
        count: from_sql_int(count),
        details: serde_json::from_str(&details)?,
        attack: match attack {
            Some(text) => Some(serde_json::from_str(&text)?),
            None => None,
        },
    })
}

fn severity_word(rank: i64) -> String {
    Severity::from_rank(rank.clamp(0, 4) as u8)
        .as_str()
        .to_string()
}
