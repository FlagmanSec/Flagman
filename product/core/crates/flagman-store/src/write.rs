//! The write side: one transaction per batch of engine outputs.
//!
//! Alerts and incidents are "upserted": the engine publishes the same id
//! again as a finding grows, and the newest version replaces the old row.
//! The analyst's status of an incident is never overwritten by the engine.

use crate::{Store, StoreError, to_sql_int};
use flagman_core::alert::Alert;
use flagman_core::engine::Output;
use flagman_core::flow::FlowRecord;
use flagman_core::incident::Incident;
use flagman_core::time::Timestamp;
use flagman_core::traffic::TrafficMinute;
use rusqlite::{Transaction, params};

impl Store {
    /// Writes a batch in one transaction (all or nothing).
    pub fn write_outputs(&mut self, outputs: &[Output]) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        for output in outputs {
            match output {
                Output::Flow(flow) => insert_flow(&tx, flow)?,
                Output::Alert(alert) => upsert_alert(&tx, alert)?,
                Output::Incident(incident) => upsert_incident(&tx, incident)?,
                Output::Traffic(minute) => add_traffic(&tx, minute)?,
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Deletes flows and traffic older than `flows_before`, and incidents
    /// (with their alerts) older than `incidents_before`.
    pub fn prune(
        &mut self,
        flows_before: Timestamp,
        incidents_before: Timestamp,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM flows WHERE last_seen < ?1",
            [flows_before.millis()],
        )?;
        tx.execute(
            "DELETE FROM traffic_minutes WHERE minute < ?1",
            [flows_before.millis()],
        )?;
        tx.execute(
            "DELETE FROM alerts WHERE last_seen < ?1",
            [incidents_before.millis()],
        )?;
        tx.execute(
            "DELETE FROM incidents WHERE last_seen < ?1",
            [incidents_before.millis()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The highest alert and incident ids stored, so new ids continue after them.
    pub fn last_ids(&self) -> Result<(u64, u64), StoreError> {
        let last = |table: &str| -> Result<u64, StoreError> {
            let sql = format!("SELECT COALESCE(MAX(id), 0) FROM {table}");
            let max: i64 = self.conn.query_row(&sql, [], |row| row.get(0))?;
            Ok(crate::from_sql_int(max))
        };
        Ok((last("alerts")?, last("incidents")?))
    }
}

fn insert_flow(tx: &Transaction<'_>, flow: &FlowRecord) -> Result<(), StoreError> {
    let mut statement = tx.prepare_cached(
        "INSERT INTO flows (first_seen, last_seen, protocol, src_ip, src_port, dst_ip, dst_port,
                            packets_fwd, packets_rev, bytes_fwd, bytes_rev, tcp_outcome)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    statement.execute(params![
        flow.first_seen.millis(),
        flow.last_seen.millis(),
        flow.protocol.as_str(),
        flow.initiator.ip.to_string(),
        flow.initiator.port,
        flow.responder.ip.to_string(),
        flow.responder.port,
        to_sql_int(flow.packets_fwd),
        to_sql_int(flow.packets_rev),
        to_sql_int(flow.bytes_fwd),
        to_sql_int(flow.bytes_rev),
        flow.tcp_outcome.map(|outcome| outcome.as_str()),
    ])?;
    Ok(())
}

fn upsert_alert(tx: &Transaction<'_>, alert: &Alert) -> Result<(), StoreError> {
    let mut statement = tx.prepare_cached(
        "INSERT INTO alerts (id, incident_id, kind, severity, first_seen, last_seen, src_ip,
                             dst_ip, dst_port, count, details, attack)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT (id) DO UPDATE SET
             incident_id = excluded.incident_id, severity = excluded.severity,
             first_seen = excluded.first_seen, last_seen = excluded.last_seen,
             count = excluded.count, details = excluded.details, attack = excluded.attack",
    )?;
    let attack = match &alert.attack {
        Some(attack) => Some(serde_json::to_string(attack)?),
        None => None,
    };
    statement.execute(params![
        to_sql_int(alert.id),
        alert.incident_id.map(to_sql_int),
        alert.kind.as_str(),
        alert.severity.rank(),
        alert.first_seen.millis(),
        alert.last_seen.millis(),
        alert.src_ip.to_string(),
        alert.dst_ip.map(|ip| ip.to_string()),
        alert.dst_port,
        to_sql_int(alert.count),
        serde_json::to_string(&alert.details)?,
        attack,
    ])?;
    Ok(())
}

fn upsert_incident(tx: &Transaction<'_>, incident: &Incident) -> Result<(), StoreError> {
    let mut statement = tx.prepare_cached(
        "INSERT INTO incidents (id, first_seen, last_seen, src_ip, severity, alert_count,
                                kinds, tactics, targets)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT (id) DO UPDATE SET
             first_seen = excluded.first_seen, last_seen = excluded.last_seen,
             severity = excluded.severity, alert_count = excluded.alert_count,
             kinds = excluded.kinds, tactics = excluded.tactics, targets = excluded.targets",
    )?;
    statement.execute(params![
        to_sql_int(incident.id),
        incident.first_seen.millis(),
        incident.last_seen.millis(),
        incident.src_ip.to_string(),
        incident.severity.rank(),
        to_sql_int(incident.alert_count),
        serde_json::to_string(&incident.kinds)?,
        serde_json::to_string(&incident.tactics)?,
        serde_json::to_string(&incident.targets)?,
    ])?;
    Ok(())
}

fn add_traffic(tx: &Transaction<'_>, minute: &TrafficMinute) -> Result<(), StoreError> {
    let mut statement = tx.prepare_cached(
        "INSERT INTO traffic_minutes (minute, class, packets, bytes) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (minute, class) DO UPDATE SET
             packets = packets + excluded.packets, bytes = bytes + excluded.bytes",
    )?;
    statement.execute(params![
        minute.minute.millis(),
        minute.class.as_str(),
        to_sql_int(minute.packets),
        to_sql_int(minute.bytes),
    ])?;
    Ok(())
}
