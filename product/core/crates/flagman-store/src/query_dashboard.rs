//! Queries behind the overview page: totals, time series and top lists.

use crate::rows::{
    AlertPoint, ClassCounts, NamedCount, Overview, SeverityCounts, TalkerRow, TrafficPoint,
};
use crate::{Store, StoreError, from_sql_int};
use flagman_core::alert::Severity;
use flagman_core::time::Timestamp;
use rusqlite::params;
use std::collections::BTreeMap;

/// A time range `[since, until)` and the bucket size used for charts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeRange {
    pub since: Timestamp,
    pub until: Timestamp,
    pub bucket_ms: i64,
}

impl TimeRange {
    /// The start of every bucket in the range, so charts get a point (maybe
    /// zero) for every bucket instead of gaps.
    fn bucket_starts(&self) -> Vec<i64> {
        let step = self.bucket_ms.max(1);
        let first = self.since.millis().div_euclid(step) * step;
        (0..)
            .map(|i| first + i * step)
            .take_while(|t| *t < self.until.millis())
            .take(2_000)
            .collect()
    }

    fn bucket_of(&self, t: i64) -> i64 {
        let step = self.bucket_ms.max(1);
        t.div_euclid(step) * step
    }
}

impl Store {
    /// The newest moment that has data. In replay mode the dashboard uses it
    /// as "now", so an old capture still shows up in "last hour".
    pub fn latest_timestamp(&self) -> Result<Option<Timestamp>, StoreError> {
        let latest: Option<i64> = self.conn.query_row(
            "SELECT MAX(t) FROM (
                 SELECT MAX(minute) + 60000 AS t FROM traffic_minutes
                 UNION ALL SELECT MAX(last_seen) FROM flows
                 UNION ALL SELECT MAX(last_seen) FROM alerts)",
            [],
            |row| row.get(0),
        )?;
        Ok(latest.map(Timestamp))
    }

    pub fn overview(&self, range: TimeRange) -> Result<Overview, StoreError> {
        let (since, until) = (range.since.millis(), range.until.millis());
        let count = |sql: &str| -> Result<u64, StoreError> {
            let value: i64 = self
                .conn
                .query_row(sql, params![since, until], |row| row.get(0))?;
            Ok(from_sql_int(value))
        };
        let mut overview = Overview {
            since,
            until,
            open_incidents: count(
                "SELECT COUNT(*) FROM incidents
                 WHERE last_seen >= ?1 AND first_seen < ?2 AND status = 'open'",
            )?,
            incidents: count(
                "SELECT COUNT(*) FROM incidents WHERE last_seen >= ?1 AND first_seen < ?2",
            )?,
            alerts: count("SELECT COUNT(*) FROM alerts WHERE last_seen >= ?1 AND first_seen < ?2")?,
            flows: count("SELECT COUNT(*) FROM flows WHERE last_seen >= ?1 AND first_seen < ?2")?,
            packets: count(
                "SELECT COALESCE(SUM(packets), 0) FROM traffic_minutes WHERE minute >= ?1 AND minute < ?2",
            )?,
            bytes: count(
                "SELECT COALESCE(SUM(bytes), 0) FROM traffic_minutes WHERE minute >= ?1 AND minute < ?2",
            )?,
            local_hosts: 0,
            incidents_by_severity: SeverityCounts::default(),
        };
        let mut statement = self.conn.prepare(
            "SELECT severity, COUNT(*) FROM incidents
             WHERE last_seen >= ?1 AND first_seen < ?2 GROUP BY severity",
        )?;
        let rows = statement.query_map(params![since, until], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (rank, n) = row?;
            overview.incidents_by_severity.add(rank, from_sql_int(n));
        }
        overview.local_hosts = self.count_local_hosts(since, until)?;
        Ok(overview)
    }

    fn count_local_hosts(&self, since: i64, until: i64) -> Result<u64, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT src_ip FROM flows WHERE last_seen >= ?1 AND first_seen < ?2
             UNION SELECT dst_ip FROM flows WHERE last_seen >= ?1 AND first_seen < ?2",
        )?;
        let ips = statement.query_map(params![since, until], |row| row.get::<_, String>(0))?;
        let mut local = 0;
        for ip in ips {
            if ip?.parse().is_ok_and(flagman_core::net::is_local) {
                local += 1;
            }
        }
        Ok(local)
    }

    pub fn traffic_series(&self, range: TimeRange) -> Result<Vec<TrafficPoint>, StoreError> {
        let mut points: BTreeMap<i64, TrafficPoint> = range
            .bucket_starts()
            .into_iter()
            .map(|t| {
                (
                    t,
                    TrafficPoint {
                        t,
                        ..TrafficPoint::default()
                    },
                )
            })
            .collect();
        let mut statement = self.conn.prepare(
            "SELECT minute, class, packets, bytes FROM traffic_minutes WHERE minute >= ?1 AND minute < ?2",
        )?;
        let rows =
            statement.query_map(params![range.since.millis(), range.until.millis()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
        for row in rows {
            let (minute, class, packets, bytes) = row?;
            if let Some(point) = points.get_mut(&range.bucket_of(minute)) {
                point.packets.add(&class, from_sql_int(packets));
                point.bytes.add(&class, from_sql_int(bytes));
            }
        }
        Ok(points.into_values().collect())
    }

    pub fn alert_series(&self, range: TimeRange) -> Result<Vec<AlertPoint>, StoreError> {
        let mut points: BTreeMap<i64, AlertPoint> = range
            .bucket_starts()
            .into_iter()
            .map(|t| {
                (
                    t,
                    AlertPoint {
                        t,
                        counts: SeverityCounts::default(),
                    },
                )
            })
            .collect();
        let mut statement = self.conn.prepare(
            "SELECT first_seen, severity FROM alerts WHERE first_seen >= ?1 AND first_seen < ?2",
        )?;
        let rows = statement
            .query_map(params![range.since.millis(), range.until.millis()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?;
        for row in rows {
            let (first_seen, rank) = row?;
            if let Some(point) = points.get_mut(&range.bucket_of(first_seen)) {
                point.counts.add(rank, 1);
            }
        }
        Ok(points.into_values().collect())
    }

    /// Hosts that sent or received the most bytes.
    pub fn top_talkers(&self, range: TimeRange, limit: u32) -> Result<Vec<TalkerRow>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT ip, SUM(bytes), COUNT(*) FROM (
                 SELECT src_ip AS ip, bytes_fwd + bytes_rev AS bytes FROM flows
                 WHERE last_seen >= ?1 AND first_seen < ?2
                 UNION ALL
                 SELECT dst_ip, bytes_fwd + bytes_rev FROM flows
                 WHERE last_seen >= ?1 AND first_seen < ?2)
             GROUP BY ip ORDER BY SUM(bytes) DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![range.since.millis(), range.until.millis(), limit],
            |row| {
                Ok(TalkerRow {
                    ip: row.get(0)?,
                    bytes: from_sql_int(row.get(1)?),
                    flows: from_sql_int(row.get(2)?),
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Destination ports with the most flows (connections).
    pub fn top_ports(&self, range: TimeRange, limit: u32) -> Result<Vec<NamedCount>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT dst_port, protocol, COUNT(*), SUM(bytes_fwd + bytes_rev) FROM flows
             WHERE last_seen >= ?1 AND first_seen < ?2 AND protocol IN ('tcp', 'udp')
             GROUP BY dst_port, protocol ORDER BY COUNT(*) DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![range.since.millis(), range.until.millis(), limit],
            |row| {
                Ok(NamedCount {
                    name: row.get::<_, i64>(0)?.to_string(),
                    detail: Some(row.get(1)?),
                    count: from_sql_int(row.get(2)?),
                    value: Some(serde_json::Value::from(from_sql_int(row.get(3)?))),
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Alert types, most severe first. Suricata alerts are listed per rule.
    pub fn top_alerts(&self, range: TimeRange, limit: u32) -> Result<Vec<NamedCount>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT kind, json_extract(details, '$.signature') AS rule, COUNT(*), MAX(severity)
             FROM alerts WHERE last_seen >= ?1 AND first_seen < ?2
             GROUP BY kind, rule ORDER BY MAX(severity) DESC, COUNT(*) DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![range.since.millis(), range.until.millis(), limit],
            |row| {
                let rank: i64 = row.get(3)?;
                Ok(NamedCount {
                    name: row.get(0)?,
                    detail: row.get(1)?,
                    count: from_sql_int(row.get(2)?),
                    value: Some(serde_json::Value::from(
                        Severity::from_rank(rank.clamp(0, 4) as u8).as_str(),
                    )),
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Packets and bytes per protocol family over the whole range.
    pub fn protocol_totals(
        &self,
        range: TimeRange,
    ) -> Result<(ClassCounts, ClassCounts), StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT class, SUM(packets), SUM(bytes) FROM traffic_minutes
             WHERE minute >= ?1 AND minute < ?2 GROUP BY class",
        )?;
        let rows =
            statement.query_map(params![range.since.millis(), range.until.millis()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
        let (mut packets, mut bytes) = (ClassCounts::default(), ClassCounts::default());
        for row in rows {
            let (class, p, b) = row?;
            packets.add(&class, from_sql_int(p));
            bytes.add(&class, from_sql_int(b));
        }
        Ok((packets, bytes))
    }
}
