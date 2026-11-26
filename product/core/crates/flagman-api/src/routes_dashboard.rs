//! Routes for the overview page, the health strip and the traffic explorer.

use crate::error::ApiError;
use crate::params::{Span, clamp_limit, parse_span};
use crate::state::{ApiState, Clock};
use axum::Json;
use axum::extract::{Query, State};
use flagman_core::health::SensorHealth;
use flagman_core::time::Timestamp;
use flagman_store::{
    AlertPoint, ClassCounts, FlowFilter, FlowRow, IncidentFilter, IncidentRow, NamedCount,
    Overview, TalkerRow, TrafficPoint,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize)]
pub struct HealthResponse {
    #[serde(flatten)]
    sensor: SensorHealth,
    server_time: Timestamp,
    /// "live" or "latest_data": what "now" means for ranges.
    clock: &'static str,
}

pub async fn health(State(state): State<ApiState>) -> Result<Json<HealthResponse>, ApiError> {
    let sensor = state
        .health
        .read()
        .map_err(|_| ApiError::internal("the health lock is poisoned"))?
        .clone();
    Ok(Json(HealthResponse {
        sensor,
        server_time: Timestamp::now(),
        clock: match state.clock {
            Clock::Live => "live",
            Clock::LatestData => "latest_data",
        },
    }))
}

#[derive(Deserialize)]
pub struct DashboardQuery {
    range: Option<String>,
}

#[derive(Serialize)]
pub struct RangeInfo {
    label: &'static str,
    since: i64,
    until: i64,
    bucket_ms: i64,
}

/// Everything the overview page shows, in one answer.
#[derive(Serialize)]
pub struct DashboardResponse {
    range: RangeInfo,
    overview: Overview,
    traffic: Vec<TrafficPoint>,
    alerts: Vec<AlertPoint>,
    top_talkers: Vec<TalkerRow>,
    top_ports: Vec<NamedCount>,
    top_alerts: Vec<NamedCount>,
    protocol_packets: ClassCounts,
    protocol_bytes: ClassCounts,
    recent_incidents: Vec<IncidentRow>,
}

pub async fn dashboard(
    State(state): State<ApiState>,
    Query(query): Query<DashboardQuery>,
) -> Result<Json<DashboardResponse>, ApiError> {
    let span: Span = parse_span(query.range.as_deref(), "1h")?;
    let response = state
        .query(move |store, clock| {
            let range = span.resolve(store, clock)?;
            let (protocol_packets, protocol_bytes) = store.protocol_totals(range)?;
            let recent = IncidentFilter {
                since: Some(range.since),
                until: Some(range.until),
                limit: 5,
                ..IncidentFilter::default()
            };
            Ok(DashboardResponse {
                range: RangeInfo {
                    label: span.label,
                    since: range.since.millis(),
                    until: range.until.millis(),
                    bucket_ms: range.bucket_ms,
                },
                overview: store.overview(range)?,
                traffic: store.traffic_series(range)?,
                alerts: store.alert_series(range)?,
                top_talkers: store.top_talkers(range, 8)?,
                top_ports: store.top_ports(range, 8)?,
                top_alerts: store.top_alerts(range, 8)?,
                protocol_packets,
                protocol_bytes,
                recent_incidents: store.incidents(&recent)?,
            })
        })
        .await?;
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct FlowQuery {
    range: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    limit: Option<u32>,
}

pub async fn list_flows(
    State(state): State<ApiState>,
    Query(query): Query<FlowQuery>,
) -> Result<Json<Vec<FlowRow>>, ApiError> {
    let span = parse_span(query.range.as_deref(), "1h")?;
    if let Some(ip) = &query.ip
        && ip.parse::<IpAddr>().is_err()
    {
        return Err(ApiError::BadRequest(format!("{ip:?} is not an IP address")));
    }
    if let Some(protocol) = &query.protocol
        && !["tcp", "udp", "icmp", "other"].contains(&protocol.as_str())
    {
        return Err(ApiError::BadRequest(
            "protocol must be tcp, udp, icmp or other".to_string(),
        ));
    }
    let limit = clamp_limit(query.limit, 200, 1_000);
    let flows = state
        .query(move |store, clock| {
            let range = span.resolve(store, clock)?;
            store.flows(&FlowFilter {
                since: Some(range.since),
                until: Some(range.until),
                ip: query.ip,
                port: query.port,
                protocol: query.protocol,
                limit,
                oldest_first: false,
            })
        })
        .await?;
    Ok(Json(flows))
}
