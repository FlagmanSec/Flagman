//! Routes for incidents and alerts.

use crate::error::ApiError;
use crate::params::{clamp_limit, parse_span};
use crate::state::ApiState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use flagman_core::alert::Severity;
use flagman_core::time::Timestamp;
use flagman_store::{AlertRow, INCIDENT_STATUSES, IncidentDetail, IncidentFilter, IncidentRow};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct IncidentQuery {
    range: Option<String>,
    min_severity: Option<String>,
    status: Option<String>,
    limit: Option<u32>,
}

pub async fn list_incidents(
    State(state): State<ApiState>,
    Query(query): Query<IncidentQuery>,
) -> Result<Json<Vec<IncidentRow>>, ApiError> {
    let span = parse_span(query.range.as_deref(), "7d")?;
    let min_severity = match query.min_severity.as_deref() {
        None | Some("") => None,
        Some("low") => Some(Severity::Low),
        Some("medium") => Some(Severity::Medium),
        Some("high") => Some(Severity::High),
        Some("critical") => Some(Severity::Critical),
        Some(other) => return Err(ApiError::BadRequest(format!("unknown severity {other:?}"))),
    };
    let status = query.status.filter(|status| !status.is_empty());
    if let Some(status) = &status
        && !INCIDENT_STATUSES.contains(&status.as_str())
    {
        return Err(ApiError::BadRequest(format!("unknown status {status:?}")));
    }
    let limit = clamp_limit(query.limit, 100, 500);
    let incidents = state
        .query(move |store, clock| {
            let range = span.resolve(store, clock)?;
            store.incidents(&IncidentFilter {
                since: Some(range.since),
                until: Some(range.until),
                min_severity,
                status,
                limit,
            })
        })
        .await?;
    Ok(Json(incidents))
}

pub async fn incident_detail(
    State(state): State<ApiState>,
    Path(id): Path<u64>,
) -> Result<Json<IncidentDetail>, ApiError> {
    let detail = state
        .query(move |store, _| store.incident_detail(id))
        .await?;
    detail.map(Json).ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct StatusChange {
    status: String,
}

pub async fn set_status(
    State(state): State<ApiState>,
    Path(id): Path<u64>,
    Json(change): Json<StatusChange>,
) -> Result<StatusCode, ApiError> {
    let found = state
        .query(move |store, _| store.set_incident_status(id, &change.status, Timestamp::now()))
        .await?;
    if found {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

#[derive(Deserialize)]
pub struct AlertQuery {
    range: Option<String>,
    limit: Option<u32>,
}

pub async fn list_alerts(
    State(state): State<ApiState>,
    Query(query): Query<AlertQuery>,
) -> Result<Json<Vec<AlertRow>>, ApiError> {
    let span = parse_span(query.range.as_deref(), "24h")?;
    let limit = clamp_limit(query.limit, 100, 1_000);
    let alerts = state
        .query(move |store, clock| {
            let range = span.resolve(store, clock)?;
            store.recent_alerts(range.since, range.until, limit)
        })
        .await?;
    Ok(Json(alerts))
}
