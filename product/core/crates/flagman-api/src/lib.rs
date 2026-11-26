//! The local HTTP API behind the dashboard.
//!
//! - Every `/api/...` route needs the token: `Authorization: Bearer <token>`.
//! - The dashboard's files (the built Svelte app) are served from `ui_dir`.
//! - The daemon binds it to `127.0.0.1` by default, so only this machine can
//!   reach it.
//!
//! Routes (all GET unless noted):
//!
//! | Route | What it returns |
//! |---|---|
//! | `/api/health` | sensor status (packets, drops, Suricata) |
//! | `/api/dashboard?range=1h` | everything the overview page shows |
//! | `/api/incidents?range=7d&min_severity=high&status=open` | incident list |
//! | `/api/incidents/{id}` | one incident with its alerts and flows |
//! | `POST /api/incidents/{id}/status` | set `open`, `confirmed`, `false_positive` or `resolved` |
//! | `/api/alerts?range=24h` | recent alerts |
//! | `/api/flows?range=1h&ip=…&port=…&protocol=tcp` | finished flows |

mod auth;
mod error;
mod headers;
mod params;
mod routes_dashboard;
mod routes_incidents;
mod state;

pub use state::{ApiState, Clock};

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use std::path::Path;
use tower_http::services::{ServeDir, ServeFile};

/// Builds the whole web application: API routes plus the dashboard files.
pub fn router(state: ApiState, ui_dir: Option<&Path>) -> Router {
    let api = Router::new()
        .route("/health", get(routes_dashboard::health))
        .route("/dashboard", get(routes_dashboard::dashboard))
        .route("/incidents", get(routes_incidents::list_incidents))
        .route("/incidents/{id}", get(routes_incidents::incident_detail))
        .route("/incidents/{id}/status", post(routes_incidents::set_status))
        .route("/alerts", get(routes_incidents::list_alerts))
        .route("/flows", get(routes_dashboard::list_flows))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_token,
        ))
        .with_state(state);

    let mut app = Router::new().nest("/api", api);
    if let Some(dir) = ui_dir {
        let index = ServeFile::new(dir.join("index.html"));
        app = app.fallback_service(ServeDir::new(dir).fallback(index));
    }
    app.layer(middleware::map_response(headers::add_security_headers))
}

/// Serves `app` on an already bound listener until `shutdown` completes.
/// The caller binds first, so a "port already in use" error shows up at once.
pub async fn serve(
    listener: std::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests;
