//! API tests: requests go through the real router, with no network involved.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use flagman_core::alert::{Alert, AlertDetails, AlertKind, Severity};
use flagman_core::engine::Output;
use flagman_core::flow::Protocol;
use flagman_core::health::SensorHealth;
use flagman_core::incident::Incident;
use flagman_core::time::Timestamp;
use flagman_store::Store;
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::{Arc, Mutex, RwLock};
use tower::ServiceExt;

const TOKEN: &str = "test-token";

fn state_with_one_incident() -> ApiState {
    let mut store = Store::open_in_memory().unwrap();
    let now = Timestamp::now().millis();
    store
        .write_outputs(&[
            Output::Alert(Alert {
                id: 1,
                incident_id: Some(1),
                kind: AlertKind::PortScan,
                severity: Severity::Medium,
                first_seen: Timestamp(now - 5_000),
                last_seen: Timestamp(now - 1_000),
                src_ip: "192.168.1.66".parse().unwrap(),
                dst_ip: Some("192.168.1.10".parse().unwrap()),
                dst_port: None,
                count: 1_000,
                details: AlertDetails::PortScan {
                    protocol: Protocol::Tcp,
                    ports_sample: vec![22],
                    window_secs: 60,
                },
                attack: None,
            }),
            Output::Incident(Incident {
                id: 1,
                first_seen: Timestamp(now - 5_000),
                last_seen: Timestamp(now - 1_000),
                src_ip: "192.168.1.66".parse().unwrap(),
                severity: Severity::Medium,
                alert_count: 1,
                kinds: vec![AlertKind::PortScan],
                tactics: vec!["Discovery".to_string()],
                targets: vec!["192.168.1.10".parse().unwrap()],
            }),
        ])
        .unwrap();
    ApiState {
        store: Arc::new(Mutex::new(store)),
        health: Arc::new(RwLock::new(SensorHealth {
            mode: "live".to_string(),
            ..SensorHealth::default()
        })),
        token: Arc::from(TOKEN),
        clock: Clock::Live,
    }
}

async fn send(app: axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn every_api_route_needs_the_token() {
    let app = router(state_with_one_incident(), None);
    let (status, body) = send(app.clone(), get("/api/dashboard", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().unwrap().contains("token"));
    let (status, _) = send(app, get("/api/incidents", Some("wrong"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_dashboard_summarises_the_last_hour() {
    let app = router(state_with_one_incident(), None);
    let (status, body) = send(app, get("/api/dashboard?range=1h", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["range"]["label"], "1h");
    assert_eq!(body["overview"]["open_incidents"], 1);
    assert_eq!(body["traffic"].as_array().unwrap().len(), 60);
    assert_eq!(body["recent_incidents"][0]["src_ip"], "192.168.1.66");
}

#[tokio::test]
async fn incidents_can_be_listed_opened_and_marked() {
    let app = router(state_with_one_incident(), None);
    let (status, list) = send(
        app.clone(),
        get("/api/incidents?min_severity=medium", Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);

    let (status, detail) = send(app.clone(), get("/api/incidents/1", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["alerts"][0]["count"], 1_000);
    let (status, _) = send(app.clone(), get("/api/incidents/99", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mark = |status: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/incidents/1/status")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"status":"{status}"}}"#)))
            .unwrap()
    };
    assert_eq!(
        send(app.clone(), mark("false_positive")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(app.clone(), mark("gone")).await.0,
        StatusCode::BAD_REQUEST
    );
    let (_, detail) = send(app, get("/api/incidents/1", Some(TOKEN))).await;
    assert_eq!(detail["incident"]["status"], "false_positive");
}

#[tokio::test]
async fn bad_parameters_are_rejected_clearly() {
    let app = router(state_with_one_incident(), None);
    let (status, body) = send(app.clone(), get("/api/dashboard?range=1y", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("range"));
    let (status, _) = send(app.clone(), get("/api/flows?ip=not-an-ip", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(app, get("/api/incidents?status=maybe", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_dashboard_files_are_served_with_security_headers() {
    let dir = tempfile_dir();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Flagman</title>",
    )
    .unwrap();
    let app = router(state_with_one_incident(), Some(&dir));
    let response = app.oneshot(get("/incidents/1", None)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "unknown paths fall back to the app"
    );
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap();
    assert!(csp.to_str().unwrap().contains("frame-ancestors 'none'"));
    std::fs::remove_dir_all(dir).ok();
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("flagman-api-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
