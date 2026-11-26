//! API errors, returned as JSON: `{"error": "..."}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use flagman_store::StoreError;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    BadRequest(String),
    NotFound,
    Internal(String),
}

impl ApiError {
    pub fn internal(message: &str) -> ApiError {
        ApiError::Internal(message.to_string())
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> ApiError {
        match error {
            StoreError::Invalid(message) => ApiError::BadRequest(message),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "missing or wrong token: open the dashboard link printed by flagmand".to_string(),
            ),
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Internal(message) => {
                tracing::error!("API error: {message}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error, see the flagmand log".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
