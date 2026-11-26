//! Token check for every API route.
//!
//! Why a token even on localhost: any web page you visit can ask your
//! browser to call `http://127.0.0.1:...`. Without a secret, such a page
//! could read your alerts. Browsers never add our `Authorization` header to
//! requests from other sites, so the token blocks that.

use crate::error::ApiError;
use crate::state::ApiState;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub async fn require_token(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), state.token.as_bytes()) => {
            next.run(request).await
        }
        _ => ApiError::Unauthorized.into_response(),
    }
}

/// Compares two byte strings in a time that does not depend on where they
/// first differ, so an attacker cannot guess the token one byte at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn compares_tokens() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
    }
}
