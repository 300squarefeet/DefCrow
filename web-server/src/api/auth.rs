//! Session lifecycle endpoint(s). The legacy password-based login
//! handler has been replaced by the Discord-key flow in
//! [`crate::api::auth_keys`]. We keep `logout` here so the public URL
//! shape (`/api/auth/logout`) does not change.

use axum::{extract::State, http::StatusCode};

use crate::state::AppState;

/// Revoke the bearer token presented in the `Authorization` header.
/// Idempotent: missing or unknown tokens still resolve to `204` so the
/// frontend can safely call this even when the session has already
/// timed out server-side.
pub async fn logout(
    State(state): State<AppState>,
    headers:      axum::http::HeaderMap,
) -> StatusCode {
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(val) = auth.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                state.sessions.remove(token);
            }
        }
    }
    StatusCode::NO_CONTENT
}
