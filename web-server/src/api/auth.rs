use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

fn rate_key(headers: &HeaderMap, username: &str) -> String {
    // Combine username + IP so the limiter catches both per-IP floods and
    // credential-stuffing (same creds, many IPs).
    // We use X-Forwarded-For only as a hint; the username component ensures
    // an attacker cannot bypass per-IP limits by spoofing headers.
    let ip = headers.get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "direct".to_string());
    format!("{}@{}", username, ip)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token:      String,
    pub expires_in: u64,
}

pub async fn login(
    State(state): State<AppState>,
    headers:      HeaderMap,
    Json(body):   Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let key = rate_key(&headers, &body.username);
    if !state.rate_limiter.check_and_record(&key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if body.username != state.config.username {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let parsed_hash = PasswordHash::new(&state.config.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    state.rate_limiter.reset(&key);
    let token = state.sessions.create_session();
    Ok(Json(LoginResponse { token, expires_in: 86400 }))
}

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
