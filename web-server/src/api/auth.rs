use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

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
    Json(body):   Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    if body.username != state.config.username {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let parsed_hash = PasswordHash::new(&state.config.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

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
