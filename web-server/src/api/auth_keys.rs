//! Discord-key login flow. Two endpoints:
//!
//! - `POST /api/auth/request-key { username }` — issues a one-time key
//!   and delivers it via the configured Discord webhook. Replies with a
//!   generic body on unknown users so the endpoint cannot be used for
//!   username enumeration.
//!
//! - `POST /api/auth/login { username, key }` — verifies the key,
//!   mints a session JWT carrying `{ sub, role, iat, exp }`, and
//!   registers it with the [`SessionStore`] so logout can revoke it.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::auth::send_discord_key;
use crate::middleware::auth::{derive_session_key, sign_session_jwt, SessionClaims, SESSION_CLAIMS_VERSION};
use crate::state::AppState;

const SESSION_TTL_SECS: i64 = 86_400;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Best-effort client IP for rate-limiting. Falls back to
/// `X-Forwarded-For` / `X-Real-IP` when the connection's peer address
/// is unavailable (e.g. under axum-test harness).
fn client_ip(connect_info: Option<&SocketAddr>, headers: &HeaderMap) -> String {
    if let Some(addr) = connect_info {
        return addr.ip().to_string();
    }
    headers.get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "direct".to_string())
}

fn normalize_username(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── POST /api/auth/request-key ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RequestKeyBody {
    pub username: String,
}

#[derive(Serialize)]
pub struct RequestKeyResponse {
    pub delivered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:     Option<String>,
}

pub async fn request_key(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<RequestKeyBody>,
) -> (StatusCode, Json<RequestKeyResponse>) {
    let username = normalize_username(&body.username);
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(RequestKeyResponse {
            delivered: false,
            error: Some("username is required".into()),
        }));
    }

    let ip = client_ip(connect_info.as_ref().map(|c| &c.0), &headers);

    // Per-IP guard runs first so flooding many distinct usernames
    // from one IP still hits the cap.
    if !state.ip_rate_limiter.check_and_record(&format!("request-key:{}", ip)) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(RequestKeyResponse {
            delivered: false,
            error: Some("too many requests".into()),
        }));
    }
    if !state.request_key_limiter.check_and_record(&username) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(RequestKeyResponse {
            delivered: false,
            error: Some("too many requests".into()),
        }));
    }

    // Resolve the webhook BEFORE the user lookup. We must produce an
    // identical response shape for known and unknown usernames — if we
    // short-circuit on "user exists?" first, a missing webhook would
    // leak existence (real user → 500, unknown → 200). Reading the
    // webhook first means the unconfigured-webhook branch lands the
    // same generic 200 for everyone.
    let webhook = {
        let s = state.auth_settings.read().await;
        s.get_webhook().map(|s| s.to_string())
    };
    let known_user = {
        let users = state.user_store.read().await;
        users.find(&username).cloned()
    };

    // Unconfigured webhook: behave the same regardless of whether the
    // user exists. We log a warning server-side so an admin can spot
    // the misconfiguration without surfacing it to anonymous callers.
    let Some(webhook_url) = webhook else {
        if known_user.is_some() {
            warn!(%username, "request-key called with no Discord webhook configured");
        }
        return (StatusCode::OK, Json(RequestKeyResponse { delivered: true, error: None }));
    };

    if known_user.is_none() {
        // Unknown user, webhook is configured — silently succeed so an
        // attacker cannot enumerate operators by polling the endpoint.
        return (StatusCode::OK, Json(RequestKeyResponse { delivered: true, error: None }));
    }

    let session_key = derive_session_key(&state.config.session_secret);
    let plain_key   = state.key_store.issue(&username, &session_key);

    match send_discord_key(&webhook_url, &username, &plain_key).await {
        Ok(()) => (StatusCode::OK, Json(RequestKeyResponse { delivered: true, error: None })),
        Err(err) => {
            warn!(?err, "discord webhook delivery failed");
            (StatusCode::BAD_GATEWAY, Json(RequestKeyResponse {
                delivered: false,
                error: Some("discord delivery failed".into()),
            }))
        }
    }
}

// ── POST /api/auth/login ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub key:      String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token:    String,
    pub username: String,
    pub role:     String,
}

pub async fn login(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let username = normalize_username(&body.username);
    if username.is_empty() || body.key.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let ip = client_ip(connect_info.as_ref().map(|c| &c.0), &headers);
    if !state.ip_rate_limiter.check_and_record(&format!("login:{}", ip)) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if !state.rate_limiter.check_and_record(&username) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let session_key = derive_session_key(&state.config.session_secret);
    if !state.key_store.verify(&username, body.key.trim(), &session_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Look up the role at login time so a freshly-promoted user gets
    // the new role on their next sign-in.
    let user = {
        let users = state.user_store.read().await;
        users.find(&username).cloned()
    };
    let user = user.ok_or(StatusCode::UNAUTHORIZED)?;

    // Successful login — clear the username bucket so the user can
    // retry promptly if they fat-finger something later in the
    // session.
    state.rate_limiter.reset(&username);

    let now = unix_now();
    let claims = SessionClaims {
        sub:  user.username.clone(),
        role: user.role.clone(),
        ver:  SESSION_CLAIMS_VERSION,
        iat:  now,
        exp:  now + SESSION_TTL_SECS,
    };
    let token = sign_session_jwt(&session_key, &claims);
    state.sessions.insert(token.clone(), claims);

    Ok(Json(LoginResponse {
        token,
        username: user.username,
        role:     user.role,
    }))
}
