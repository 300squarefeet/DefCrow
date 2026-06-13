//! Admin endpoints for managing operators and the global auth
//! settings. Wrapped at the router level by `require_auth` +
//! [`crate::middleware::require_admin::require_admin`], so handlers
//! here can assume the requesting session is authenticated and holds
//! the admin role.

use std::path::PathBuf;

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::send_discord_key;
use crate::auth::users::{UserRecord, ROLE_ADMIN, ROLE_OPERATOR};
use crate::middleware::auth::SessionClaims;
use crate::state::AppState;

fn artifacts_dir(state: &AppState) -> PathBuf {
    PathBuf::from(&state.config.artifacts_dir)
}

// ── GET /api/admin/users ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserRecord>,
}

pub async fn list_users(State(state): State<AppState>) -> Json<UserListResponse> {
    let users = state.user_store.read().await.list();
    Json(UserListResponse { users })
}

// ── POST /api/admin/users ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddUserBody {
    pub username: String,
    pub role:     String,
}

pub async fn add_user(
    State(state): State<AppState>,
    Json(body):   Json<AddUserBody>,
) -> Result<(StatusCode, Json<UserRecord>), (StatusCode, String)> {
    let username = body.username.trim().to_string();
    if username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "username is required".into()));
    }
    if body.role != ROLE_ADMIN && body.role != ROLE_OPERATOR {
        return Err((StatusCode::BAD_REQUEST, "role must be 'admin' or 'operator'".into()));
    }

    let mut store = state.user_store.write().await;
    store.add(&username, &body.role)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    store.save(&artifacts_dir(&state))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let record = store.find(&username).cloned()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "user vanished after add".into()))?;
    Ok((StatusCode::CREATED, Json(record)))
}

// ── DELETE /api/admin/users/:username ──────────────────────────────────────

pub async fn delete_user(
    State(state):       State<AppState>,
    Extension(claims):  Extension<SessionClaims>,
    Path(username):     Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Refuse to let an admin nuke their own session — they would
    // immediately be locked out and the UX is confusing.
    if username.to_lowercase() == claims.sub.to_lowercase() {
        return Err((StatusCode::BAD_REQUEST, "cannot delete your own account".into()));
    }

    let mut store = state.user_store.write().await;
    store.remove(&username)
        .map_err(|e| {
            // The user store maps both "not found" and "last admin" to
            // anyhow errors. Differentiate so the client sees 404 vs
            // 409 appropriately.
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, msg)
            } else {
                (StatusCode::CONFLICT, msg)
            }
        })?;
    store.save(&artifacts_dir(&state))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ── GET /api/admin/settings ────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct AuthSettingsBody {
    pub discord_webhook: Option<String>,
}

pub async fn get_settings(State(state): State<AppState>) -> Json<AuthSettingsBody> {
    let s = state.auth_settings.read().await;
    Json(AuthSettingsBody {
        discord_webhook: s.get_webhook().map(|s| s.to_string()),
    })
}

// ── PUT /api/admin/settings ────────────────────────────────────────────────

pub async fn put_settings(
    State(state): State<AppState>,
    Json(body):   Json<AuthSettingsBody>,
) -> Result<Json<AuthSettingsBody>, (StatusCode, String)> {
    let mut s = state.auth_settings.write().await;
    s.set_webhook(body.discord_webhook)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    s.save(&artifacts_dir(&state))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AuthSettingsBody {
        discord_webhook: s.get_webhook().map(|s| s.to_string()),
    }))
}

// ── POST /api/admin/settings/test-webhook ──────────────────────────────────

#[derive(Serialize)]
pub struct TestWebhookResponse {
    pub ok:    bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Trigger a synthetic Discord delivery against the currently-saved
/// webhook so an admin can verify the embed renders before relying on
/// it for real logins. Uses a fixed `[test]` username + bogus key so a
/// triggered embed can never be mistaken for a real credential.
pub async fn test_webhook(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
) -> Json<TestWebhookResponse> {
    let webhook = {
        let s = state.auth_settings.read().await;
        s.get_webhook().map(|s| s.to_string())
    };
    let Some(url) = webhook else {
        return Json(TestWebhookResponse {
            ok:    false,
            error: Some("Discord webhook is not configured".into()),
        });
    };
    // Synthetic username + sentinel "key" — anyone trying to reuse the
    // delivered string against `/api/auth/login` is rejected because
    // `verify` requires an actual `key_store` entry.
    let actor   = format!("{} (test)", claims.sub);
    let sentinel = "TEST-ONLY";
    match send_discord_key(&url, &actor, sentinel).await {
        Ok(()) => Json(TestWebhookResponse { ok: true,  error: None }),
        Err(e) => Json(TestWebhookResponse {
            ok:    false,
            error: Some(format!("delivery failed: {}", e)),
        }),
    }
}
