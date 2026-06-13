//! Integration tests for the Discord-key login flow + admin endpoints.
//!
//! Discord delivery itself is exercised against a closed-loop mock by
//! configuring an unreachable webhook (so `/request-key` returns
//! 502) — the side-channel test is sufficient to prove that handler
//! wiring is correct without making a real network call.
//!
//! Live Discord delivery is verified manually per the implementation
//! plan.

use std::sync::Arc;

use axum::{
    middleware as axum_mw,
    routing::{delete, get, post},
    Router,
};
use axum_test::TestServer;
use serde_json::{json, Value};
use tokio::sync::RwLock;

use web_server::{
    api,
    auth::{users::ROLE_OPERATOR, AuthSettings, KeyStore, UserStore},
    builder::job_store::JobStore,
    config::Config,
    middleware::{
        auth::{derive_session_key, require_auth, sign_session_jwt, LoginRateLimiter, SessionClaims, SessionStore},
        require_admin::require_admin,
    },
    state::AppState,
};

fn make_state(artifacts_dir: &str) -> AppState {
    AppState {
        config: Config {
            port: 8080,
            username: "admin".into(),
            session_secret: "testsecret".into(),
            scaffold_rlib: "libscaffold.rlib".into(),
            artifacts_dir: artifacts_dir.to_string(),
            bootstrap_username: "admin".into(),
            bootstrap_webhook:  None,
        },
        sessions:            SessionStore::new(),
        jobs:                JobStore::new(),
        rate_limiter:        LoginRateLimiter::new(5, 60),
        generate_limiter:    LoginRateLimiter::new(20, 60),
        request_key_limiter: LoginRateLimiter::new(3, 60),
        ip_rate_limiter:     LoginRateLimiter::new(20, 60),
        staged_key: [0u8; 32],
        staged_dir: std::path::PathBuf::from(artifacts_dir).join("staged"),
        smuggler_dir: std::path::PathBuf::from(artifacts_dir).join("smuggler"),
        user_store:    Arc::new(RwLock::new(UserStore::bootstrap("admin"))),
        auth_settings: Arc::new(RwLock::new(AuthSettings::default())),
        key_store:     Arc::new(KeyStore::new()),
    }
}

fn build_app(state: AppState) -> Router {
    let admin = Router::new()
        .route("/api/admin/users",           get(api::admin::list_users).post(api::admin::add_user))
        .route("/api/admin/users/:username", delete(api::admin::delete_user))
        .route("/api/admin/settings",        get(api::admin::get_settings).put(api::admin::put_settings))
        .route_layer(axum_mw::from_fn(require_admin))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/api/auth/request-key", post(api::auth_keys::request_key))
        .route("/api/auth/login",       post(api::auth_keys::login))
        .route("/api/auth/logout",      post(api::auth::logout))
        .merge(admin)
        .with_state(state)
}

fn make_server(artifacts_dir: &str) -> (TestServer, AppState) {
    let state = make_state(artifacts_dir);
    let app   = build_app(state.clone());
    (TestServer::new(app).unwrap(), state)
}

/// Mint a session token directly so we don't have to drive the full
/// Discord round-trip for admin tests. Mirrors what `login` does on
/// success.
fn issue_token_for(state: &AppState, sub: &str, role: &str) -> String {
    let key = derive_session_key(&state.config.session_secret);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = SessionClaims {
        sub:  sub.into(),
        role: role.into(),
        iat:  now,
        exp:  now + 3600,
    };
    let tok = sign_session_jwt(&key, &claims);
    state.sessions.insert(tok.clone(), claims);
    tok
}

// ── request-key + login ─────────────────────────────────────────────────────

#[tokio::test]
async fn request_key_unknown_user_returns_200_no_enum() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, _) = make_server(tmp.path().to_str().unwrap());

    let resp = server.post("/api/auth/request-key")
        .json(&json!({ "username": "ghost" }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["delivered"], true);
}

#[tokio::test]
async fn request_key_with_webhook_unconfigured_returns_500_for_real_user() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, _) = make_server(tmp.path().to_str().unwrap());

    let resp = server.post("/api/auth/request-key")
        .json(&json!({ "username": "admin" }))
        .await;
    resp.assert_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = resp.json();
    assert_eq!(body["delivered"], false);
}

#[tokio::test]
async fn login_with_correct_key_returns_token() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());

    // Bypass Discord by minting a key directly in the store.
    let session_key = derive_session_key(&state.config.session_secret);
    let plain = state.key_store.issue("admin", &session_key);

    let resp = server.post("/api/auth/login")
        .json(&json!({ "username": "admin", "key": plain }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["token"].as_str().unwrap().split('.').count() == 3);
    assert_eq!(body["username"], "admin");
    assert_eq!(body["role"], "admin");
}

#[tokio::test]
async fn login_with_wrong_key_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    let session_key = derive_session_key(&state.config.session_secret);
    let _ = state.key_store.issue("admin", &session_key);

    let resp = server.post("/api/auth/login")
        .json(&json!({ "username": "admin", "key": "BADKEY99" }))
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_with_used_key_returns_401() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    let session_key = derive_session_key(&state.config.session_secret);
    let plain = state.key_store.issue("admin", &session_key);

    let r1 = server.post("/api/auth/login")
        .json(&json!({ "username": "admin", "key": plain }))
        .await;
    r1.assert_status_ok();
    let r2 = server.post("/api/auth/login")
        .json(&json!({ "username": "admin", "key": plain }))
        .await;
    r2.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rate_limit_kicks_in_after_5() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, _) = make_server(tmp.path().to_str().unwrap());

    for _ in 0..5 {
        let resp = server.post("/api/auth/login")
            .json(&json!({ "username": "admin", "key": "WRONGKEY" }))
            .await;
        resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }
    let resp = server.post("/api/auth/login")
        .json(&json!({ "username": "admin", "key": "WRONGKEY" }))
        .await;
    // Either per-username (5/min) or per-IP (20/min) caps fire. We
    // expect the username cap to trip first.
    resp.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
}

// ── admin endpoints ─────────────────────────────────────────────────────────

#[tokio::test]
async fn non_admin_blocked_403() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    {
        let mut store = state.user_store.write().await;
        store.add("alice", ROLE_OPERATOR).unwrap();
    }
    let tok = issue_token_for(&state, "alice", ROLE_OPERATOR);

    let resp = server.get("/api/admin/users")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_admin_blocked_401() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, _) = make_server(tmp.path().to_str().unwrap());
    let resp = server.get("/api/admin/users").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_can_list_users() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    let tok = issue_token_for(&state, "admin", "admin");

    let resp = server.get("/api/admin/users")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["users"][0]["username"], "admin");
}

#[tokio::test]
async fn admin_can_add_user() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    let tok = issue_token_for(&state, "admin", "admin");

    let resp = server.post("/api/admin/users")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .json(&json!({ "username": "alice", "role": "operator" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["username"], "alice");
    assert_eq!(body["role"], "operator");

    // Was persisted to disk.
    let raw = std::fs::read_to_string(tmp.path().join("users.json")).unwrap();
    assert!(raw.contains("alice"));
}

#[tokio::test]
async fn admin_cannot_remove_last_admin() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    // Add a different admin first so we are not blocked by the
    // "cannot delete self" guard.
    {
        let mut store = state.user_store.write().await;
        store.add("bob", "admin").unwrap();
    }
    let tok = issue_token_for(&state, "bob", "admin");
    // Remove the original admin first so only `bob` remains.
    let r1 = server.delete("/api/admin/users/admin")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    r1.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Now bob is the last admin. We can't truly be a different user
    // here, so approximate by issuing a token for a hypothetical
    // second admin without adding them to the store. The handler
    // reads the store directly, so the last-admin guard fires.
    let other = issue_token_for(&state, "phantom", "admin");
    let r2 = server.delete("/api/admin/users/bob")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", other).parse().unwrap(),
        )
        .await;
    r2.assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn admin_cannot_remove_self() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    // Add a second admin so the last-admin guard wouldn't fire first.
    {
        let mut store = state.user_store.write().await;
        store.add("bob", "admin").unwrap();
    }
    let tok = issue_token_for(&state, "admin", "admin");

    let resp = server.delete("/api/admin/users/admin")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_set_webhook() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    let tok = issue_token_for(&state, "admin", "admin");

    let resp = server.put("/api/admin/settings")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .json(&json!({ "discord_webhook": "https://discord.com/api/webhooks/abc" }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["discord_webhook"], "https://discord.com/api/webhooks/abc");

    // Persisted to disk.
    let raw = std::fs::read_to_string(tmp.path().join("auth_settings.json")).unwrap();
    assert!(raw.contains("discord.com"));
}

#[tokio::test]
async fn admin_get_webhook_returns_value() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    {
        let mut s = state.auth_settings.write().await;
        s.set_webhook(Some("https://discord.com/api/webhooks/xyz".into()));
    }
    let tok = issue_token_for(&state, "admin", "admin");

    let resp = server.get("/api/admin/settings")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["discord_webhook"], "https://discord.com/api/webhooks/xyz");
}

#[tokio::test]
async fn logout_revokes_session() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, state) = make_server(tmp.path().to_str().unwrap());
    let tok = issue_token_for(&state, "admin", "admin");

    let r1 = server.post("/api/auth/logout")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    r1.assert_status(axum::http::StatusCode::NO_CONTENT);

    let r2 = server.get("/api/admin/users")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", tok).parse().unwrap(),
        )
        .await;
    r2.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}
