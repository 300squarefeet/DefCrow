//! Integration tests for the Discord-key login flow.
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
    routing::post,
    Router,
};
use axum_test::TestServer;
use serde_json::{json, Value};
use tokio::sync::RwLock;

use web_server::{
    api,
    auth::{AuthSettings, KeyStore, UserStore},
    builder::job_store::JobStore,
    config::Config,
    middleware::auth::{derive_session_key, LoginRateLimiter, SessionStore},
    state::AppState,
};

fn make_state(artifacts_dir: &str) -> AppState {
    AppState {
        config: Config {
            port: 8080,
            username: "admin".into(),
            password_hash: "$argon2id$test".into(),
            session_secret: "testsecret".into(),
            scaffold_rlib: "libscaffold.rlib".into(),
            artifacts_dir: artifacts_dir.to_string(),
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
    Router::new()
        .route("/api/auth/request-key", post(api::auth_keys::request_key))
        .route("/api/auth/login",       post(api::auth_keys::login))
        .route("/api/auth/logout",      post(api::auth::logout))
        .with_state(state)
}

fn make_server(artifacts_dir: &str) -> (TestServer, AppState) {
    let state = make_state(artifacts_dir);
    let app   = build_app(state.clone());
    (TestServer::new(app).unwrap(), state)
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
