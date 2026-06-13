use axum_test::TestServer;
use axum::{
    routing::get,
    Router,
};
use web_server::{
    api::download::download_artifact,
    auth::{AuthSettings, KeyStore, UserStore},
    builder::job_store::JobStore,
    config::Config,
    middleware::auth::{LoginRateLimiter, SessionStore},
    state::AppState,
};

fn make_state(artifacts_dir: &str) -> AppState {
    AppState {
        config: Config {
            port: 8080,
            session_secret: "testsecret".into(),
            scaffold_rlib: "libscaffold.rlib".into(),
            artifacts_dir: artifacts_dir.to_string(),
            bootstrap_username: "admin".into(),
            bootstrap_webhook:  None,
        },
        sessions:         SessionStore::new(),
        jobs:             JobStore::new(),
        rate_limiter:     LoginRateLimiter::new(5, 60),
        generate_limiter: LoginRateLimiter::new(20, 60),
        request_key_limiter: LoginRateLimiter::new(3, 60),
        ip_rate_limiter:  LoginRateLimiter::new(10, 60),
        staged_key:       [0u8; 32],
        staged_dir:       std::path::PathBuf::from(artifacts_dir).join("staged"),
        smuggler_dir:     std::path::PathBuf::from(artifacts_dir).join("smuggler"),
        user_store:       std::sync::Arc::new(tokio::sync::RwLock::new(UserStore::default())),
        auth_settings:    std::sync::Arc::new(tokio::sync::RwLock::new(AuthSettings::default())),
        key_store:        std::sync::Arc::new(KeyStore::new()),
    }
}

fn make_server(artifacts_dir: &str) -> TestServer {
    let app = Router::new()
        .route("/download/:id", get(download_artifact))
        .with_state(make_state(artifacts_dir));
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn download_serves_artifact_and_deletes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let art_path = tmp.path().join("payload.exe");
    std::fs::write(&art_path, b"MZTEST").unwrap();

    // Write .path pointer file
    let path_file = tmp.path().join("abc123.path");
    std::fs::write(&path_file, art_path.to_str().unwrap()).unwrap();

    let server = make_server(tmp.path().to_str().unwrap());
    let resp = server.get("/download/abc123").await;
    resp.assert_status_ok();
    assert_eq!(resp.as_bytes(), b"MZTEST" as &[u8]);

    // Artifact and pointer must be gone
    assert!(!art_path.exists(), "artifact must be deleted after download");
    assert!(!path_file.exists(), ".path file must be deleted after download");
}

#[tokio::test]
async fn download_is_one_time_only() {
    let tmp = tempfile::tempdir().unwrap();
    let art_path = tmp.path().join("payload2.exe");
    std::fs::write(&art_path, b"MZTEST2").unwrap();

    let path_file = tmp.path().join("xyz789.path");
    std::fs::write(&path_file, art_path.to_str().unwrap()).unwrap();

    let server = make_server(tmp.path().to_str().unwrap());

    // First request: success
    let resp1 = server.get("/download/xyz789").await;
    resp1.assert_status_ok();

    // Second request: 404 (artifact consumed)
    let resp2 = server.get("/download/xyz789").await;
    resp2.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_unknown_id_returns_404() {
    let tmp = tempfile::tempdir().unwrap();
    let server = make_server(tmp.path().to_str().unwrap());
    let resp = server.get("/download/nonexistent").await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
