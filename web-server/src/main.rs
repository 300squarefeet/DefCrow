use web_server::{api, builder, config, middleware, state, ws};
use axum::{middleware as axum_mw, routing::{delete, get, post}, Router};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;

use builder::{job_store::JobStore, scaffold::build_scaffold_rlib};
use config::Config;
use middleware::auth::{LoginRateLimiter, require_auth, SessionStore};
use state::AppState;

pub fn build_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/generate",        post(api::generate::generate))
        .route("/api/jobs/:id",        get(api::jobs::get_job_status))
        .route("/api/jobs/:id",        delete(api::jobs::delete_job))
        .route("/api/download/:id",    get(api::download::download_artifact))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/api/auth/login",  post(api::auth::login))
        .route("/api/auth/logout", post(api::auth::logout))
        .route("/api/health",      get(|| async { "ok" }))
        .route("/ws/jobs/:id",     get(ws::progress::ws_job_progress))
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

    let workspace = std::env::var("DEFCROW_WORKSPACE")
        .unwrap_or_else(|_| ".".into());

    let rlib = build_scaffold_rlib(&workspace)
        .expect("failed to build libscaffold.rlib");
    cfg.scaffold_rlib = rlib;

    let state = AppState {
        config:           cfg.clone(),
        sessions:         SessionStore::new(),
        jobs:             JobStore::new(),
        rate_limiter:     LoginRateLimiter::new(5, 60),
        generate_limiter: LoginRateLimiter::new(20, 60),
    };

    web_server::api::cleanup::spawn_cleanup_task(cfg.artifacts_dir.clone());

    let addr = format!("0.0.0.0:{}", cfg.port);
    let app  = build_router(state);

    tracing::info!("DefCrow server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
