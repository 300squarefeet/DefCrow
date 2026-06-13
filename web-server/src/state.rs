use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    auth::{AuthSettings, KeyStore, UserStore},
    builder::job_store::JobStore,
    config::Config,
    middleware::auth::{LoginRateLimiter, SessionStore},
};

#[derive(Clone)]
pub struct AppState {
    pub config:           Config,
    pub sessions:         SessionStore,
    pub jobs:             JobStore,
    pub rate_limiter:     LoginRateLimiter,
    pub generate_limiter: LoginRateLimiter,
    /// Rate limiter for `/api/auth/request-key`, keyed by lowercased
    /// username. Decoupled from the login limiter so that asking for a
    /// fresh key does not eat into the login attempt budget.
    pub request_key_limiter: LoginRateLimiter,
    /// Rate limiter for the auth endpoints keyed by client IP — a
    /// second guard so per-username buckets cannot be sidestepped by
    /// rotating usernames from the same address.
    pub ip_rate_limiter:  LoginRateLimiter,
    pub staged_key:       [u8; 32],
    pub staged_dir:       PathBuf,
    pub smuggler_dir:     PathBuf,
    // Auth state added for the Discord-key login flow. Wired in for
    // Tasks 3-4 to consume; main.rs construction stays as a TODO for
    // Task 7 (bootstrap admin + load from artifacts dir).
    pub user_store:       Arc<RwLock<UserStore>>,
    pub auth_settings:    Arc<RwLock<AuthSettings>>,
    pub key_store:        Arc<KeyStore>,
}
