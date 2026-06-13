use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    auth::{AuthSettings, UserStore},
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
    pub staged_key:       [u8; 32],
    pub staged_dir:       PathBuf,
    pub smuggler_dir:     PathBuf,
    // Auth state added for the Discord-key login flow. Wired in for
    // Tasks 3-4 to consume; main.rs construction stays as a TODO for
    // Task 7 (bootstrap admin + load from artifacts dir).
    pub user_store:       Arc<RwLock<UserStore>>,
    pub auth_settings:    Arc<RwLock<AuthSettings>>,
}
