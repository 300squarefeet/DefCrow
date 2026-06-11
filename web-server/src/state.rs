use std::path::PathBuf;
use crate::{builder::job_store::JobStore, config::Config, middleware::auth::{LoginRateLimiter, SessionStore}};

#[derive(Clone)]
pub struct AppState {
    pub config:           Config,
    pub sessions:         SessionStore,
    pub jobs:             JobStore,
    pub rate_limiter:     LoginRateLimiter,
    pub generate_limiter: LoginRateLimiter,
    pub staged_key:       [u8; 32],
    pub staged_dir:       PathBuf,
}
