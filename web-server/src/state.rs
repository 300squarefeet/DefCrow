use crate::{builder::job_store::JobStore, config::Config, middleware::auth::SessionStore};

#[derive(Clone)]
pub struct AppState {
    pub config:   Config,
    pub sessions: SessionStore,
    pub jobs:     JobStore,
}
