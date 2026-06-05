use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, Rng};
use std::{sync::Arc, time::{Duration, Instant}};

const SESSION_TTL: Duration = Duration::from_secs(86400);
const TOKEN_LEN:   usize    = 64;

#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<DashMap<String, Instant>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(DashMap::new()) }
    }

    pub fn create_session(&self) -> String {
        let token: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(TOKEN_LEN)
            .map(char::from)
            .collect();
        self.inner.insert(token.clone(), Instant::now());
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        match self.inner.get(token) {
            Some(created) => created.elapsed() < SESSION_TTL,
            None => false,
        }
    }

    pub fn remove(&self, token: &str) {
        self.inner.remove(token);
    }
}

pub async fn require_auth(
    State(sessions): State<SessionStore>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    match auth {
        Some(token) if sessions.validate(&token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create_and_validate() {
        let store = SessionStore::new();
        let token = store.create_session();
        assert!(store.validate(&token));
    }

    #[test]
    fn test_invalid_token_rejected() {
        let store = SessionStore::new();
        assert!(!store.validate("not-a-real-token"));
    }

    #[test]
    fn test_removed_token_invalid() {
        let store = SessionStore::new();
        let token = store.create_session();
        store.remove(&token);
        assert!(!store.validate(&token));
    }
}
