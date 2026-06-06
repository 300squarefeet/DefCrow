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

/// Sliding-window rate limiter for login attempts (keyed by client IP).
/// Tracks (attempt_count, window_start) per key.
#[derive(Clone)]
pub struct LoginRateLimiter {
    inner:        Arc<DashMap<String, (u32, Instant)>>,
    max_attempts: u32,
    window:       Duration,
}

impl LoginRateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            inner:        Arc::new(DashMap::new()),
            max_attempts,
            window:       Duration::from_secs(window_secs),
        }
    }

    /// Returns false if the key is currently rate-limited; records the attempt.
    pub fn check_and_record(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut entry = self.inner.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > self.window {
            *entry = (1, now);
            true
        } else if entry.0 >= self.max_attempts {
            false
        } else {
            entry.0 += 1;
            true
        }
    }

    pub fn reset(&self, key: &str) {
        self.inner.remove(key);
    }
}

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
    State(state): State<crate::state::AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    match auth {
        Some(token) if state.sessions.validate(&token) => Ok(next.run(req).await),
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
