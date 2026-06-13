use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

type HmacSha256 = Hmac<Sha256>;

const SESSION_TTL: Duration = Duration::from_secs(86400);

/// Sliding-window rate limiter for login attempts.
/// Keyed on caller-supplied strings — `username@ip` for the legacy login
/// path, lowercased username for the request-key endpoint, and the raw
/// client IP for the per-IP guard.
/// Hard cap of 10 000 entries prevents unbounded growth from attacker-supplied keys.
#[derive(Clone)]
pub struct LoginRateLimiter {
    inner:        Arc<DashMap<String, (u32, Instant)>>,
    max_attempts: u32,
    window:       Duration,
    max_entries:  usize,
}

impl LoginRateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            inner:        Arc::new(DashMap::new()),
            max_attempts,
            window:       Duration::from_secs(window_secs),
            max_entries:  10_000,
        }
    }

    /// Returns false if the key is currently rate-limited; records the attempt.
    pub fn check_and_record(&self, key: &str) -> bool {
        let now = Instant::now();
        // Prevent unbounded map growth from attacker-supplied keys.
        if self.inner.len() >= self.max_entries {
            self.evict_expired(now);
            if self.inner.len() >= self.max_entries { return false; }
        }
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

    fn evict_expired(&self, now: Instant) {
        self.inner.retain(|_, v| now.duration_since(v.1) <= self.window);
    }
}

// ── Session claims (HS256 JWT) ──────────────────────────────────────────────

/// Schema version of [`SessionClaims`]. Bump whenever the claim set
/// changes in a way that should invalidate every outstanding token
/// (e.g. the password→Discord-key migration). `decode_session` refuses
/// any token whose `ver` does not match this constant.
pub const SESSION_CLAIMS_VERSION: u32 = 2;

/// Claims carried inside the session JWT. `sub` holds the username,
/// `role` is `"admin"` or `"operator"`, `ver` pins the claim schema so
/// pre-migration tokens get rejected even when the signing secret is
/// reused, and `exp` is the unix expiry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub:  String,
    pub role: String,
    #[serde(default)]
    pub ver:  u32,
    pub iat:  i64,
    pub exp:  i64,
}

/// Stretch the configured session secret to a 32-byte HMAC key. We
/// hash rather than slice so any length is acceptable and short
/// secrets still spread their entropy across the full key.
pub fn derive_session_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Mint an HS256 JWT signed with `key` carrying the supplied claims.
pub fn sign_session_jwt(key: &[u8; 32], claims: &SessionClaims) -> String {
    let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims).unwrap());
    let data    = format!("{}.{}", header, payload);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

/// Decode and verify a session JWT. Returns `None` for any tampering,
/// signature mismatch, malformed structure, or expired token.
pub fn decode_session(token: &str, key: &[u8; 32]) -> Option<SessionClaims> {
    let mut parts = token.splitn(3, '.');
    let header  = parts.next()?;
    let payload = parts.next()?;
    let sig     = parts.next()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig).ok()?;
    let data = format!("{}.{}", header, payload);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    let raw    = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: SessionClaims = serde_json::from_slice(&raw).ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if claims.exp <= now { return None; }
    // Reject any token signed against a prior claim schema. This is
    // how the password→Discord-key migration invalidates outstanding
    // sessions without having to rotate `DEFCROW_SESSION_SECRET`.
    if claims.ver != SESSION_CLAIMS_VERSION { return None; }
    Some(claims)
}

// ── Session store ───────────────────────────────────────────────────────────

/// Maps an issued JWT to the claims it carries so we can revoke
/// individual sessions on logout. The JWT signature is verified
/// independently — this map's role is membership + revocation.
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<DashMap<String, (SessionClaims, Instant)>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(DashMap::new()) }
    }

    /// Record an issued session token + its claims. Returns the token
    /// unchanged for ergonomic chaining.
    pub fn insert(&self, token: String, claims: SessionClaims) -> String {
        self.inner.insert(token.clone(), (claims, Instant::now()));
        token
    }

    /// Look up claims for an issued token. Returns `None` if the token
    /// was revoked, never issued, or aged past `SESSION_TTL`.
    pub fn lookup(&self, token: &str) -> Option<SessionClaims> {
        let entry = self.inner.get(token)?;
        if entry.1.elapsed() >= SESSION_TTL { return None; }
        Some(entry.0.clone())
    }

    /// Membership-only check kept for legacy callers that just want a
    /// boolean.
    pub fn validate(&self, token: &str) -> bool {
        self.lookup(token).is_some()
    }

    pub fn remove(&self, token: &str) {
        self.inner.remove(token);
    }
}

// ── Middleware ──────────────────────────────────────────────────────────────

pub async fn require_auth(
    State(state): State<crate::state::AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Membership check first — covers logout-style revocation.
    let stored = state.sessions.lookup(&token).ok_or(StatusCode::UNAUTHORIZED)?;

    // Re-verify the JWT signature on every request so a stolen
    // SessionStore entry without the signing key cannot be forged.
    let key = derive_session_key(&state.config.session_secret);
    let claims = decode_session(&token, &key).ok_or(StatusCode::UNAUTHORIZED)?;

    // Defense in depth: if the stored claims diverge from the JWT
    // claims, refuse — protects against a poisoned in-memory entry.
    if stored.sub != claims.sub || stored.role != claims.role {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Inject the claims so downstream handlers (notably the admin
    // guard) can pull username + role without re-decoding.
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] { derive_session_key("testsecret") }

    fn make_claims(role: &str) -> SessionClaims {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        SessionClaims {
            sub:  "alice".into(),
            role: role.into(),
            ver:  SESSION_CLAIMS_VERSION,
            iat:  now,
            exp:  now + 3600,
        }
    }

    #[test]
    fn sign_then_decode_roundtrip() {
        let k = key();
        let claims = make_claims("admin");
        let tok = sign_session_jwt(&k, &claims);
        let got = decode_session(&tok, &k).expect("verifies");
        assert_eq!(got.sub, "alice");
        assert_eq!(got.role, "admin");
    }

    #[test]
    fn decode_rejects_tampered_token() {
        let k = key();
        let claims = make_claims("operator");
        let mut tok = sign_session_jwt(&k, &claims);
        tok.push('x');
        assert!(decode_session(&tok, &k).is_none());
    }

    #[test]
    fn decode_rejects_wrong_key() {
        let k1 = key();
        let k2 = derive_session_key("othersecret");
        let claims = make_claims("admin");
        let tok = sign_session_jwt(&k1, &claims);
        assert!(decode_session(&tok, &k2).is_none());
    }

    #[test]
    fn decode_rejects_expired() {
        let k = key();
        let mut claims = make_claims("admin");
        claims.exp = 0;
        let tok = sign_session_jwt(&k, &claims);
        assert!(decode_session(&tok, &k).is_none());
    }

    #[test]
    fn decode_rejects_pre_migration_ver() {
        // Tokens minted before the schema bump default to ver=0 via
        // `#[serde(default)]`. Those must fail to decode so the
        // password→Discord-key cutover invalidates outstanding
        // sessions without rotating the signing secret.
        let k = key();
        let mut claims = make_claims("admin");
        claims.ver = 0;
        let tok = sign_session_jwt(&k, &claims);
        assert!(decode_session(&tok, &k).is_none());
    }

    #[test]
    fn session_store_insert_lookup_remove() {
        let store = SessionStore::new();
        let claims = make_claims("admin");
        let tok = store.insert("tok123".into(), claims.clone());
        let got = store.lookup(&tok).unwrap();
        assert_eq!(got.sub, claims.sub);
        assert!(store.validate(&tok));
        store.remove(&tok);
        assert!(!store.validate(&tok));
    }

    #[test]
    fn session_store_unknown_token() {
        let store = SessionStore::new();
        assert!(store.lookup("nope").is_none());
        assert!(!store.validate("nope"));
    }
}
