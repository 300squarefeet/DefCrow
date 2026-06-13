//! In-memory store of pending one-time login keys delivered via
//! Discord. Keys live for 5 minutes, are single-use, and are stored as
//! HMAC-SHA256 hashes so a memory dump cannot replay them. Keyed on
//! lowercased username; issuing a fresh key for the same user
//! invalidates the previous one.

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Confusable-free alphabet (no `I`, `O`, `0`, `1`).
const KEY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const KEY_LEN:        usize = 8;
const KEY_TTL_SECS:   i64   = 300;

#[derive(Clone, Debug)]
pub struct PendingKey {
    pub key_hash:   [u8; 32],
    pub issued_at:  i64,
    pub expires_at: i64,
    pub used:       bool,
}

impl PendingKey {
    fn is_expired(&self, now: i64) -> bool { now >= self.expires_at }
}

#[derive(Default)]
pub struct KeyStore {
    inner: Arc<DashMap<String, PendingKey>>,
}

impl KeyStore {
    pub fn new() -> Self { Self::default() }

    /// Generate a fresh 8-char key, store its HMAC hash under
    /// `username` (lowercased), and return the plaintext for delivery.
    /// Overwrites any previously issued key for the same user.
    pub fn issue(&self, username: &str, session_secret: &[u8; 32]) -> String {
        let key = generate_key();
        let hash = hmac_key(&key, session_secret);
        let now = unix_now();
        self.inner.insert(
            username.to_lowercase(),
            PendingKey {
                key_hash:   hash,
                issued_at:  now,
                expires_at: now + KEY_TTL_SECS,
                used:       false,
            },
        );
        key
    }

    /// Constant-time check that `key` matches the stored hash for
    /// `username`. On success, marks the entry used and returns
    /// `true`. Replays, wrong keys, expired keys, and missing entries
    /// all return `false`.
    pub fn verify(&self, username: &str, key: &str, session_secret: &[u8; 32]) -> bool {
        let user_key = username.to_lowercase();
        let now = unix_now();
        let Some(mut entry) = self.inner.get_mut(&user_key) else { return false };
        if entry.used || entry.is_expired(now) { return false; }
        let candidate = hmac_key(key, session_secret);
        if !constant_time_eq(&candidate, &entry.key_hash) { return false; }
        entry.used = true;
        true
    }

    /// Drop entries past their expiry. Safe to call from a background
    /// task on an interval.
    pub fn cleanup(&self) {
        let now = unix_now();
        self.inner.retain(|_, v| !v.is_expired(now) && !v.used);
    }

    #[cfg(test)]
    fn force_expire(&self, username: &str) {
        if let Some(mut v) = self.inner.get_mut(&username.to_lowercase()) {
            v.expires_at = 0;
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.inner.len() }
}

fn generate_key() -> String {
    let mut buf = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| KEY_ALPHABET[(*b as usize) % KEY_ALPHABET.len()] as char)
        .collect()
}

fn hmac_key(key: &str, session_secret: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(session_secret).expect("HMAC accepts any key");
    mac.update(key.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 { diff |= a[i] ^ b[i]; }
    diff == 0
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];

    #[test]
    fn key_generation_uses_safe_alphabet() {
        for _ in 0..256 {
            let key = generate_key();
            assert_eq!(key.len(), KEY_LEN);
            for c in key.chars() {
                assert!(!"IO01".contains(c), "key {:?} contains a confusable char", key);
                assert!(c.is_ascii_uppercase() || c.is_ascii_digit(), "unexpected char: {}", c);
            }
        }
    }

    #[test]
    fn key_generation_is_8_chars() {
        let ks = KeyStore::new();
        let key = ks.issue("alice", &SECRET);
        assert_eq!(key.len(), 8);
    }

    #[test]
    fn key_generation_is_unique_per_call() {
        // Probabilistically near-zero collision odds (1/32^8 per pair).
        let ks = KeyStore::new();
        let k1 = ks.issue("alice", &SECRET);
        let k2 = ks.issue("alice", &SECRET);
        assert_ne!(k1, k2);
    }

    #[test]
    fn issuing_again_invalidates_previous_key() {
        let ks = KeyStore::new();
        let k1 = ks.issue("alice", &SECRET);
        let _  = ks.issue("alice", &SECRET);
        // Old key should no longer verify.
        assert!(!ks.verify("alice", &k1, &SECRET));
    }

    #[test]
    fn verify_succeeds_then_marks_used() {
        let ks = KeyStore::new();
        let k = ks.issue("alice", &SECRET);
        assert!(ks.verify("alice", &k, &SECRET));
        // Replay must fail.
        assert!(!ks.verify("alice", &k, &SECRET));
    }

    #[test]
    fn verify_is_case_insensitive_on_username() {
        let ks = KeyStore::new();
        let k = ks.issue("Alice", &SECRET);
        assert!(ks.verify("aLICE", &k, &SECRET));
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let ks = KeyStore::new();
        let _ = ks.issue("alice", &SECRET);
        assert!(!ks.verify("alice", "ABCDEFGH", &SECRET));
    }

    #[test]
    fn verify_fails_on_unknown_user() {
        let ks = KeyStore::new();
        assert!(!ks.verify("ghost", "ABCDEFGH", &SECRET));
    }

    #[test]
    fn verify_fails_on_expired_key() {
        let ks = KeyStore::new();
        let k = ks.issue("alice", &SECRET);
        ks.force_expire("alice");
        assert!(!ks.verify("alice", &k, &SECRET));
    }

    #[test]
    fn cleanup_drops_expired_and_used_entries() {
        let ks = KeyStore::new();
        let _ = ks.issue("alice", &SECRET);
        let b = ks.issue("bob",   &SECRET);
        ks.force_expire("alice");
        // Mark bob used.
        assert!(ks.verify("bob", &b, &SECRET));
        ks.cleanup();
        assert_eq!(ks.len(), 0);
    }
}
