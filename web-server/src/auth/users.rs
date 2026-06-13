//! File-backed user store. Persists to `${artifacts_dir}/users.json`
//! using an atomic write-then-rename pattern. Enforces uniqueness of
//! usernames and refuses to delete the last admin so the deployment
//! cannot lock itself out.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

const USERS_FILE:    &str = "users.json";
const TMP_SUFFIX:    &str = ".tmp";
const SCHEMA_VERSION: u32 = 1;

pub const ROLE_ADMIN:    &str = "admin";
pub const ROLE_OPERATOR: &str = "operator";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub username:   String,
    pub role:       String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UsersFile {
    version: u32,
    users:   Vec<UserRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct UserStore {
    users: Vec<UserRecord>,
}

impl UserStore {
    /// Load the user store from `${dir}/users.json`. If the file does
    /// not yet exist, bootstrap a single admin user with
    /// `bootstrap_username` and persist it before returning.
    pub fn load(dir: &Path, bootstrap_username: &str) -> Result<Self> {
        let path = Self::path(dir);
        if !path.exists() {
            let store = Self::bootstrap(bootstrap_username);
            store.save(dir)?;
            return Ok(store);
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let file: UsersFile = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(Self { users: file.users })
    }

    /// Construct an in-memory store seeded with a single admin user.
    /// Does not touch disk; pair with [`save`] to persist.
    pub fn bootstrap(bootstrap_username: &str) -> Self {
        let now = now_iso8601();
        Self {
            users: vec![UserRecord {
                username:   bootstrap_username.to_string(),
                role:       ROLE_ADMIN.to_string(),
                created_at: now,
            }],
        }
    }

    pub fn list(&self) -> Vec<UserRecord> {
        self.users.clone()
    }

    pub fn find(&self, username: &str) -> Option<&UserRecord> {
        let needle = username.to_lowercase();
        self.users.iter().find(|u| u.username.to_lowercase() == needle)
    }

    /// Add a new user. Rejects duplicate usernames (case-insensitive)
    /// and unknown roles.
    pub fn add(&mut self, username: &str, role: &str) -> Result<()> {
        if username.trim().is_empty() {
            return Err(anyhow!("username cannot be empty"));
        }
        if role != ROLE_ADMIN && role != ROLE_OPERATOR {
            return Err(anyhow!("role must be 'admin' or 'operator'"));
        }
        if self.find(username).is_some() {
            return Err(anyhow!("user '{}' already exists", username));
        }
        self.users.push(UserRecord {
            username:   username.to_string(),
            role:       role.to_string(),
            created_at: now_iso8601(),
        });
        Ok(())
    }

    /// Remove a user. Refuses to remove the last admin so the
    /// deployment can always be re-administered.
    pub fn remove(&mut self, username: &str) -> Result<()> {
        let needle = username.to_lowercase();
        let idx = self.users.iter().position(|u| u.username.to_lowercase() == needle)
            .ok_or_else(|| anyhow!("user '{}' not found", username))?;
        if self.users[idx].role == ROLE_ADMIN {
            let admin_count = self.users.iter().filter(|u| u.role == ROLE_ADMIN).count();
            if admin_count <= 1 {
                return Err(anyhow!("cannot remove the last admin user"));
            }
        }
        self.users.remove(idx);
        Ok(())
    }

    /// Persist atomically: write to `users.json.tmp` and rename.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path     = Self::path(dir);
        let tmp_path = Self::tmp_path(dir);
        let file = UsersFile { version: SCHEMA_VERSION, users: self.users.clone() };
        let serialized = serde_json::to_string_pretty(&file)?;
        std::fs::write(&tmp_path, serialized.as_bytes())
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &path)
            .with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }

    fn path(dir: &Path) -> PathBuf { dir.join(USERS_FILE) }
    fn tmp_path(dir: &Path) -> PathBuf { dir.join(format!("{}{}", USERS_FILE, TMP_SUFFIX)) }
}

fn now_iso8601() -> String {
    // Format like `2026-06-13T10:00:00Z` using std-only.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    iso8601_from_unix(secs)
}

/// Convert unix seconds (UTC) to an ISO-8601 string. std-only impl
/// suitable for a timestamp we never need to parse back.
fn iso8601_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem  = secs.rem_euclid(86_400);
    let h    = rem / 3600;
    let m    = (rem % 3600) / 60;
    let s    = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

/// Howard Hinnant's days-from-civil inverse. Returns (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z   = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y   = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m   = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y   = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn bootstrap_creates_admin_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let store = UserStore::load(tmp.path(), "admin").unwrap();
        let users = store.list();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].role, ROLE_ADMIN);
        // File should now exist on disk.
        assert!(tmp.path().join(USERS_FILE).exists());
    }

    #[test]
    fn add_then_find() {
        let mut store = UserStore::bootstrap("admin");
        store.add("alice", ROLE_OPERATOR).unwrap();
        let found = store.find("AliCE").unwrap();
        assert_eq!(found.username, "alice");
        assert_eq!(found.role, ROLE_OPERATOR);
    }

    #[test]
    fn add_duplicate_rejected() {
        let mut store = UserStore::bootstrap("admin");
        store.add("alice", ROLE_OPERATOR).unwrap();
        let err = store.add("ALICE", ROLE_ADMIN).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_rejects_unknown_role() {
        let mut store = UserStore::bootstrap("admin");
        let err = store.add("alice", "wizard").unwrap_err();
        assert!(err.to_string().contains("role must be"));
    }

    #[test]
    fn remove_last_admin_rejected() {
        let mut store = UserStore::bootstrap("admin");
        let err = store.remove("admin").unwrap_err();
        assert!(err.to_string().contains("last admin"));
    }

    #[test]
    fn remove_operator_ok() {
        let mut store = UserStore::bootstrap("admin");
        store.add("alice", ROLE_OPERATOR).unwrap();
        store.remove("alice").unwrap();
        assert!(store.find("alice").is_none());
    }

    #[test]
    fn remove_admin_ok_when_other_admin_present() {
        let mut store = UserStore::bootstrap("admin");
        store.add("alice", ROLE_ADMIN).unwrap();
        store.remove("admin").unwrap();
        assert!(store.find("admin").is_none());
        assert!(store.find("alice").is_some());
    }

    #[test]
    fn save_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut store = UserStore::bootstrap("admin");
        store.add("alice", ROLE_OPERATOR).unwrap();
        store.save(tmp.path()).unwrap();
        let loaded = UserStore::load(tmp.path(), "ignored").unwrap();
        assert_eq!(loaded.list(), store.list());
        // Sanity-check the on-disk JSON.
        let raw = std::fs::read_to_string(tmp.path().join(USERS_FILE)).unwrap();
        assert!(raw.contains("\"version\""));
        assert!(raw.contains("\"alice\""));
    }
}
