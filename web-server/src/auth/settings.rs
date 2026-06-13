//! Global auth settings persisted to `${artifacts_dir}/auth_settings.json`.
//! Currently holds the Discord webhook URL used for delivering one-time
//! login keys. Atomic-rename writes mirror the user store.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const SETTINGS_FILE:  &str = "auth_settings.json";
const TMP_SUFFIX:     &str = ".tmp";
const SCHEMA_VERSION:  u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AuthSettings {
    #[serde(default)]
    pub version:         u32,
    #[serde(default)]
    pub discord_webhook: Option<String>,
}

impl AuthSettings {
    /// Load from disk. Missing file is not an error — we return defaults
    /// so a fresh deployment can boot before an admin configures
    /// Discord.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        if !path.exists() {
            return Ok(Self::default_with_version());
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut parsed: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        if parsed.version == 0 { parsed.version = SCHEMA_VERSION; }
        Ok(parsed)
    }

    pub fn get_webhook(&self) -> Option<&str> {
        self.discord_webhook.as_deref().filter(|s| !s.is_empty())
    }

    /// Set or clear the Discord webhook URL. Validates that the URL is
    /// rooted at the official Discord webhook host so a compromised
    /// admin (or a misclick) cannot redirect login keys to an attacker
    /// endpoint — i.e. SSRF / token-exfil hardening at the persistence
    /// boundary.
    pub fn set_webhook(&mut self, url: Option<String>) -> Result<()> {
        let normalized = url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if let Some(ref u) = normalized {
            validate_webhook_url(u)?;
        }
        self.discord_webhook = normalized;
        Ok(())
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path     = Self::path(dir);
        let tmp_path = Self::tmp_path(dir);
        let mut out = self.clone();
        out.version = SCHEMA_VERSION;
        let serialized = serde_json::to_string_pretty(&out)?;
        std::fs::write(&tmp_path, serialized.as_bytes())
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &path)
            .with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }

    fn default_with_version() -> Self {
        Self { version: SCHEMA_VERSION, discord_webhook: None }
    }

    fn path(dir: &Path) -> PathBuf { dir.join(SETTINGS_FILE) }
    fn tmp_path(dir: &Path) -> PathBuf { dir.join(format!("{}{}", SETTINGS_FILE, TMP_SUFFIX)) }
}

/// Reject anything that isn't a Discord webhook URL. Accepts only
/// `https://discord.com/api/webhooks/...` and the legacy
/// `https://discordapp.com/api/webhooks/...` alias. Rejecting other
/// schemes/hosts blocks SSRF and credential-exfil to attacker
/// infrastructure.
fn validate_webhook_url(url: &str) -> Result<()> {
    const ALLOWED_PREFIXES: &[&str] = &[
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/",
        "https://canary.discord.com/api/webhooks/",
        "https://ptb.discord.com/api/webhooks/",
    ];
    if !ALLOWED_PREFIXES.iter().any(|p| url.starts_with(p)) {
        return Err(anyhow::anyhow!(
            "webhook URL must start with https://discord.com/api/webhooks/"
        ));
    }
    // Reject embedded credentials / @ tricks (e.g.
    // `https://discord.com/api/webhooks/@evil.com/...`) by checking the
    // path segment immediately after `/api/webhooks/` does not contain
    // an `@` before the next `/`.
    if let Some(tail) = url.splitn(2, "/api/webhooks/").nth(1) {
        let first_seg = tail.split('/').next().unwrap_or("");
        if first_seg.contains('@') || first_seg.is_empty() {
            return Err(anyhow::anyhow!(
                "webhook URL contains an invalid path segment"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_empty_webhook() {
        let tmp = TempDir::new().unwrap();
        let settings = AuthSettings::load(tmp.path()).unwrap();
        assert!(settings.get_webhook().is_none());
    }

    #[test]
    fn set_then_get() {
        let mut s = AuthSettings::default();
        s.set_webhook(Some("https://discord.com/api/webhooks/abc".into())).unwrap();
        assert_eq!(s.get_webhook(), Some("https://discord.com/api/webhooks/abc"));
        s.set_webhook(None).unwrap();
        assert!(s.get_webhook().is_none());
    }

    #[test]
    fn empty_string_clears_webhook() {
        let mut s = AuthSettings::default();
        s.set_webhook(Some("   ".into())).unwrap();
        assert!(s.get_webhook().is_none());
    }

    #[test]
    fn save_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut s = AuthSettings::default();
        s.set_webhook(Some("https://discord.com/api/webhooks/xyz".into())).unwrap();
        s.save(tmp.path()).unwrap();
        let loaded = AuthSettings::load(tmp.path()).unwrap();
        assert_eq!(loaded.get_webhook(), Some("https://discord.com/api/webhooks/xyz"));
    }

    #[test]
    fn rejects_non_discord_host() {
        let mut s = AuthSettings::default();
        let err = s.set_webhook(Some("https://evil.example/api/webhooks/abc".into())).unwrap_err();
        assert!(err.to_string().contains("discord.com"));
        assert!(s.get_webhook().is_none());
    }

    #[test]
    fn rejects_http_scheme() {
        let mut s = AuthSettings::default();
        assert!(s.set_webhook(Some("http://discord.com/api/webhooks/abc".into())).is_err());
    }

    #[test]
    fn rejects_at_sign_smuggling() {
        let mut s = AuthSettings::default();
        // `@` in the first path segment is the classic credential-in-URL
        // exfil trick — refuse outright.
        assert!(s.set_webhook(Some("https://discord.com/api/webhooks/@evil.example/x".into())).is_err());
    }

    #[test]
    fn accepts_canary_and_ptb_subdomains() {
        let mut s = AuthSettings::default();
        s.set_webhook(Some("https://canary.discord.com/api/webhooks/1/abc".into())).unwrap();
        s.set_webhook(Some("https://ptb.discord.com/api/webhooks/1/abc".into())).unwrap();
    }
}
