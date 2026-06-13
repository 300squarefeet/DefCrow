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

    pub fn set_webhook(&mut self, url: Option<String>) {
        self.discord_webhook = url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
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
        s.set_webhook(Some("https://discord.com/api/webhooks/abc".into()));
        assert_eq!(s.get_webhook(), Some("https://discord.com/api/webhooks/abc"));
        s.set_webhook(None);
        assert!(s.get_webhook().is_none());
    }

    #[test]
    fn empty_string_clears_webhook() {
        let mut s = AuthSettings::default();
        s.set_webhook(Some("   ".into()));
        assert!(s.get_webhook().is_none());
    }

    #[test]
    fn save_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut s = AuthSettings::default();
        s.set_webhook(Some("https://discord.com/api/webhooks/xyz".into()));
        s.save(tmp.path()).unwrap();
        let loaded = AuthSettings::load(tmp.path()).unwrap();
        assert_eq!(loaded.get_webhook(), Some("https://discord.com/api/webhooks/xyz"));
    }
}
