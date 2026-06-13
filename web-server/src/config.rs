use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port:                u16,
    pub session_secret:      String,
    pub scaffold_rlib:       String,
    pub artifacts_dir:       String,
    /// Username seeded into `users.json` on first run when the file
    /// does not yet exist. Defaults to `admin`.
    pub bootstrap_username:  String,
    /// Optional Discord webhook URL used to seed `auth_settings.json`
    /// on first run when the file does not yet exist. Lets a fresh
    /// deployment escape the chicken-and-egg of needing to log in to
    /// configure the webhook that delivers the login key.
    pub bootstrap_webhook:   Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            port:                env::var("DEFCROW_PORT")
                                   .unwrap_or("8080".into()).parse()?,
            session_secret:      env::var("DEFCROW_SESSION_SECRET")
                                   .expect("DEFCROW_SESSION_SECRET must be set"),
            scaffold_rlib:       env::var("DEFCROW_SCAFFOLD_RLIB")
                                   .unwrap_or("target/x86_64-pc-windows-gnu/release/libloader_scaffold.rlib".into()),
            artifacts_dir:       env::var("DEFCROW_ARTIFACTS_DIR")
                                   .unwrap_or("/tmp/defcrow-artifacts".into()),
            bootstrap_username:  env::var("DEFCROW_BOOTSTRAP_USERNAME")
                                   .unwrap_or("admin".into()),
            bootstrap_webhook:   env::var("DEFCROW_BOOTSTRAP_WEBHOOK")
                                   .ok()
                                   .map(|s| s.trim().to_string())
                                   .filter(|s| !s.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        std::env::set_var("DEFCROW_SESSION_SECRET", "testsecret");
        std::env::remove_var("DEFCROW_BOOTSTRAP_USERNAME");
        std::env::remove_var("DEFCROW_BOOTSTRAP_WEBHOOK");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.bootstrap_username, "admin");
        assert!(cfg.bootstrap_webhook.is_none());
    }

    #[test]
    fn test_bootstrap_webhook_blank_is_none() {
        std::env::set_var("DEFCROW_SESSION_SECRET", "testsecret");
        std::env::set_var("DEFCROW_BOOTSTRAP_WEBHOOK", "   ");
        let cfg = Config::from_env().unwrap();
        assert!(cfg.bootstrap_webhook.is_none());
        std::env::remove_var("DEFCROW_BOOTSTRAP_WEBHOOK");
    }
}
