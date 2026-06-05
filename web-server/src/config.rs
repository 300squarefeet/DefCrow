use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port:           u16,
    pub username:       String,
    pub password_hash:  String,
    pub session_secret: String,
    pub scaffold_rlib:  String,
    pub artifacts_dir:  String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            port:           env::var("DEFCROW_PORT")
                              .unwrap_or("8080".into()).parse()?,
            username:       env::var("DEFCROW_USERNAME")
                              .unwrap_or("admin".into()),
            password_hash:  env::var("DEFCROW_PASSWORD_HASH")
                              .expect("DEFCROW_PASSWORD_HASH must be set"),
            session_secret: env::var("DEFCROW_SESSION_SECRET")
                              .expect("DEFCROW_SESSION_SECRET must be set"),
            scaffold_rlib:  env::var("DEFCROW_SCAFFOLD_RLIB")
                              .unwrap_or("target/x86_64-pc-windows-gnu/release/libscaffold.rlib".into()),
            artifacts_dir:  env::var("DEFCROW_ARTIFACTS_DIR")
                              .unwrap_or("/tmp/defcrow-artifacts".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        std::env::set_var("DEFCROW_PASSWORD_HASH", "$argon2id$test");
        std::env::set_var("DEFCROW_SESSION_SECRET", "testsecret");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.username, "admin");
    }
}
