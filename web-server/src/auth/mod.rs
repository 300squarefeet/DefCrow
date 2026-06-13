//! Authentication primitives: file-backed user store, auth settings,
//! in-memory key store for one-time Discord-delivered login keys, and
//! the Discord webhook sender used to deliver those keys.

pub mod users;
pub mod settings;
pub mod keystore;
pub mod discord;

pub use users::{UserRecord, UserStore};
pub use settings::AuthSettings;
pub use keystore::{KeyStore, PendingKey};
pub use discord::send_discord_key;
