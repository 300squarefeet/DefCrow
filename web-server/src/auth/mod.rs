//! Authentication primitives: file-backed user store and global auth
//! settings. KeyStore + Discord delivery are added in Task 2.

pub mod users;
pub mod settings;

pub use users::{UserRecord, UserStore};
pub use settings::AuthSettings;
