pub mod api_hash;
pub use api_hash::djb2_hash;
#[cfg(target_os = "windows")]
pub use api_hash::resolve_by_hash;
