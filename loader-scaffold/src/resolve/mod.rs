pub mod api_hash;
pub use api_hash::{djb2_hash, djb2_hash_lower};
#[cfg(target_os = "windows")]
pub use api_hash::resolve_by_hash;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use api_hash::peb_get_module_base;
