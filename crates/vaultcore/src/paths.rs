//! Per-user runtime locations.

use std::path::PathBuf;

/// `~/Library/Caches/fnvault` on macOS.
pub fn runtime_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("fnvault")
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("vaultd.sock")
}

pub fn log_path() -> PathBuf {
    runtime_dir().join("vaultd.log")
}
