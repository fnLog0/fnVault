//! Platform abstraction for secret storage, unlock authentication, and
//! lock events.
//!
//! Each backend exposes the same free functions, selected at compile time:
//!   `master_key_exists`, `store_master_key`, `read_master_key`,
//!   `delete_master_key`, `touchid_authenticate`, `touch_id_unlock`,
//!   `set_item`, `get_item`, `delete_item`, `run_lock_observer`.
//!
//! - **macOS** ([`macos`]): Keychain + Touch ID (LocalAuthentication).
//! - **Linux** ([`linux`]): Secret Service (via `keyring`) + a passphrase gate.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
