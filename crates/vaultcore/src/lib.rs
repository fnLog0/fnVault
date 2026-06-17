//! fnVault shared core: crypto, Keychain/Touch ID access, the session state
//! machine, and the daemon wire protocol.

pub mod backup;
pub mod crypto;
pub mod error;
pub mod paths;
pub mod platform;
pub mod protocol;
pub mod session;
pub mod store;
pub mod totp;

/// Backwards-compatible alias: the storage/auth backend used to live in a
/// macOS-only `keychain` module; it is now the cross-platform [`platform`].
pub use platform as keychain;

pub use error::{Result, VaultError};
