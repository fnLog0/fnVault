//! fnVault shared core: crypto, Keychain/Touch ID access, the session state
//! machine, and the daemon wire protocol.

pub mod crypto;
pub mod error;
pub mod keychain;
pub mod paths;
pub mod protocol;
pub mod session;
pub mod store;

pub use error::{Result, VaultError};
