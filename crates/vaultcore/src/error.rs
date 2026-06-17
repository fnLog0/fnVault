use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("authentication failed or cancelled")]
    AuthFailed,
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("vault is not initialized (run `vault init`)")]
    NotInitialized,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("crypto error")]
    Crypto,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("daemon unreachable")]
    DaemonUnreachable,
}

impl VaultError {
    /// Stable machine-readable code, mirrored on the wire and in CLI exit codes.
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::Locked => "locked",
            VaultError::AuthFailed => "auth_failed",
            VaultError::NotFound(_) => "not_found",
            VaultError::NotInitialized => "not_initialized",
            VaultError::AlreadyInitialized => "already_initialized",
            VaultError::Keychain(_) => "keychain",
            VaultError::Crypto => "crypto",
            VaultError::Io(_) => "io",
            VaultError::Protocol(_) => "protocol",
            VaultError::DaemonUnreachable => "daemon_unreachable",
        }
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;
