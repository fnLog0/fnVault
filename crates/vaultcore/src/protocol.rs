//! Newline-delimited JSON wire protocol between `vault` and `vaultd`.

use serde::{Deserialize, Serialize};

use crate::store::{SecretMeta, SecretRecord};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Init,
    Status,
    List,
    Unlock,
    Lock,
    Get {
        name: String,
    },
    Set {
        name: String,
        tag: String,
        value: String,
        #[serde(default)]
        expires: Option<String>,
    },
    Delete {
        name: String,
    },
    /// Decrypt and return every secret (for encrypted export). Requires unlock.
    ExportAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub initialized: bool,
    pub unlocked: bool,
    pub idle_timeout_secs: u64,
    /// Seconds since last activity (None if locked).
    pub since_activity_secs: Option<u64>,
    /// Seconds until idle relock (None if locked or timeout disabled).
    pub idle_remaining_secs: Option<u64>,
    /// Seconds until the absolute session cap relocks (None if locked/disabled).
    #[serde(default)]
    pub session_remaining_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Secret { value: String },
    List { secrets: Vec<SecretMeta> },
    Export { records: Vec<SecretRecord> },
    Status(StatusInfo),
    Error { code: String, message: String },
}

impl Request {
    pub fn encode(&self) -> String {
        let mut s = serde_json::to_string(self).expect("request serialization");
        s.push('\n');
        s
    }
}

impl Response {
    pub fn encode(&self) -> String {
        let mut s = serde_json::to_string(self).expect("response serialization");
        s.push('\n');
        s
    }

    pub fn error(err: &crate::error::VaultError) -> Self {
        Response::Error {
            code: err.code().to_string(),
            message: err.to_string(),
        }
    }
}
