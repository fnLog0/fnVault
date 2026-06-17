//! Higher-level vault operations on top of `keychain` + `crypto`.
//!
//! Secret values are stored encrypted, one Keychain item per secret. Names and
//! metadata live in a single plaintext index item so `list` works without an
//! unlock.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, KEY_LEN};
use crate::error::{Result, VaultError};
use crate::keychain;

const INDEX_ACCOUNT: &str = "__fnvault_index__";

fn secret_account(name: &str) -> String {
    format!("secret:{name}")
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: String,
    pub tag: String,
    pub created: String,
    pub updated: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub secrets: Vec<SecretMeta>,
}

pub fn is_initialized() -> bool {
    keychain::master_key_exists()
}

/// Create the master key and an empty index. Errors if already initialized.
pub fn init() -> Result<()> {
    if is_initialized() {
        return Err(VaultError::AlreadyInitialized);
    }
    let key = crypto::generate_master_key();
    keychain::store_master_key(&key)?;
    save_index(&Index::default())?;
    Ok(())
}

pub fn load_index() -> Result<Index> {
    match keychain::get_item(INDEX_ACCOUNT)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| VaultError::Protocol(format!("corrupt index: {e}"))),
        None => Ok(Index::default()),
    }
}

pub fn save_index(index: &Index) -> Result<()> {
    let bytes = serde_json::to_vec(index)
        .map_err(|e| VaultError::Protocol(format!("index serialize: {e}")))?;
    keychain::set_item(INDEX_ACCOUNT, &bytes)
}

pub fn list() -> Result<Vec<SecretMeta>> {
    let mut secrets = load_index()?.secrets;
    secrets.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(secrets)
}

/// Add or update a secret. Requires the in-memory master key.
pub fn set_secret(key: &[u8; KEY_LEN], name: &str, tag: &str, value: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(VaultError::Protocol("secret name must not be empty".into()));
    }
    let blob = crypto::encrypt(key, value)?;
    keychain::set_item(&secret_account(name), &blob)?;

    let mut index = load_index()?;
    let now = today();
    if let Some(meta) = index.secrets.iter_mut().find(|m| m.name == name) {
        meta.tag = tag.to_string();
        meta.updated = now;
    } else {
        index.secrets.push(SecretMeta {
            name: name.to_string(),
            tag: tag.to_string(),
            created: now.clone(),
            updated: now,
        });
    }
    save_index(&index)
}

/// Decrypt and return a secret value. Requires the in-memory master key.
pub fn get_secret(key: &[u8; KEY_LEN], name: &str) -> Result<Vec<u8>> {
    let blob = keychain::get_item(&secret_account(name))?
        .ok_or_else(|| VaultError::NotFound(name.to_string()))?;
    crypto::decrypt(key, &blob)
}

pub fn delete_secret(name: &str) -> Result<()> {
    let mut index = load_index()?;
    let before = index.secrets.len();
    index.secrets.retain(|m| m.name != name);
    if index.secrets.len() == before {
        return Err(VaultError::NotFound(name.to_string()));
    }
    keychain::delete_item(&secret_account(name))?;
    save_index(&index)
}
