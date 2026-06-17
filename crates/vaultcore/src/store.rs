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
    /// Optional expiry date (YYYY-MM-DD) for rotation reminders.
    #[serde(default)]
    pub expires: Option<String>,
}

/// A complete secret incl. its value — used for encrypted export/import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub name: String,
    pub tag: String,
    pub value: String,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub secrets: Vec<SecretMeta>,
}

pub fn is_initialized() -> bool {
    keychain::master_key_exists()
}

/// Whether a tag marks a secret as sensitive enough to require a fresh Touch ID
/// on every read, even within an unlocked session (tiered policy).
pub fn is_sensitive_tag(tag: &str) -> bool {
    let t = tag.to_lowercase();
    ["banking", "bank", "prod", "production"]
        .iter()
        .any(|k| t.contains(k))
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

/// Look up a secret's metadata without decrypting its value.
pub fn get_meta(name: &str) -> Result<Option<SecretMeta>> {
    Ok(load_index()?.secrets.into_iter().find(|m| m.name == name))
}

/// Add or update a secret. Requires the in-memory master key.
pub fn set_secret(
    key: &[u8; KEY_LEN],
    name: &str,
    tag: &str,
    value: &[u8],
    expires: Option<String>,
) -> Result<()> {
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
        meta.expires = expires;
    } else {
        index.secrets.push(SecretMeta {
            name: name.to_string(),
            tag: tag.to_string(),
            created: now.clone(),
            updated: now,
            expires,
        });
    }
    save_index(&index)
}

/// Decrypt every secret into full records (for encrypted export).
pub fn export_all(key: &[u8; KEY_LEN]) -> Result<Vec<SecretRecord>> {
    let metas = load_index()?.secrets;
    let mut records = Vec::with_capacity(metas.len());
    for m in metas {
        let value = get_secret(key, &m.name)?;
        records.push(SecretRecord {
            name: m.name,
            tag: m.tag,
            value: String::from_utf8(value)
                .map_err(|_| VaultError::Protocol("non-UTF-8 secret in export".into()))?,
            expires: m.expires,
        });
    }
    Ok(records)
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
