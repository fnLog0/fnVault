//! Linux backend: secret storage via the Secret Service (`keyring` crate, talks
//! to gnome-keyring / KWallet over D-Bus) and an unlock gate backed by a vault
//! passphrase (Argon2-verified).
//!
//! Rationale: Linux fingerprint support (fprintd) is fragmented, so the
//! universally-available gate is a passphrase. The passphrase is set on first
//! unlock and verified thereafter — "unlock once per session", same as Touch ID
//! on macOS. (fprintd biometrics + sleep/screen-lock auto-lock are a later pass.)

use keyring::{Entry, Error as KrError};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::KEY_LEN;
use crate::error::{Result, VaultError};

const MASTER_SERVICE: &str = "fnvault.masterkey";
const MASTER_ACCOUNT: &str = "master";
const DATA_SERVICE: &str = "fnvault.data";
const AUTH_SERVICE: &str = "fnvault.auth";
const AUTH_ACCOUNT: &str = "verifier";
const SALT_LEN: usize = 16;

fn entry(service: &str, account: &str) -> Result<Entry> {
    Entry::new(service, account).map_err(|e| VaultError::Keychain(format!("keyring: {e}")))
}

fn read(service: &str, account: &str) -> Result<Option<Vec<u8>>> {
    match entry(service, account)?.get_secret() {
        Ok(v) => Ok(Some(v)),
        Err(KrError::NoEntry) => Ok(None),
        Err(e) => Err(VaultError::Keychain(format!("keyring read: {e}"))),
    }
}

fn write(service: &str, account: &str, data: &[u8]) -> Result<()> {
    entry(service, account)?
        .set_secret(data)
        .map_err(|e| VaultError::Keychain(format!("keyring write: {e}")))
}

fn remove(service: &str, account: &str) -> Result<()> {
    match entry(service, account)?.delete_credential() {
        Ok(()) | Err(KrError::NoEntry) => Ok(()),
        Err(e) => Err(VaultError::Keychain(format!("keyring delete: {e}"))),
    }
}

// ---- storage ------------------------------------------------------------

pub fn master_key_exists() -> bool {
    matches!(read(MASTER_SERVICE, MASTER_ACCOUNT), Ok(Some(_)))
}

pub fn store_master_key(key: &[u8; KEY_LEN]) -> Result<()> {
    write(MASTER_SERVICE, MASTER_ACCOUNT, key)
}

pub fn read_master_key() -> Result<[u8; KEY_LEN]> {
    let v = read(MASTER_SERVICE, MASTER_ACCOUNT)?.ok_or(VaultError::NotInitialized)?;
    if v.len() != KEY_LEN {
        return Err(VaultError::Keychain("master key has wrong length".into()));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&v);
    Ok(k)
}

pub fn delete_master_key() -> Result<()> {
    remove(MASTER_SERVICE, MASTER_ACCOUNT)
}

pub fn set_item(account: &str, data: &[u8]) -> Result<()> {
    write(DATA_SERVICE, account, data)
}

pub fn get_item(account: &str) -> Result<Option<Vec<u8>>> {
    read(DATA_SERVICE, account)
}

pub fn delete_item(account: &str) -> Result<()> {
    remove(DATA_SERVICE, account)
}

// ---- passphrase auth ----------------------------------------------------

/// Prompt for a passphrase from the (headless) daemon via systemd-ask-password.
fn ask(prompt: &str) -> Result<String> {
    let out = std::process::Command::new("systemd-ask-password")
        .arg(prompt)
        .output()
        .map_err(|_| {
            VaultError::Keychain(
                "no passphrase prompt available (need systemd-ask-password)".into(),
            )
        })?;
    if !out.status.success() {
        return Err(VaultError::AuthFailed);
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .to_string())
}

fn derive(pass: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut h = [0u8; KEY_LEN];
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut h)
        .map_err(|_| VaultError::Crypto)?;
    Ok(h)
}

/// Gate the session on the vault passphrase. Sets it on first unlock, verifies
/// it thereafter (Argon2 over a stored salt).
pub fn touchid_authenticate(reason: &str) -> Result<()> {
    match read(AUTH_SERVICE, AUTH_ACCOUNT)? {
        None => {
            let p1 = ask("Set a passphrase for fnVault")?;
            if p1.is_empty() {
                return Err(VaultError::Keychain("passphrase must not be empty".into()));
            }
            let p2 = ask("Confirm fnVault passphrase")?;
            if p1 != p2 {
                return Err(VaultError::Keychain("passphrases do not match".into()));
            }
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let h = derive(&p1, &salt)?;
            let mut blob = Vec::with_capacity(SALT_LEN + KEY_LEN);
            blob.extend_from_slice(&salt);
            blob.extend_from_slice(&h);
            write(AUTH_SERVICE, AUTH_ACCOUNT, &blob)
        }
        Some(blob) => {
            if blob.len() != SALT_LEN + KEY_LEN {
                return Err(VaultError::Keychain("corrupt auth verifier".into()));
            }
            let (salt, stored) = blob.split_at(SALT_LEN);
            let h = derive(&ask(reason)?, salt)?;
            if h.as_slice() == stored {
                Ok(())
            } else {
                Err(VaultError::AuthFailed)
            }
        }
    }
}

pub fn touch_id_unlock(reason: &str) -> Result<[u8; KEY_LEN]> {
    touchid_authenticate(reason)?;
    read_master_key()
}

pub fn run_lock_observer(_cb: extern "C" fn()) {
    // TODO(step 3): subscribe to logind PrepareForSleep + screensaver lock over
    // D-Bus. For now the idle-timeout backstop handles relocking; park so the
    // daemon's observer thread stays idle rather than spinning.
    loop {
        std::thread::park();
    }
}
