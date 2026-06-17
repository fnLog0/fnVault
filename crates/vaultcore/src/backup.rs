//! Passphrase-sealed export/import blobs for backup & machine migration.
//!
//! Format: `b"FNVB" || version(1) || salt(16) || nonce(24) || ciphertext+tag`.
//! Key = Argon2id(passphrase, salt). Body = XChaCha20-Poly1305.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{Result, VaultError};

const MAGIC: &[u8; 4] = b"FNVB";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN; // magic + version + salt

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

/// Encrypt `plaintext` under a passphrase. Returns the full self-describing blob.
pub fn seal(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase.as_bytes(), &salt)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VaultError::Crypto)?;

    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`]. Wrong passphrase => `Crypto` error.
pub fn open(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + NONCE_LEN {
        return Err(VaultError::Protocol("backup file too short".into()));
    }
    if &data[0..4] != MAGIC {
        return Err(VaultError::Protocol("not an fnVault backup file".into()));
    }
    if data[4] != VERSION {
        return Err(VaultError::Protocol(format!(
            "unsupported backup version {}",
            data[4]
        )));
    }
    let salt = &data[5..5 + SALT_LEN];
    let nonce_bytes = &data[HEADER_LEN..HEADER_LEN + NONCE_LEN];
    let ct = &data[HEADER_LEN + NONCE_LEN..];

    let key = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| VaultError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let blob = seal("correct horse", b"{\"secrets\":[]}").unwrap();
        assert_eq!(&blob[0..4], MAGIC);
        assert_eq!(open("correct horse", &blob).unwrap(), b"{\"secrets\":[]}");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal("right", b"data").unwrap();
        assert!(open("wrong", &blob).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(open("x", b"not a backup").is_err());
    }
}
