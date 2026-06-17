//! XChaCha20-Poly1305 AEAD over the master key.
//!
//! Wire/at-rest format for an encrypted secret: `nonce(24) || ciphertext+tag`.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;

use crate::error::{Result, VaultError};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// Generate a fresh random 32-byte master key.
pub fn generate_master_key() -> [u8; KEY_LEN] {
    let k = XChaCha20Poly1305::generate_key(&mut OsRng);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&k);
    out
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VaultError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(VaultError::Crypto);
    }
    let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| VaultError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_master_key();
        let msg = b"super-secret-token-1234";
        let ct = encrypt(&key, msg).unwrap();
        assert_ne!(&ct[NONCE_LEN..], msg);
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn empty_value_round_trip() {
        let key = generate_master_key();
        let ct = encrypt(&key, b"").unwrap();
        assert_eq!(decrypt(&key, &ct).unwrap(), b"");
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = generate_master_key();
        let k2 = generate_master_key();
        let ct = encrypt(&k1, b"hello").unwrap();
        assert!(decrypt(&k2, &ct).is_err());
    }

    #[test]
    fn tamper_fails() {
        let key = generate_master_key();
        let mut ct = encrypt(&key, b"hello").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn truncated_fails() {
        let key = generate_master_key();
        assert!(decrypt(&key, &[0u8; 5]).is_err());
    }
}
