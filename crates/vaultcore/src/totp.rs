//! RFC 6238 TOTP (time-based one-time passwords), HMAC-SHA1.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Result, VaultError};

type HmacSha1 = Hmac<Sha1>;

/// Decode a base32 (RFC 4648) TOTP secret, tolerating spaces, lowercase, and
/// missing padding (the common `otpauth://` form).
fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
    let upper = cleaned.trim_end_matches('=').to_uppercase();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &upper)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| VaultError::Protocol("invalid base32 TOTP secret".into()))
}

/// Compute the code for an explicit unix timestamp (testable).
pub fn totp_at(secret: &str, unix_secs: u64, period: u64, digits: u32) -> Result<String> {
    let key = decode_secret(secret)?;
    let counter = unix_secs / period;
    let msg = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| VaultError::Crypto)?;
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let modulo = 10u32.pow(digits);
    Ok(format!("{:0width$}", bin % modulo, width = digits as usize))
}

/// Current 6-digit, 30-second code.
pub fn totp_now(secret: &str) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| VaultError::Crypto)?
        .as_secs();
    totp_at(secret, now, 30, 6)
}

/// Seconds left in the current 30-second window.
pub fn seconds_remaining() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    30 - (now % 30)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vector: ASCII secret "12345678901234567890" in base32.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        assert_eq!(totp_at(SECRET, 59, 30, 8).unwrap(), "94287082");
        assert_eq!(totp_at(SECRET, 1111111109, 30, 8).unwrap(), "07081804");
        assert_eq!(totp_at(SECRET, 59, 30, 6).unwrap(), "287082");
    }

    #[test]
    fn tolerates_lowercase_and_spaces() {
        let pretty = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(totp_at(pretty, 59, 30, 6).unwrap(), "287082");
    }

    #[test]
    fn rejects_bad_secret() {
        assert!(totp_at("!!!!", 59, 30, 6).is_err());
    }
}
