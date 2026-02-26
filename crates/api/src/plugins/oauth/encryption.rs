//! AES-256-GCM encryption utilities for OAuth tokens.
//!
//! When `AccountConfig::encrypt_oauth_tokens` is `true`, access tokens,
//! refresh tokens, and ID tokens are encrypted before being persisted and
//! decrypted transparently on read.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use base64::Engine;
use sha2::{Digest, Sha256};

use better_auth_core::AuthError;

/// Derive a 256-bit key from the auth secret using SHA-256.
fn derive_key(secret: &str) -> Key<Aes256Gcm> {
    let hash = Sha256::digest(secret.as_bytes());
    *Key::<Aes256Gcm>::from_slice(&hash)
}

/// Encrypt a plaintext string using AES-256-GCM.
///
/// Returns a base64-encoded string of `nonce || ciphertext`.
pub fn encrypt_token(plaintext: &str, secret: &str) -> Result<String, AuthError> {
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| AuthError::internal(format!("Token encryption failed: {}", e)))?;

    // Prepend nonce (12 bytes) to ciphertext
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt a base64-encoded `nonce || ciphertext` string using AES-256-GCM.
pub fn decrypt_token(encrypted: &str, secret: &str) -> Result<String, AuthError> {
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new(&key);

    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| AuthError::internal(format!("Token decryption base64 error: {}", e)))?;

    if combined.len() < 12 {
        return Err(AuthError::internal(
            "Encrypted token too short (missing nonce)",
        ));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AuthError::internal(format!("Token decryption failed: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| AuthError::internal(format!("Decrypted token is not valid UTF-8: {}", e)))
}

/// Conditionally encrypt a token value. Returns the original value when
/// encryption is disabled, or the encrypted value when enabled.
pub fn maybe_encrypt(
    value: Option<String>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) => Ok(Some(encrypt_token(&v, secret)?)),
        (v, _) => Ok(v),
    }
}

/// Conditionally decrypt a token value. Returns the original value when
/// encryption is disabled, or the decrypted value when enabled.
pub fn maybe_decrypt(
    value: Option<&str>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) => Ok(Some(decrypt_token(v, secret)?)),
        (Some(v), false) => Ok(Some(v.to_string())),
        (None, _) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = "a]vt!MFX8H-e!4igKa5)Tu.{ec:2$z%n";
        let plaintext = "ya29.a0AfH6SMBx-some-access-token";

        let encrypted = encrypt_token(plaintext, secret).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_token(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_maybe_encrypt_none() {
        let result = maybe_encrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_maybe_encrypt_disabled() {
        let token = "plain-token".to_string();
        let result = maybe_encrypt(Some(token.clone()), false, "secret").unwrap();
        assert_eq!(result, Some(token));
    }

    #[test]
    fn test_maybe_decrypt_none() {
        let result = maybe_decrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
        assert!(result.is_none());
    }
}
