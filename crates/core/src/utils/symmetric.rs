//! Better Auth's XChaCha20-Poly1305 record format and versioned key envelopes.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{AuthError, AuthResult, FieldValue, config::SecretKey};

fn raw_encrypt(secret: &str, plaintext: &str) -> AuthResult<String> {
    let cipher = XChaCha20Poly1305::new_from_slice(&Sha256::digest(secret.as_bytes()))
        .map_err(|error| AuthError::internal(format!("Initialize symmetric cipher: {error}")))?;
    let mut nonce = [0; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext.as_bytes())
        .map_err(|error| AuthError::internal(format!("Encrypt authentication data: {error}")))?;
    Ok(hex::encode([nonce.as_slice(), &ciphertext].concat()))
}

fn raw_decrypt(secret: &str, encoded: &str) -> AuthResult<String> {
    let bytes = hex::decode(encoded).map_err(|error| {
        AuthError::internal(format!("Invalid encrypted authentication data: {error}"))
    })?;
    let cipher = XChaCha20Poly1305::new_from_slice(&Sha256::digest(secret.as_bytes()))
        .map_err(|error| AuthError::internal(format!("Initialize symmetric cipher: {error}")))?;
    let (nonce, ciphertext) = bytes
        .split_first_chunk::<24>()
        .ok_or_else(|| AuthError::internal("Missing authentication data nonce"))?;
    let plaintext = cipher
        .decrypt(&XNonce::from(*nonce), ciphertext)
        .map_err(|error| AuthError::internal(format!("Decrypt authentication data: {error}")))?;
    // Upstream TextDecoder removes the UTF-8 BOM and replaces invalid sequences.
    Ok(String::from_utf8_lossy(
        plaintext
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(&plaintext),
    )
    .into_owned())
}

fn parse_envelope(data: &str) -> Option<(u128, &str)> {
    let (version, ciphertext) = data.strip_prefix("$ba$")?.split_once('$')?;
    Some((crate::config::parse_secret_version(version)?, ciphertext))
}

/// Encrypt with the current key. Versioned keys add a `$ba$<version>$` envelope.
pub fn encrypt<'a>(key: impl Into<SecretKey<'a>>, plaintext: &str) -> AuthResult<String> {
    match key.into() {
        SecretKey::Single(secret) => raw_encrypt(secret, plaintext),
        SecretKey::Versioned { keys, .. } => {
            let current = keys
                .first()
                .ok_or_else(|| AuthError::config("Missing current encryption key"))?;
            let ciphertext = raw_encrypt(&current.value, plaintext)?;
            Ok(format!("$ba${}${ciphertext}", current.version))
        }
    }
}

/// Decrypt with the envelope's retained key or the explicit legacy key.
pub fn decrypt<'a>(key: impl Into<SecretKey<'a>>, encoded: &str) -> AuthResult<String> {
    match key.into() {
        SecretKey::Single(secret) => raw_decrypt(secret, encoded),
        SecretKey::Versioned {
            keys,
            legacy_secret,
        } => {
            if let Some((version, ciphertext)) = parse_envelope(encoded) {
                let key = keys
                    .iter()
                    .find(|key| key.version == version)
                    .ok_or_else(|| {
                        AuthError::internal(format!(
                            "Secret version {version} not found in keys (key may have been retired)"
                        ))
                    })?;
                raw_decrypt(&key.value, ciphertext)
            } else if let Some(secret) = legacy_secret {
                raw_decrypt(secret, encoded)
            } else {
                Err(AuthError::internal(
                    "Cannot decrypt legacy bare-hex payload: no legacy secret available. Set BETTER_AUTH_SECRET for backwards compatibility.",
                ))
            }
        }
    }
}

/// Consume native ciphertext at the cipher's string operation without coercing adapter output.
pub fn decrypt_field<'a>(
    key: impl Into<SecretKey<'a>>,
    encoded: &FieldValue,
) -> AuthResult<String> {
    let key = key.into();
    match encoded {
        FieldValue::String(encoded) => decrypt(key, encoded),
        FieldValue::Utf16String(encoded) => {
            // Ciphertext is ASCII hex. Preserve envelope key selection before rejecting invalid code units.
            let encoded = String::from_utf16_lossy(encoded.as_utf16());
            decrypt(key, &encoded)
        }
        value => {
            let message = match &key {
                SecretKey::Single(_) => format!(
                    "hex string expected, got {}",
                    match value {
                        FieldValue::Undefined => "undefined",
                        FieldValue::Bool(_) => "boolean",
                        FieldValue::Number(_) => "number",
                        _ => "object",
                    }
                ),
                SecretKey::Versioned { .. } => match value {
                    FieldValue::Null => {
                        "Cannot read properties of null (reading 'startsWith')".into()
                    }
                    FieldValue::Undefined => {
                        "Cannot read properties of undefined (reading 'startsWith')".into()
                    }
                    _ => "data.startsWith is not a function".into(),
                },
            };
            Err(AuthError::internal(message))
        }
    }
}
