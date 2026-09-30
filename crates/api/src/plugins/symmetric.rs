use better_auth_core::{AuthError, AuthResult};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use sha2::{Digest, Sha256};

// Better Auth encodes nonce || ciphertext || tag as hex with SHA-256(secret).
pub(crate) fn encrypt(secret: &str, plaintext: &str) -> AuthResult<String> {
    let cipher = XChaCha20Poly1305::new_from_slice(&Sha256::digest(secret.as_bytes()))
        .map_err(|error| AuthError::internal(format!("Initialize symmetric cipher: {error}")))?;
    let mut nonce = [0; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext.as_bytes())
        .map_err(|error| AuthError::internal(format!("Encrypt authentication data: {error}")))?;
    Ok(nonce
        .iter()
        .chain(&ciphertext)
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn decrypt(secret: &str, encoded: &str) -> AuthResult<String> {
    if !encoded.len().is_multiple_of(2) {
        return Err(AuthError::bad_request(
            "Invalid encrypted authentication data",
        ));
    }
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|error| {
                AuthError::bad_request(format!("Invalid encrypted authentication data: {error}"))
            })?;
            u8::from_str_radix(pair, 16).map_err(|error| {
                AuthError::bad_request(format!("Invalid encrypted authentication data: {error}"))
            })
        })
        .collect::<AuthResult<_>>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&Sha256::digest(secret.as_bytes()))
        .map_err(|error| AuthError::internal(format!("Initialize symmetric cipher: {error}")))?;
    let (nonce, ciphertext) = bytes
        .split_first_chunk::<24>()
        .ok_or_else(|| AuthError::bad_request("Missing authentication data nonce"))?;
    let plaintext = cipher
        .decrypt(&XNonce::from(*nonce), ciphertext)
        .map_err(|error| AuthError::bad_request(format!("Decrypt authentication data: {error}")))?;
    String::from_utf8(plaintext)
        .map_err(|error| AuthError::bad_request(format!("Decode authentication data: {error}")))
}
