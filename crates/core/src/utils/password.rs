//! Shared password hashing and verification utilities.
//!
//! These functions centralise the Argon2-based password operations that were
//! previously duplicated across `email_password`, `password_management`,
//! `admin`, and `two_factor` plugins.

use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};

use crate::error::{AuthError, AuthResult};

/// Hash a plaintext password with Argon2id using a random salt.
pub fn hash_password(password: &str) -> AuthResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;

    Ok(password_hash.to_string())
}

/// Verify a plaintext password against an Argon2 hash string.
pub fn verify_password(password: &str, hash: &str) -> AuthResult<()> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::InvalidCredentials)?;

    Ok(())
}
