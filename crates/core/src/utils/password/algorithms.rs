use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher as _, PasswordVerifier as _};
use async_trait::async_trait;
use rand::RngCore;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

use super::PasswordHasher;
use crate::{AuthError, AuthResult};

/// Better Auth's default NFKC-normalized scrypt password format.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScryptPasswordHasher;

fn derive_key(password: &str, salt: &str) -> AuthResult<String> {
    let password: String = password.nfkc().collect();
    let params = scrypt::Params::new(14, 16, 1)
        .map_err(|error| AuthError::PasswordHash(error.to_string()))?;
    let mut key = [0; 64];
    // Upstream uses the hexadecimal salt text as input, not its decoded bytes.
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut key)
        .map_err(|error| AuthError::PasswordHash(error.to_string()))?;
    Ok(hex::encode(key))
}

#[async_trait]
impl PasswordHasher for ScryptPasswordHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut salt = [0; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let salt = hex::encode(salt);
            Ok(format!("{salt}:{}", derive_key(&password, &salt)?))
        })
        .await
        .map_err(|error| {
            AuthError::PasswordHash(format!("Password hashing task failed: {error}"))
        })?
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        let mut parts = hash.split(':');
        let (Some(salt), Some(key)) = (parts.next(), parts.next()) else {
            return Err(AuthError::PasswordHash("Invalid password hash".into()));
        };
        if salt.is_empty() || key.is_empty() {
            return Err(AuthError::PasswordHash("Invalid password hash".into()));
        }
        let (salt, key, password) = (salt.to_owned(), key.to_owned(), password.to_owned());
        tokio::task::spawn_blocking(move || {
            let computed = derive_key(&password, &salt)?;
            Ok(bool::from(computed.as_bytes().ct_eq(key.as_bytes())))
        })
        .await
        .map_err(|error| {
            AuthError::PasswordHash(format!("Password verification task failed: {error}"))
        })?
    }
}

/// Explicit compatibility with password hashes created by older better-auth-rs releases.
///
/// This hasher uses Argon2 PHC strings. It does not accept scrypt hashes or migrate records.
#[derive(Debug, Clone, Copy, Default)]
pub struct Argon2PasswordHasher;

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        let password: String = password.nfkc().collect();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|error| {
                    AuthError::PasswordHash(format!("Failed to hash password: {error}"))
                })
        })
        .await
        .map_err(|error| {
            AuthError::PasswordHash(format!("Password hashing task failed: {error}"))
        })?
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        let hash = hash.to_owned();
        let password: String = password.nfkc().collect();
        tokio::task::spawn_blocking(move || {
            let hash = PasswordHash::new(&hash).map_err(|error| {
                AuthError::PasswordHash(format!("Invalid password hash: {error}"))
            })?;
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok())
        })
        .await
        .map_err(|error| {
            AuthError::PasswordHash(format!("Password verification task failed: {error}"))
        })?
    }
}
