//! Shared password utilities for hashing, verification, validation and
//! session-cookie construction.
//!
//! Lives in `better-auth-core` so that any crate in the workspace (plugins,
//! integrations, etc.) can reuse these primitives without duplicating logic.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;

mod algorithms;
#[cfg(test)]
mod tests;
pub use algorithms::{Argon2PasswordHasher, ScryptPasswordHasher};

use crate::error::{AuthError, AuthResult};
use crate::plugin::AuthContext;
use crate::schema::AuthSchema;
use crate::types::UpdateUser;

// ---------------------------------------------------------------------------
// PasswordHasher trait
// ---------------------------------------------------------------------------

/// Custom password hasher trait for pluggable password hashing strategies.
///
/// When provided in plugin configs, this overrides the default scrypt-based
/// password hashing.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password and return the hash string.
    async fn hash(&self, password: &str) -> AuthResult<String>;
    /// Verify a password against a hash string. Returns `true` if the password matches.
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool>;
}

// ---------------------------------------------------------------------------
// hash / verify helpers
// ---------------------------------------------------------------------------

/// Hash `password` using the custom `hasher` (if provided) or the default
/// Better Auth scrypt algorithm.
pub async fn hash_password(
    hasher: Option<&Arc<dyn PasswordHasher>>,
    password: &str,
) -> AuthResult<String> {
    if let Some(hasher) = hasher {
        return hasher.hash(password).await;
    }

    ScryptPasswordHasher.hash(password).await
}

/// Verify `password` against `hash` using the custom `hasher` (if provided) or
/// the default scrypt algorithm. Returns `Ok(())` on match, or
/// `Err(AuthError::InvalidCredentials)` on mismatch.
pub async fn verify_password(
    hasher: Option<&Arc<dyn PasswordHasher>>,
    password: &str,
    hash: &str,
) -> AuthResult<()> {
    let valid = match hasher {
        Some(hasher) => hasher.verify(hash, password).await?,
        None => ScryptPasswordHasher.verify(hash, password).await?,
    };
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

// ---------------------------------------------------------------------------
// Password validation
// ---------------------------------------------------------------------------

/// Validate `password` against both the plugin-level length limits and the
/// global `PasswordConfig` strength rules.  Performs min-length, max-length,
/// uppercase, lowercase, digit and special-character checks.
pub fn validate_password(
    password: &str,
    min_length: usize,
    max_length: usize,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<()> {
    let config = &ctx.config.password;

    let length = password.encode_utf16().count();
    if length < min_length {
        return Err(AuthError::bad_request("Password too short"));
    }

    if length > max_length {
        return Err(AuthError::bad_request("Password too long"));
    }

    if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthError::bad_request(
            "Password must contain at least one uppercase letter",
        ));
    }

    if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err(AuthError::bad_request(
            "Password must contain at least one lowercase letter",
        ));
    }

    if config.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::bad_request(
            "Password must contain at least one number",
        ));
    }

    if config.require_special
        && !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
    {
        return Err(AuthError::bad_request(
            "Password must contain at least one special character",
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Serialisation helper
// ---------------------------------------------------------------------------

/// Serialize any `Serialize`-able value to `serde_json::Value`, converting
/// errors to `AuthError::internal`.
pub fn serialize_to_value(value: &impl Serialize) -> AuthResult<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|e| AuthError::internal(format!("Failed to serialize value: {}", e)))
}

// ---------------------------------------------------------------------------
// UpdateUser helper
// ---------------------------------------------------------------------------

/// Build an `UpdateUser` that only changes the `metadata` field.
pub fn update_user_metadata(metadata: crate::FieldValue) -> UpdateUser {
    UpdateUser {
        metadata: Some(metadata),
        ..Default::default()
    }
}

/// Shared password behavior selected by the installed password plugins.
#[derive(Clone)]
pub struct PasswordRuntimePolicy {
    pub hasher: Option<Arc<dyn PasswordHasher>>,
    pub on_password_reset: Option<Arc<OnPasswordResetCallback>>,
    pub revoke_sessions_on_password_reset: bool,
    pub min_length: usize,
    pub max_length: usize,
}
/// The user found before the password write and the original endpoint request.
#[derive(Clone, Debug)]
pub struct PasswordResetEvent {
    pub user: crate::wire::UserView,
    pub request: Option<crate::AuthRequest>,
}

pub type OnPasswordResetCallback = dyn Fn(
        PasswordResetEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<()>> + Send>>
    + Send
    + Sync;
impl PasswordRuntimePolicy {
    /// Reject overlong credentials before performing a password hash or database lookup.
    pub fn validate_max_length(&self, password: &str) -> AuthResult<()> {
        if password.encode_utf16().count() > self.max_length {
            return Err(AuthError::bad_request("Password too long"));
        }
        Ok(())
    }

    pub fn new(config: &crate::config::PasswordConfig) -> Self {
        Self {
            hasher: None,
            on_password_reset: None,
            revoke_sessions_on_password_reset: false,
            min_length: config.min_length,
            max_length: config.max_length,
        }
    }
}
