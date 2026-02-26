//! Shared password utilities for hashing, verification, validation and
//! session-cookie construction.
//!
//! Lives in `better-auth-core` so that any crate in the workspace (plugins,
//! integrations, etc.) can reuse these primitives without duplicating logic.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher as Argon2PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use serde::Serialize;

use crate::adapters::DatabaseAdapter;
use crate::config::SameSite;
use crate::error::{AuthError, AuthResult};
use crate::plugin::AuthContext;
use crate::types::UpdateUser;

// ---------------------------------------------------------------------------
// PasswordHasher trait
// ---------------------------------------------------------------------------

/// Custom password hasher trait for pluggable password hashing strategies.
///
/// When provided in plugin configs, this overrides the default Argon2-based
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
/// Argon2 algorithm.
pub async fn hash_password(
    hasher: Option<&Arc<dyn PasswordHasher>>,
    password: &str,
) -> AuthResult<String> {
    if let Some(hasher) = hasher {
        return hasher.hash(password).await;
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;

    Ok(password_hash.to_string())
}

/// Verify `password` against `hash` using the custom `hasher` (if provided) or
/// the default Argon2 algorithm.  Returns `Ok(())` on match, or
/// `Err(AuthError::InvalidCredentials)` on mismatch.
pub async fn verify_password(
    hasher: Option<&Arc<dyn PasswordHasher>>,
    password: &str,
    hash: &str,
) -> AuthResult<()> {
    if let Some(hasher) = hasher {
        return hasher.verify(hash, password).await.and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(AuthError::InvalidCredentials)
            }
        });
    }

    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;

    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::InvalidCredentials)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Password validation
// ---------------------------------------------------------------------------

/// Validate `password` against both the plugin-level length limits and the
/// global `PasswordConfig` strength rules.  Performs min-length, max-length,
/// uppercase, lowercase, digit and special-character checks.
pub fn validate_password<DB: DatabaseAdapter>(
    password: &str,
    min_length: usize,
    max_length: usize,
    ctx: &AuthContext<DB>,
) -> AuthResult<()> {
    let config = &ctx.config.password;

    if password.len() < min_length {
        return Err(AuthError::bad_request(format!(
            "Password must be at least {} characters long",
            config.min_length
        )));
    }

    if password.len() > max_length {
        return Err(AuthError::bad_request(format!(
            "Password must be at most {} characters long",
            max_length
        )));
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
// Session cookie construction
// ---------------------------------------------------------------------------

/// Build a `Set-Cookie` header value for the given session `token`, respecting
/// the `SessionConfig` settings from `ctx`.
pub fn create_session_cookie<DB: DatabaseAdapter>(token: &str, ctx: &AuthContext<DB>) -> String {
    let session_config = &ctx.config.session;
    let secure = if session_config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    let http_only = if session_config.cookie_http_only {
        "; HttpOnly"
    } else {
        ""
    };
    let same_site = match session_config.cookie_same_site {
        SameSite::Strict => "; SameSite=Strict",
        SameSite::Lax => "; SameSite=Lax",
        SameSite::None => "; SameSite=None",
    };

    let expires = chrono::Utc::now() + session_config.expires_in;
    let expires_str = expires.format("%a, %d %b %Y %H:%M:%S GMT");

    format!(
        "{}={}; Path=/; Expires={}{}{}{}",
        session_config.cookie_name, token, expires_str, secure, http_only, same_site
    )
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
pub fn update_user_metadata(metadata: serde_json::Value) -> UpdateUser {
    UpdateUser {
        metadata: Some(metadata),
        ..Default::default()
    }
}
