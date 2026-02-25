use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;

use crate::adapters::DatabaseAdapter;
use crate::config::AuthConfig;
use crate::entity::{AuthSession, AuthUser};
use crate::error::AuthResult;
use crate::types::CreateSession;

type HmacSha256 = Hmac<Sha256>;

/// Session manager handles session creation, validation, and cleanup
pub struct SessionManager<DB: DatabaseAdapter> {
    config: Arc<AuthConfig>,
    database: Arc<DB>,
}

impl<DB: DatabaseAdapter> SessionManager<DB> {
    pub fn new(config: Arc<AuthConfig>, database: Arc<DB>) -> Self {
        Self { config, database }
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<DB::Session> {
        let expires_at = Utc::now() + self.config.session.expires_in;

        let create_session = CreateSession {
            user_id: user.id().to_string(),
            expires_at,
            ip_address,
            user_agent,
            impersonated_by: None,
            active_organization_id: None,
        };

        let session = self.database.create_session(create_session).await?;
        Ok(session)
    }

    /// Get session by token
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<DB::Session>> {
        let session = self.database.get_session(token).await?;

        // Check if session exists and is not expired
        if let Some(ref session) = session {
            if session.expires_at() < Utc::now() || !session.active() {
                // Session expired or inactive - delete it
                self.database.delete_session(token).await?;
                return Ok(None);
            }

            // Update session if configured to do so
            if self.config.session.update_age {
                let new_expires_at = Utc::now() + self.config.session.expires_in;
                let _ = self
                    .database
                    .update_session_expiry(token, new_expires_at)
                    .await;
            }
        }

        Ok(session)
    }

    /// Delete a session
    pub async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.database.delete_session(token).await?;
        Ok(())
    }

    /// Delete all sessions for a user
    pub async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.database.delete_user_sessions(user_id).await?;
        Ok(())
    }

    /// Get all active sessions for a user
    pub async fn list_user_sessions(&self, user_id: &str) -> AuthResult<Vec<DB::Session>> {
        let sessions = self.database.get_user_sessions(user_id).await?;
        let now = Utc::now();

        // Filter out expired sessions
        let active_sessions: Vec<DB::Session> = sessions
            .into_iter()
            .filter(|session| session.expires_at() > now && session.active())
            .collect();

        Ok(active_sessions)
    }

    /// Revoke a specific session by token
    pub async fn revoke_session(&self, token: &str) -> AuthResult<bool> {
        // Check if session exists before trying to delete
        let session_exists = self.get_session(token).await?.is_some();

        if session_exists {
            self.delete_session(token).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all_user_sessions(&self, user_id: &str) -> AuthResult<usize> {
        // Get count of sessions before deletion for return value
        let sessions = self.list_user_sessions(user_id).await?;
        let count = sessions.len();

        self.delete_user_sessions(user_id).await?;
        Ok(count)
    }

    /// Revoke all sessions for a user except the current one
    pub async fn revoke_other_user_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> AuthResult<usize> {
        let sessions = self.list_user_sessions(user_id).await?;
        let mut count = 0;

        for session in sessions {
            if session.token() != current_token {
                self.delete_session(session.token()).await?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> AuthResult<usize> {
        let count = self.database.delete_expired_sessions().await?;
        Ok(count)
    }

    /// Validate session token format (64-character hex string)
    pub fn validate_token_format(&self, token: &str) -> bool {
        token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Sign a session token with HMAC-SHA256 using the config secret.
    ///
    /// Returns the signed value in the format `token.base64url_signature`.
    pub fn sign_token(&self, token: &str) -> String {
        let signature = compute_hmac_signature(token, &self.config.secret);
        format!("{}.{}", token, signature)
    }

    /// Verify an HMAC-signed cookie value and extract the raw token.
    ///
    /// Expects the format `token.base64url_signature`. Returns `Some(token)` if
    /// the signature is valid, `None` otherwise.
    pub fn verify_signed_token(&self, signed_value: &str) -> Option<String> {
        verify_and_extract_token(signed_value, &self.config.secret)
    }

    /// Extract session token from a request.
    ///
    /// Tries Bearer token from Authorization header first (no HMAC verification),
    /// then falls back to parsing the configured cookie from the Cookie header
    /// (with HMAC signature verification).
    pub fn extract_session_token(&self, req: &crate::types::AuthRequest) -> Option<String> {
        // Try Bearer token first (no HMAC signing for API clients)
        if let Some(auth_header) = req.headers.get("authorization")
            && let Some(token) = auth_header.strip_prefix("Bearer ")
        {
            return Some(token.to_string());
        }

        // Fall back to cookie (with HMAC verification)
        if let Some(cookie_header) = req.headers.get("cookie") {
            let cookie_name = &self.config.session.cookie_name;
            for part in cookie_header.split(';') {
                let part = part.trim();
                if let Some(value) = part.strip_prefix(&format!("{}=", cookie_name))
                    && !value.is_empty()
                {
                    // Verify HMAC signature and extract raw token
                    return self.verify_signed_token(value);
                }
            }
        }

        None
    }
}

/// Compute HMAC-SHA256 signature for a token, returning base64url-encoded signature.
fn compute_hmac_signature(token: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize();
    URL_SAFE_NO_PAD.encode(result.into_bytes())
}

/// Verify an HMAC-signed value and extract the raw token.
///
/// This is a standalone function that can be used without a SessionManager.
fn verify_and_extract_token(signed_value: &str, secret: &str) -> Option<String> {
    let (token, signature) = signed_value.rsplit_once('.')?;
    if token.is_empty() || signature.is_empty() {
        return None;
    }

    let expected_signature = compute_hmac_signature(token, secret);

    // Constant-time comparison to prevent timing attacks
    if signature.len() != expected_signature.len() {
        return None;
    }
    let matches = signature
        .as_bytes()
        .iter()
        .zip(expected_signature.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if matches != 0 {
        return None;
    }

    Some(token.to_string())
}

/// Sign a session token with HMAC-SHA256 (standalone function for use outside SessionManager).
pub fn sign_session_token(token: &str, secret: &str) -> String {
    let signature = compute_hmac_signature(token, secret);
    format!("{}.{}", token, signature)
}
