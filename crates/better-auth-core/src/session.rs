use chrono::Utc;
use std::sync::Arc;

use crate::adapters::DatabaseAdapter;
use crate::config::AuthConfig;
use crate::error::AuthResult;
use crate::types::{CreateSession, Session, User};

/// Session manager handles session creation, validation, and cleanup
pub struct SessionManager {
    config: Arc<AuthConfig>,
    database: Arc<dyn DatabaseAdapter>,
}

impl SessionManager {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn DatabaseAdapter>) -> Self {
        Self { config, database }
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<Session> {
        let expires_at = Utc::now() + self.config.session.expires_in;

        let create_session = CreateSession {
            user_id: user.id.clone(),
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
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        let session = self.database.get_session(token).await?;

        // Check if session exists and is not expired
        if let Some(ref session) = session {
            if session.expires_at < Utc::now() || !session.active {
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
    pub async fn list_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        let sessions = self.database.get_user_sessions(user_id).await?;
        let now = Utc::now();

        // Filter out expired sessions
        let active_sessions: Vec<Session> = sessions
            .into_iter()
            .filter(|session| session.expires_at > now && session.active)
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
            if session.token != current_token {
                self.delete_session(&session.token).await?;
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

    /// Validate session token format
    pub fn validate_token_format(&self, token: &str) -> bool {
        token.starts_with("session_") && token.len() > 40
    }

    /// Extract session token from a request.
    ///
    /// Tries Bearer token from Authorization header first, then falls back
    /// to parsing the configured cookie from the Cookie header.
    pub fn extract_session_token(&self, req: &crate::types::AuthRequest) -> Option<String> {
        // Try Bearer token first
        if let Some(auth_header) = req.headers.get("authorization")
            && let Some(token) = auth_header.strip_prefix("Bearer ")
        {
            return Some(token.to_string());
        }

        // Fall back to cookie
        if let Some(cookie_header) = req.headers.get("cookie") {
            let cookie_name = &self.config.session.cookie_name;
            for part in cookie_header.split(';') {
                let part = part.trim();
                if let Some(value) = part.strip_prefix(&format!("{}=", cookie_name))
                    && !value.is_empty()
                {
                    return Some(value.to_string());
                }
            }
        }

        None
    }
}
