use chrono::Utc;
use std::sync::Arc;

use crate::adapters::DatabaseAdapter;
use crate::config::AuthConfig;
use crate::entity::{AuthSession, AuthUser};
use crate::error::AuthResult;
use crate::types::CreateSession;

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
            if !self.config.session.disable_session_refresh {
                let should_refresh = match self.config.session.update_age {
                    Some(age) => {
                        // Only refresh if the session was last updated more than
                        // `update_age` ago.
                        let updated = session.updated_at();
                        Utc::now() - updated >= age
                    }
                    // No update_age set → refresh on every access.
                    None => true,
                };

                if should_refresh {
                    let new_expires_at = Utc::now() + self.config.session.expires_in;
                    let _ = self
                        .database
                        .update_session_expiry(token, new_expires_at)
                        .await;
                }
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

        // Fall back to cookie (using the `cookie` crate for correct parsing)
        if let Some(cookie_header) = req.headers.get("cookie") {
            let cookie_name = &self.config.session.cookie_name;
            for c in cookie::Cookie::split_parse(cookie_header).flatten() {
                if c.name() == cookie_name && !c.value().is_empty() {
                    return Some(c.value().to_string());
                }
            }
        }

        None
    }
}
