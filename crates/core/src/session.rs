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

impl<DB: DatabaseAdapter> Clone for SessionManager<DB> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            database: self.database.clone(),
        }
    }
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
        let mut session = self.database.get_session(token).await?;

        let should_refresh = if let Some(ref s) = session {
            let now = Utc::now();

            if s.expires_at() < now || !s.active() {
                // Session expired or inactive — best-effort cleanup. A DB
                // hiccup here shouldn't turn "your session is expired" into
                // a 500; the row will be caught by the next access or the
                // periodic `cleanup_expired_sessions` sweep.
                if let Err(err) = self.database.delete_session(token).await {
                    tracing::warn!(
                        error = %err,
                        "Failed to delete expired session; will be retried later"
                    );
                }
                return Ok(None);
            }

            if !self.config.session.disable_session_refresh {
                match self.config.session.update_age {
                    Some(age) => {
                        // Only refresh if the session was last updated more than
                        // `update_age` ago.
                        let updated = s.updated_at();
                        Utc::now() - updated >= age
                    }
                    // No update_age set → refresh on every access.
                    None => true,
                }
            } else {
                false
            }
        } else {
            false
        };

        if should_refresh {
            let new_expires_at = Utc::now() + self.config.session.expires_in;
            match self
                .database
                .update_session_expiry(token, new_expires_at)
                .await
            {
                Ok(()) => {
                    // Re-read so the returned session reflects the new expiry.
                    // Both failure modes fall back to the pre-refresh session:
                    // a concurrent revoke (re-read returns None) shouldn't log
                    // the user out mid-request, and a second DB hiccup
                    // shouldn't turn a successful refresh into a 500.
                    match self.database.get_session(token).await {
                        Ok(Some(refreshed)) => session = Some(refreshed),
                        Ok(None) => {
                            tracing::warn!(
                                "Session re-read after refresh returned None (concurrent revoke?); returning pre-refresh value"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "Session re-read after refresh failed; returning pre-refresh value"
                            );
                        }
                    }
                }
                Err(err) => {
                    // Transient write failure (connection reset, contention,
                    // etc.) must not fail the whole request. Keep the
                    // pre-refresh session — auth still works, the refresh
                    // window will be retried on the next call.
                    tracing::warn!(
                        error = %err,
                        "Failed to refresh session expiry; returning pre-refresh session"
                    );
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

    /// Check whether a session is "fresh" (created recently enough for
    /// sensitive operations like password change or account deletion).
    ///
    /// Returns `true` when `fresh_age` is set and
    /// `session.created_at() + fresh_age > now`.
    /// If `fresh_age` is `None`, the session is never considered fresh.
    pub fn is_session_fresh(&self, session: &impl AuthSession) -> bool {
        match self.config.session.fresh_age {
            Some(fresh_age) => session.created_at() + fresh_age > Utc::now(),
            None => false,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
    use crate::config::SessionConfig;
    use crate::types::{CreateUser, User};
    use chrono::Duration;

    fn test_config(session: SessionConfig) -> Arc<AuthConfig> {
        Arc::new(AuthConfig {
            session,
            ..AuthConfig::default()
        })
    }

    async fn setup() -> (Arc<MemoryDatabaseAdapter>, User) {
        let db = Arc::new(MemoryDatabaseAdapter::new());
        let user = db
            .create_user(CreateUser {
                email: Some("test@example.com".into()),
                name: Some("Test User".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        (db, user)
    }

    #[tokio::test]
    async fn refresh_updates_returned_session_expires_at() {
        let (db, user) = setup().await;
        let config = test_config(SessionConfig {
            expires_in: Duration::hours(1),
            update_age: None,
            ..SessionConfig::default()
        });
        let mgr = SessionManager::new(config, db.clone());

        let initial = mgr.create_session(&user, None, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let refreshed = mgr.get_session(initial.token()).await.unwrap().unwrap();
        assert!(refreshed.expires_at() > initial.expires_at());
    }

    #[tokio::test]
    async fn refresh_is_throttled_by_update_age() {
        let (db, user) = setup().await;
        let config = test_config(SessionConfig {
            expires_in: Duration::hours(1),
            update_age: Some(Duration::hours(1)),
            ..SessionConfig::default()
        });
        let mgr = SessionManager::new(config, db.clone());

        let initial = mgr.create_session(&user, None, None).await.unwrap();
        let observed = mgr.get_session(initial.token()).await.unwrap().unwrap();
        assert_eq!(observed.expires_at(), initial.expires_at());
    }

    #[tokio::test]
    async fn refresh_skipped_when_disabled() {
        let (db, user) = setup().await;
        let config = test_config(SessionConfig {
            expires_in: Duration::hours(1),
            update_age: None,
            disable_session_refresh: true,
            ..SessionConfig::default()
        });
        let mgr = SessionManager::new(config, db.clone());

        let initial = mgr.create_session(&user, None, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let observed = mgr.get_session(initial.token()).await.unwrap().unwrap();
        assert_eq!(observed.expires_at(), initial.expires_at());
    }

    #[tokio::test]
    async fn expired_session_is_removed_and_returns_none() {
        let (db, user) = setup().await;
        let config = test_config(SessionConfig::default());
        let mgr = SessionManager::new(config, db.clone());

        let created = mgr.create_session(&user, None, None).await.unwrap();
        db.update_session_expiry(created.token(), Utc::now() - Duration::seconds(1))
            .await
            .unwrap();

        let result = mgr.get_session(created.token()).await.unwrap();
        assert!(result.is_none());
        let still_there = db.get_session(created.token()).await.unwrap();
        assert!(still_there.is_none());
    }
}
