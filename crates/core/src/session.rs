use chrono::Utc;
use std::sync::Arc;

use crate::adapters::AuthDatabase;
use crate::config::AuthConfig;
use crate::entity::{AuthSession, AuthUser};
use crate::error::AuthResult;
use crate::types::{CreateSession, Session};

/// Session manager handles session creation, validation, and cleanup
pub struct SessionManager {
    config: Arc<AuthConfig>,
    database: Arc<AuthDatabase>,
}

impl Clone for SessionManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            database: self.database.clone(),
        }
    }
}

impl SessionManager {
    pub fn new(config: Arc<AuthConfig>, database: Arc<AuthDatabase>) -> Self {
        Self { config, database }
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<Session> {
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
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        let session: Option<Session> = self.database.get_session(token).await?;

        // Check if session exists and is not expired
        if let Some(ref session) = session {
            let now = Utc::now();

            if session.expires_at() < now || !session.active() {
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
                        Utc::now().signed_duration_since(updated) >= age
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
    pub async fn list_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        let sessions: Vec<Session> = self.database.get_user_sessions(user_id).await?;
        let now = Utc::now();

        // Filter out expired sessions
        let active_sessions: Vec<Session> = sessions
            .into_iter()
            .filter(|session: &Session| session.expires_at() > now && session.active())
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
    use crate::adapters::{AuthDatabase, DatabaseAdapter, SeaOrmAdapter, run_migrations};
    use crate::entity::AuthSession;
    use crate::sea_orm::Database;
    use crate::types::AuthRequest;
    use crate::types::HttpMethod;
    use chrono::Duration;

    fn test_config() -> Arc<AuthConfig> {
        Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"))
    }

    async fn test_database() -> Arc<AuthDatabase> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        Arc::new(SeaOrmAdapter::new(database))
    }

    fn test_manager() -> SessionManager {
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        SessionManager::new(test_config(), runtime.block_on(test_database()))
    }

    // ── validate_token_format ───────────────────────────────────────────

    #[test]
    fn valid_token_format() {
        let mgr = test_manager();
        let token = "session_abcdefghijklmnopqrstuvwxyz1234567890";
        assert!(mgr.validate_token_format(token));
    }

    #[test]
    fn invalid_token_no_prefix() {
        let mgr = test_manager();
        assert!(!mgr.validate_token_format("abcdefghijklmnopqrstuvwxyz1234567890"));
    }

    #[test]
    fn invalid_token_too_short() {
        let mgr = test_manager();
        assert!(!mgr.validate_token_format("session_short"));
    }

    // ── extract_session_token ───────────────────────────────────────────

    #[test]
    fn extract_from_bearer() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("authorization".into(), "Bearer my-token".into());
        assert_eq!(mgr.extract_session_token(&req), Some("my-token".into()));
    }

    #[test]
    fn extract_from_cookie() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert(
            "cookie".into(),
            "better-auth.session_token=tok123; other=val".into(),
        );
        assert_eq!(mgr.extract_session_token(&req), Some("tok123".into()));
    }

    #[test]
    fn extract_bearer_takes_precedence_over_cookie() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("authorization".into(), "Bearer bearer-tok".into());
        let _ = req.headers.insert(
            "cookie".into(),
            "better-auth.session_token=cookie-tok".into(),
        );
        assert_eq!(mgr.extract_session_token(&req), Some("bearer-tok".into()));
    }

    #[test]
    fn extract_returns_none_without_auth() {
        let mgr = test_manager();
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    #[test]
    fn extract_skips_empty_cookie_value() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("cookie".into(), "better-auth.session_token=".into());
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    // ── is_session_fresh ────────────────────────────────────────────────

    #[test]
    fn session_fresh_when_within_window() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.fresh_age = Some(Duration::minutes(10));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

        // A session created "now" is fresh within a 10-minute window.
        let session = crate::types::Session {
            id: "s1".into(),
            expires_at: Utc::now() + Duration::hours(1),
            token: "tok".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        assert!(mgr.is_session_fresh(&session));
    }

    #[test]
    fn session_not_fresh_when_old() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.fresh_age = Some(Duration::minutes(10));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

        let session = crate::types::Session {
            id: "s1".into(),
            expires_at: Utc::now() + Duration::hours(1),
            token: "tok".into(),
            created_at: Utc::now() - Duration::minutes(20),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        assert!(!mgr.is_session_fresh(&session));
    }

    #[test]
    fn session_never_fresh_when_no_fresh_age() {
        let mgr = test_manager(); // default: fresh_age = None
        let session = crate::types::Session {
            id: "s1".into(),
            expires_at: Utc::now() + Duration::hours(1),
            token: "tok".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        assert!(!mgr.is_session_fresh(&session));
    }

    // ── async operations ────────────────────────────────────────────────

    #[tokio::test]
    async fn create_and_get_session() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        // Create a user first
        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_string();

        let retrieved = mgr.get_session(&token).await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn delete_session_removes_it() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_string();

        mgr.delete_session(&token).await.unwrap();
        let retrieved = mgr.get_session(&token).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn revoke_session_returns_true_when_found() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let result = mgr.revoke_session(session.token()).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn revoke_session_returns_false_when_not_found() {
        let mgr = SessionManager::new(test_config(), test_database().await);
        let result = mgr.revoke_session("nonexistent-token").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn list_user_sessions_excludes_expired() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        // Create two sessions
        let _ = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();

        let sessions = mgr.list_user_sessions(user.id()).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn revoke_all_user_sessions() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let _ = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();

        let count = mgr.revoke_all_user_sessions(user.id()).await.unwrap();
        assert_eq!(count, 2);

        let sessions = mgr.list_user_sessions(user.id()).await.unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn revoke_other_sessions_keeps_current() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let current = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();

        let count = mgr
            .revoke_other_user_sessions(user.id(), current.token())
            .await
            .unwrap();
        assert_eq!(count, 2);

        let remaining = mgr.list_user_sessions(user.id()).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].token(), current.token());
    }
}
