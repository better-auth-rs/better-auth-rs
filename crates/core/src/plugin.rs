use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::adapters::DatabaseAdapter;
use crate::config::AuthConfig;
use crate::email::EmailProvider;
use crate::entity::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::types::{AuthRequest, AuthResponse, HttpMethod};

/// Plugin trait that all authentication plugins must implement.
///
/// Generic over `DB` so that lifecycle hooks receive the adapter's concrete
/// entity types (e.g., `DB::User`, `DB::Session`).
#[async_trait]
pub trait AuthPlugin<DB: DatabaseAdapter>: Send + Sync {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;

    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Called when the plugin is initialized
    async fn on_init(&self, ctx: &mut AuthContext<DB>) -> AuthResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>>;

    /// Called after a user is created
    async fn on_user_created(&self, user: &DB::User, ctx: &AuthContext<DB>) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after a session is created
    async fn on_session_created(
        &self,
        session: &DB::Session,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    /// Called before a user is deleted
    async fn on_user_deleted(&self, user_id: &str, ctx: &AuthContext<DB>) -> AuthResult<()> {
        let _ = (user_id, ctx);
        Ok(())
    }

    /// Called before a session is deleted
    async fn on_session_deleted(
        &self,
        session_token: &str,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        let _ = (session_token, ctx);
        Ok(())
    }
}

/// Route definition for plugins
#[derive(Debug, Clone)]
pub struct AuthRoute {
    pub path: String,
    pub method: HttpMethod,
    /// Identifier used as the OpenAPI `operationId` for this route.
    pub operation_id: String,
}

/// Context passed to plugin methods
pub struct AuthContext<DB: DatabaseAdapter> {
    pub config: Arc<AuthConfig>,
    pub database: Arc<DB>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuthRoute {
    pub fn new(
        method: HttpMethod,
        path: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            method,
            operation_id: operation_id.into(),
        }
    }

    pub fn get(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, path, operation_id)
    }

    pub fn post(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, path, operation_id)
    }

    pub fn put(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, path, operation_id)
    }

    pub fn delete(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, path, operation_id)
    }
}

impl<DB: DatabaseAdapter> AuthContext<DB> {
    pub fn new(config: Arc<AuthConfig>, database: Arc<DB>) -> Self {
        let email_provider = config.email_provider.clone();
        Self {
            config,
            database,
            email_provider,
            metadata: HashMap::new(),
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.insert(key.into(), value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    /// Get the email provider, returning an error if none is configured.
    pub fn email_provider(&self) -> AuthResult<&dyn EmailProvider> {
        self.email_provider
            .as_deref()
            .ok_or_else(|| AuthError::config("No email provider configured"))
    }

    /// Extract a session token from the request, validate the session, and
    /// return the authenticated `(User, Session)` pair.
    ///
    /// This centralises the pattern previously duplicated across many plugins
    /// (`get_authenticated_user`, `require_session`, etc.).
    pub async fn require_session(&self, req: &AuthRequest) -> AuthResult<(DB::User, DB::Session)> {
        let session_manager =
            crate::session::SessionManager::new(self.config.clone(), self.database.clone());

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
            && let Some(user) = self.database.get_user_by_id(session.user_id()).await?
        {
            return Ok((user, session));
        }

        Err(AuthError::Unauthenticated)
    }
}
