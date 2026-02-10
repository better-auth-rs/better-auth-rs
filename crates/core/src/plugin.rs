use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::adapters::DatabaseAdapter;
use crate::config::AuthConfig;
use crate::email::EmailProvider;
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
    pub handler: String,
}

/// Context passed to plugin methods
pub struct AuthContext<DB: DatabaseAdapter> {
    pub config: Arc<AuthConfig>,
    pub database: Arc<DB>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuthRoute {
    pub fn new(method: HttpMethod, path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            method,
            handler: handler.into(),
        }
    }

    pub fn get(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, path, handler)
    }

    pub fn post(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, path, handler)
    }

    pub fn put(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, path, handler)
    }

    pub fn delete(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, path, handler)
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
}
