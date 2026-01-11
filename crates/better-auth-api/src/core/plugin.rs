use async_trait::async_trait;
use std::sync::Arc;
use std::collections::HashMap;

use crate::types::{AuthRequest, AuthResponse, User, Session, HttpMethod};
use crate::error::AuthResult;
use crate::adapters::{DatabaseAdapter, CacheAdapter, MailerAdapter};
use crate::core::config::AuthConfig;

/// Capability requirements declared by plugins.
#[derive(Debug, Clone, Copy, Default)]
pub struct PluginCapabilities {
    pub needs_database: bool,
    pub needs_cache: bool,
    pub needs_mailer: bool,
    pub needs_rate_limiter: bool,
    pub needs_job_runner: bool,
}

/// Runtime capabilities provided by the system.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeCapabilities {
    pub database: bool,
    pub cache: bool,
    pub mailer: bool,
    pub rate_limiter: bool,
    pub job_runner: bool,
}

/// Plugin trait that all authentication plugins must implement
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;
    
    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Capability requirements for this plugin
    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities::default()
    }
    
    /// Called when the plugin is initialized
    async fn on_init(&self, ctx: &mut AuthContext) -> AuthResult<()> {
        let _ = ctx;
        Ok(())
    }
    
    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>>;
    
    /// Called after a user is created
    async fn on_user_created(&self, user: &User, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }
    
    /// Called after a session is created
    async fn on_session_created(&self, session: &Session, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }
    
    /// Called before a user is deleted
    async fn on_user_deleted(&self, user_id: &str, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (user_id, ctx);
        Ok(())
    }
    
    /// Called before a session is deleted
    async fn on_session_deleted(&self, session_token: &str, ctx: &AuthContext) -> AuthResult<()> {
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

/// Route definition resolved by the core.
#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub path: String,
    pub method: HttpMethod,
    pub handler: String,
    pub plugin: &'static str,
}

/// Context passed to plugin methods
pub struct AuthContext {
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn DatabaseAdapter>,
    pub cache: Option<Arc<dyn CacheAdapter>>,
    pub mailer: Option<Arc<dyn MailerAdapter>>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub hooks: Arc<dyn HookDispatcher>,
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

impl AuthContext {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn DatabaseAdapter>) -> Self {
        Self {
            config,
            database,
            cache: None,
            mailer: None,
            metadata: HashMap::new(),
            hooks: Arc::new(NoopHookDispatcher),
        }
    }

    pub fn new_with_capabilities(
        config: Arc<AuthConfig>,
        database: Arc<dyn DatabaseAdapter>,
        cache: Option<Arc<dyn CacheAdapter>>,
        mailer: Option<Arc<dyn MailerAdapter>>,
        hooks: Arc<dyn HookDispatcher>,
    ) -> Self {
        Self {
            config,
            database,
            cache,
            mailer,
            metadata: HashMap::new(),
            hooks,
        }
    }
    
    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.insert(key.into(), value);
    }
    
    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    pub async fn emit_user_created(&self, user: &User) -> AuthResult<()> {
        self.hooks.user_created(user, self).await
    }

    pub async fn emit_session_created(&self, session: &Session) -> AuthResult<()> {
        self.hooks.session_created(session, self).await
    }

    pub async fn emit_user_deleted(&self, user_id: &str) -> AuthResult<()> {
        self.hooks.user_deleted(user_id, self).await
    }

    pub async fn emit_session_deleted(&self, session_token: &str) -> AuthResult<()> {
        self.hooks.session_deleted(session_token, self).await
    }
}

/// Hook dispatcher for plugin lifecycle events.
#[async_trait]
pub trait HookDispatcher: Send + Sync {
    async fn user_created(&self, user: &User, ctx: &AuthContext) -> AuthResult<()>;
    async fn session_created(&self, session: &Session, ctx: &AuthContext) -> AuthResult<()>;
    async fn user_deleted(&self, user_id: &str, ctx: &AuthContext) -> AuthResult<()>;
    async fn session_deleted(&self, session_token: &str, ctx: &AuthContext) -> AuthResult<()>;
}

struct NoopHookDispatcher;

#[async_trait]
impl HookDispatcher for NoopHookDispatcher {
    async fn user_created(&self, _user: &User, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }

    async fn session_created(&self, _session: &Session, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }

    async fn user_deleted(&self, _user_id: &str, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }

    async fn session_deleted(&self, _session_token: &str, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }
}
