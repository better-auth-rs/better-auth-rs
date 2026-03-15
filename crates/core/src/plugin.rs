use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::adapters::AuthDatabase;
use crate::config::AuthConfig;
use crate::email::EmailProvider;
use crate::entity::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::session::SessionManager;
use crate::types::{AuthRequest, AuthResponse, HttpMethod, Session, User};

/// Action returned by [`AuthPlugin::before_request`].
#[derive(Debug)]
pub enum BeforeRequestAction {
    /// Short-circuit with this response (e.g. return session JSON).
    Respond(AuthResponse),
    /// Inject a virtual session so downstream handlers see it as authenticated.
    InjectSession {
        user_id: String,
        session_token: String,
    },
}

/// Plugin trait that all authentication plugins must implement.
///
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;

    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Called when the plugin is initialized
    async fn on_init(&self, ctx: &mut AuthContext) -> AuthResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// Called before route matching for every incoming request.
    ///
    /// Return `Some(BeforeRequestAction::Respond(..))` to short-circuit with a
    /// response, `Some(BeforeRequestAction::InjectSession { .. })` to attach a
    /// virtual session (e.g. API-key → session emulation), or `None` to let the
    /// request continue to normal route matching.
    async fn before_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(None)
    }

    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>>;

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

/// Generates the [`AuthPlugin`] impl for a plugin with static route dispatch.
///
/// Eliminates the dual declaration of routes in `routes()` and `on_request()`
/// by generating both from a single route table.
///
/// # Exceptions (must keep manual impl)
/// - `OAuthPlugin` — dynamic path matching for `/callback/{provider}`
/// - `SessionManagementPlugin` — match guards and OR patterns
/// - `EmailPasswordPlugin` — conditional routes based on config
/// - `UserManagementPlugin` — conditional routes based on config
/// - `PasswordManagementPlugin` — dynamic path matching for `/reset-password/{token}`
/// - `OrganizationPlugin` — handlers accept extra `&self.config` argument
#[macro_export]
macro_rules! impl_auth_plugin {
    (@pat get) => { $crate::HttpMethod::Get };
    (@pat post) => { $crate::HttpMethod::Post };
    (@pat put) => { $crate::HttpMethod::Put };
    (@pat delete) => { $crate::HttpMethod::Delete };
    (@pat patch) => { $crate::HttpMethod::Patch };
    (@pat head) => { $crate::HttpMethod::Head };

    (@route get) => { $crate::AuthRoute::get };
    (@route post) => { $crate::AuthRoute::post };
    (@route put) => { $crate::AuthRoute::put };
    (@route delete) => { $crate::AuthRoute::delete };

    (
        $plugin:ty, $name:expr;
        routes {
            $( $method:ident $path:literal => $handler:ident, $op_id:literal );* $(;)?
        }
        $( extra { $($extra:tt)* } )?
    ) => {
        #[::async_trait::async_trait]
        impl $crate::AuthPlugin for $plugin {
            fn name(&self) -> &'static str { $name }

            fn routes(&self) -> Vec<$crate::AuthRoute> {
                vec![
                    $( $crate::AuthRoute::new($crate::impl_auth_plugin!(@pat $method), $path, $op_id), )*
                ]
            }

            async fn on_request(
                &self,
                req: &$crate::AuthRequest,
                ctx: &$crate::AuthContext,
            ) -> $crate::AuthResult<Option<$crate::AuthResponse>> {
                match (req.method(), req.path()) {
                    $(
                        ($crate::impl_auth_plugin!(@pat $method), $path) => {
                            Ok(Some(self.$handler(req, ctx).await?))
                        }
                    )*
                    _ => Ok(None),
                }
            }

            $( $($extra)* )?
        }
    };
}

/// Route definition for plugins
#[derive(Debug, Clone)]
pub struct AuthRoute {
    pub path: String,
    pub method: HttpMethod,
    /// Identifier used as the OpenAPI `operationId` for this route.
    pub operation_id: String,
}

/// Context passed to plugin methods.
pub struct AuthContext {
    pub config: Arc<AuthConfig>,
    pub database: Arc<AuthDatabase>,
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

impl AuthContext {
    pub fn new(config: Arc<AuthConfig>, database: Arc<AuthDatabase>) -> Self {
        let email_provider = config.email_provider.clone();
        Self {
            config,
            database,
            email_provider,
            metadata: HashMap::new(),
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        _ = self.metadata.insert(key.into(), value);
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

    /// Create a `SessionManager` from this context's config and database.
    pub fn session_manager(&self) -> crate::session::SessionManager {
        crate::session::SessionManager::new(self.config.clone(), self.database.clone())
    }

    /// Extract a session token from the request, validate the session, and
    /// return the authenticated `(User, Session)` pair.
    ///
    /// This centralises the pattern previously duplicated across many plugins
    /// (`get_authenticated_user`, `require_session`, etc.).
    pub async fn require_session(&self, req: &AuthRequest) -> AuthResult<(User, Session)> {
        let session_manager = self.session_manager();

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
            && let Some(user) = self.database.get_user_by_id(session.user_id()).await?
        {
            return Ok((user, session));
        }

        Err(AuthError::Unauthenticated)
    }
}

/// Axum-friendly shared state type.
///
/// All fields are behind `Arc` so `AuthState` is cheap to clone and can
/// be used directly as axum `State`.
pub struct AuthState {
    pub config: Arc<AuthConfig>,
    pub database: Arc<AuthDatabase>,
    pub session_manager: SessionManager,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
}

impl Clone for AuthState {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            database: self.database.clone(),
            session_manager: self.session_manager.clone(),
            email_provider: self.email_provider.clone(),
        }
    }
}

impl AuthState {
    /// Create a new `AuthState` from an `AuthContext` and `SessionManager`.
    pub fn new(ctx: &AuthContext, session_manager: SessionManager) -> Self {
        Self {
            config: ctx.config.clone(),
            database: ctx.database.clone(),
            session_manager,
            email_provider: ctx.email_provider.clone(),
        }
    }

    /// Create an `AuthContext` for use with existing plugin handler methods.
    pub fn to_context(&self) -> AuthContext {
        let mut ctx = AuthContext::new(self.config.clone(), self.database.clone());
        ctx.email_provider = self.email_provider.clone();
        ctx
    }

    /// Build a `Set-Cookie` header value for a session token.
    pub fn session_cookie(&self, token: &str) -> String {
        crate::utils::cookie_utils::create_session_cookie(token, &self.config)
    }

    /// Build a `Set-Cookie` header value that clears the session cookie.
    pub fn clear_session_cookie(&self) -> String {
        crate::utils::cookie_utils::create_clear_session_cookie(&self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{DatabaseAdapter, SeaOrmAdapter, run_migrations};
    use crate::entity::AuthUser;
    use crate::sea_orm::Database;

    async fn test_database() -> Arc<AuthDatabase> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        Arc::new(SeaOrmAdapter::new(database))
    }

    #[test]
    fn auth_route_constructors() {
        let get = AuthRoute::get("/test", "getTest");
        assert_eq!(get.method, HttpMethod::Get);
        assert_eq!(get.path, "/test");
        assert_eq!(get.operation_id, "getTest");

        let post = AuthRoute::post("/create", "createItem");
        assert_eq!(post.method, HttpMethod::Post);

        let put = AuthRoute::put("/update", "updateItem");
        assert_eq!(put.method, HttpMethod::Put);

        let delete = AuthRoute::delete("/remove", "deleteItem");
        assert_eq!(delete.method, HttpMethod::Delete);
    }

    #[test]
    fn auth_route_new() {
        let route = AuthRoute::new(HttpMethod::Patch, "/patch", "patchIt");
        assert_eq!(route.method, HttpMethod::Patch);
        assert_eq!(route.path, "/patch");
    }

    #[test]
    fn auth_context_new() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config.clone(), db);
        assert!(ctx.email_provider.is_none());
        assert!(ctx.metadata.is_empty());
    }

    #[test]
    fn auth_context_metadata() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let mut ctx = AuthContext::new(config, db);

        ctx.set_metadata("key", serde_json::json!("value"));
        assert_eq!(ctx.get_metadata("key"), Some(&serde_json::json!("value")));
        assert!(ctx.get_metadata("missing").is_none());
    }

    #[test]
    fn auth_context_email_provider_error_when_none() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config, db);
        assert!(ctx.email_provider().is_err());
    }

    #[test]
    fn auth_state_clones() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config.clone(), db.clone());
        let sm = SessionManager::new(config, db);
        let state = AuthState::new(&ctx, sm);
        let cloned = state.clone();
        assert_eq!(cloned.config.secret, state.config.secret);
    }

    #[test]
    fn auth_state_to_context() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config.clone(), db.clone());
        let sm = SessionManager::new(config, db);
        let state = AuthState::new(&ctx, sm);
        let ctx2 = state.to_context();
        assert_eq!(ctx2.config.secret, state.config.secret);
    }

    #[tokio::test]
    async fn auth_context_require_session_unauthenticated() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let db = test_database().await;
        let ctx = AuthContext::new(config, db);
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let result = ctx.require_session(&req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn auth_context_require_session_with_valid_session() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let db = test_database().await;

        // Create a user
        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        // Create a session
        let sm = SessionManager::new(config.clone(), db.clone());
        let session = sm.create_session(&user, None, None).await.unwrap();

        // Build request with the session token
        let ctx = AuthContext::new(config.clone(), db);
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert(
            "cookie".into(),
            format!("better-auth.session_token={}", session.token()),
        );

        let (found_user, _found_session) = ctx.require_session(&req).await.unwrap();
        assert_eq!(found_user.id(), user.id());
    }

    #[test]
    fn auth_state_session_cookie() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config.clone(), db.clone());
        let sm = SessionManager::new(config, db);
        let state = AuthState::new(&ctx, sm);

        let cookie = state.session_cookie("my-token");
        assert!(cookie.contains("better-auth.session_token=my-token"));
        assert!(cookie.contains("HttpOnly"));
    }

    #[test]
    fn auth_state_clear_session_cookie() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config.clone(), db.clone());
        let sm = SessionManager::new(config, db);
        let state = AuthState::new(&ctx, sm);

        let cookie = state.clear_session_cookie();
        assert!(cookie.contains("better-auth.session_token="));
        // Clear cookie uses expires=UNIX_EPOCH (Thu, 01 Jan 1970)
        assert!(cookie.contains("1970"));
    }
}

/// Plugin trait for axum-native routing.
///
/// Unlike [`AuthPlugin`] which uses the custom `AuthRequest`/`AuthResponse`
/// abstraction, `AxumPlugin` returns a standard `axum::Router` with handlers
/// already bound to routes. This eliminates the triple route-matching overhead
/// and enables use of axum extractors.
#[cfg(feature = "axum")]
#[async_trait]
pub trait AxumPlugin: Send + Sync {
    /// Plugin name — should be unique and match the `AuthPlugin` name when
    /// both traits are implemented on the same type.
    fn name(&self) -> &'static str;

    /// Return an axum `Router` with all routes for this plugin.
    ///
    /// The router uses [`AuthState`] as its state type.
    fn router(&self) -> axum::Router<AuthState>;

    /// Called after a user is created.
    async fn on_user_created(&self, _user: &User, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }

    /// Called after a session is created.
    async fn on_session_created(&self, _session: &Session, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }

    /// Called before a user is deleted.
    async fn on_user_deleted(&self, _user_id: &str, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }

    /// Called before a session is deleted.
    async fn on_session_deleted(&self, _session_token: &str, _ctx: &AuthContext) -> AuthResult<()> {
        Ok(())
    }
}
