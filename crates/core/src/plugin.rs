use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AuthConfig;
use crate::email::EmailProvider;
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
#[cfg(test)]
use crate::session::SessionManager;
use crate::store::AuthStore;
use crate::types::{AuthRequest, AuthResponse, HttpMethod};

type MetadataMap = HashMap<String, serde_json::Value>;

pub struct AuthInitParts {
    pub extensions: crate::RuntimeExtensions,
    pub email_verification_policy: crate::email::EmailVerificationRuntimePolicy,
    pub metadata: MetadataMap,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub password_policy: crate::utils::password::PasswordRuntimePolicy,
}

/// Action returned by [`AuthPlugin::before_request`].
#[derive(Debug)]
pub enum BeforeRequestAction {
    /// Short-circuit with this response (e.g. return session JSON).
    Respond(AuthResponse),
    /// Replace the request body and continue with the remaining hooks.
    ReplaceBody(Vec<u8>),
    /// Inject a virtual session so downstream handlers see it as authenticated.
    InjectSession {
        session: Box<crate::wire::SessionView>,
    },
}

/// Plugin trait that all authentication plugins must implement.
///
#[async_trait]
pub trait AuthPlugin<S: AuthSchema>: Send + Sync + std::any::Any {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;

    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Default endpoint limits, overridden by explicit application limits.
    fn rate_limits(&self) -> AuthResult<Vec<(String, crate::middleware::EndpointRateLimit)>> {
        Ok(Vec::new())
    }

    /// Called when the plugin is initialized
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// Called before route matching for every incoming request.
    ///
    /// Return `Some(BeforeRequestAction::Respond(..))` to short-circuit with a
    /// response, `Some(BeforeRequestAction::InjectSession { .. })` to attach a
    /// virtual session, or `Some(BeforeRequestAction::ReplaceBody(..))` to rewrite
    /// the request body. Session injection and body replacement continue through
    /// the remaining hooks before normal route matching.
    async fn before_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(None)
    }

    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>>;

    /// Inspect or extend the final route response after session cookies are applied.
    async fn after_request(
        &self,
        _req: &AuthRequest,
        _response: &mut AuthResponse,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
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
        impl<S: $crate::AuthSchema> $crate::AuthPlugin<S> for $plugin {
            fn name(&self) -> &'static str { $name }

            fn routes(&self) -> Vec<$crate::AuthRoute> {
                vec![
                    $( $crate::AuthRoute::new($crate::impl_auth_plugin!(@pat $method), $path, $op_id), )*
                ]
            }

            async fn on_request(
                &self,
                req: &$crate::AuthRequest,
                ctx: &$crate::AuthContext<S>,
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

/// Initialization context passed to plugin setup.
pub struct AuthInitContext<S: AuthSchema> {
    pub extensions: crate::RuntimeExtensions,
    pub email_verification_policy: crate::email::EmailVerificationRuntimePolicy,
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub password_policy: crate::utils::password::PasswordRuntimePolicy,
    pub metadata: MetadataMap,
}

/// Context passed to plugin methods.
pub struct AuthContext<S: AuthSchema> {
    pub extensions: crate::RuntimeExtensions,
    pub email_verification_policy: crate::email::EmailVerificationRuntimePolicy,
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub password_policy: crate::utils::password::PasswordRuntimePolicy,
    pub metadata: MetadataMap,
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

impl<S: AuthSchema> AuthInitContext<S> {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> Self {
        let email_provider = config.email_provider.clone();
        let password_policy = crate::utils::password::PasswordRuntimePolicy::new(&config.password);
        Self {
            extensions: crate::RuntimeExtensions::default(),
            email_verification_policy: crate::email::EmailVerificationRuntimePolicy::default(),
            config,
            database,
            email_provider,
            password_policy,
            metadata: MetadataMap::new(),
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        _ = self.metadata.insert(key.into(), value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    pub fn into_parts(self) -> AuthInitParts {
        AuthInitParts {
            extensions: self.extensions,
            email_verification_policy: self.email_verification_policy,
            metadata: self.metadata,
            email_provider: self.email_provider,
            password_policy: self.password_policy,
        }
    }
}

impl<S: AuthSchema> AuthContext<S> {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> Self {
        let email_provider = config.email_provider.clone();
        let password_policy = crate::utils::password::PasswordRuntimePolicy::new(&config.password);
        Self {
            extensions: crate::RuntimeExtensions::default(),
            email_verification_policy: crate::email::EmailVerificationRuntimePolicy::default(),
            config,
            database,
            email_provider,
            password_policy,
            metadata: MetadataMap::new(),
        }
    }

    pub fn with_metadata(
        config: Arc<AuthConfig>,
        database: Arc<dyn AuthStore<S>>,
        metadata: MetadataMap,
    ) -> Self {
        let email_provider = config.email_provider.clone();
        let password_policy = crate::utils::password::PasswordRuntimePolicy::new(&config.password);
        Self {
            extensions: crate::RuntimeExtensions::default(),
            email_verification_policy: crate::email::EmailVerificationRuntimePolicy::default(),
            config,
            database,
            email_provider,
            password_policy,
            metadata,
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
    pub fn session_manager(&self) -> crate::session::SessionManager<S> {
        crate::session::SessionManager::new(self.config.clone(), self.database.clone())
    }

    /// Extract a session token from the request, validate the session, and
    /// return the authenticated `(User, Session)` pair.
    ///
    /// This centralises the pattern previously duplicated across many plugins
    /// (`get_authenticated_user`, `require_session`, etc.).
    pub async fn require_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(crate::wire::UserView, crate::wire::SessionView)> {
        self.require_session_with_read(req, crate::session::SessionRead::Cached)
            .await
    }

    /// Require a session read from the server store for sensitive work.
    pub async fn require_authoritative_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(crate::wire::UserView, crate::wire::SessionView)> {
        self.require_session_with_read(req, crate::session::SessionRead::Authoritative)
            .await
    }

    async fn require_session_with_read(
        &self,
        req: &AuthRequest,
        read: crate::session::SessionRead,
    ) -> AuthResult<(crate::wire::UserView, crate::wire::SessionView)> {
        let resolved = self.session_manager().resolve(req, read).await?;
        resolved
            .data
            .map(|data| (data.user, data.session))
            .ok_or(AuthError::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::AuthUser;
    use crate::test_store::test_database;

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
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

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_route_new() {
        let route = AuthRoute::new(HttpMethod::Patch, "/patch", "patchIt");
        assert_eq!(route.method, HttpMethod::Patch);
        assert_eq!(route.path, "/patch");
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_context_new() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config.clone(), db);
        assert!(ctx.email_provider.is_none());
        assert!(ctx.metadata.is_empty());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
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

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_context_email_provider_error_when_none() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config, db);
        assert!(ctx.email_provider().is_err());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[tokio::test]
    async fn auth_context_require_session_unauthenticated() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let db = test_database().await;
        let ctx = AuthContext::new(config, db);
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let result = ctx.require_session(&req).await;
        assert!(result.is_err());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
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
            format!(
                "better-auth.session_token={}",
                crate::utils::cookie_utils::sign_cookie_value(&session.token, &config.secret)
            ),
        );

        let (found_user, _found_session) = ctx.require_session(&req).await.unwrap();
        assert_eq!(found_user.id(), user.id());
    }
}
