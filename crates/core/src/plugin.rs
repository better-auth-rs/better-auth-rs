use async_trait::async_trait;
use chrono::{DateTime, Utc};
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

/// Runtime metadata published by enabled plugins.
pub type MetadataMap = HashMap<String, serde_json::Value>;

pub struct AuthInitParts<S: AuthSchema> {
    request_runtime: crate::request_runtime::RequestRuntime,
    pub database_hooks: Vec<Arc<dyn crate::store::database_hooks::DatabaseHooks<S>>>,
    pub runtime: crate::plugin_runtime::PluginRuntime<S>,
    pub extensions: crate::RuntimeExtensions,
    pub email_verification_policy: crate::email::EmailVerificationRuntimePolicy,
    pub metadata: MetadataMap,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub secondary_storage: Option<Arc<dyn crate::store::SecondaryStorage>>,
    pub password_policy: crate::utils::password::PasswordRuntimePolicy,
}

/// Action returned by [`AuthPlugin::before_request`].
#[derive(Debug)]
pub enum BeforeRequestAction {
    /// Short-circuit with this response (e.g. return session JSON).
    Respond(AuthResponse),
    /// Replace the request body and continue with the remaining hooks.
    ReplaceBody(Vec<u8>),
    /// Merge endpoint body/query after all before hooks; retain original Request bytes.
    MergeContext(crate::endpoint_input::EndpointInputPatch),
    /// Inject a virtual session so downstream handlers see it as authenticated.
    InjectSession {
        session: Box<crate::wire::SessionView>,
    },
    /// Set the current Session from a trusted server hook without projecting its User value.
    /// Authoritative reads still discard this value when the store owns sessions.
    InjectNativeSession {
        session: Box<crate::session::NativeSessionData>,
    },
}

/// Plugin trait that all authentication plugins must implement.
///
#[async_trait]
pub trait AuthPlugin<S: AuthSchema>: Send + Sync + std::any::Any {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;

    /// Declare adapter fields before the default database and plugin runtime are initialized.
    /// Keep runtime validation, callbacks, and side effects in `on_init`.
    fn schema(&self, _fields: &mut crate::plugin_runtime::ModelFields) -> AuthResult<()> {
        Ok(())
    }

    /// Return the upstream plugin ID; core option wrappers have no plugin ID.
    fn telemetry_plugin_id(&self) -> Option<&'static str> {
        Some(self.name())
    }

    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Document this configured plugin without invoking application field policies.
    fn openapi(&self) -> AuthResult<crate::openapi::OpenApiPluginMetadata> {
        crate::openapi::OpenApiPluginMetadata::from_routes(self.name(), self.routes())
    }

    /// Select the base password hasher before plugin initialization wraps it.
    fn password_hasher(&self) -> Option<Arc<dyn crate::utils::password::PasswordHasher>> {
        None
    }

    /// Report configured options without invoking callbacks or initializing the plugin.
    fn telemetry(&self, _options: &mut crate::observability::telemetry::PluginTelemetry) {}

    /// Default endpoint limits, overridden by explicit application limits.
    fn rate_limits(&self) -> AuthResult<Vec<crate::middleware::PluginRateLimit>> {
        Ok(Vec::new())
    }

    /// Called when the plugin is initialized
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// Inspect an HTTP request after rate limiting and before endpoint middleware.
    /// Native API calls do not run this hook. A response skips endpoint hooks.
    async fn on_http_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    /// Inspect the HTTP router response, including route misses and body errors.
    /// Early HTTP request responses and native endpoint calls skip this hook.
    /// A replacement response stops the remaining HTTP response hooks.
    async fn on_http_response(
        &self,
        _req: &AuthRequest,
        _response: &mut AuthResponse,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    /// Called for a registered endpoint after HTTP body decoding and origin checks.
    ///
    /// Return `Some(BeforeRequestAction::Respond(..))` to short-circuit with a
    /// response, `Some(BeforeRequestAction::InjectSession { .. })` to attach a
    /// virtual session, or `Some(BeforeRequestAction::InjectNativeSession { .. })`
    /// to supply the complete trusted Session. `Some(BeforeRequestAction::ReplaceBody(..))`
    /// rewrites the request body. These actions continue through the remaining hooks.
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
            $( $method:ident $path:literal => $handler:ident, $op_id:literal
                $(, allowed_media_types = [$($media_type:literal),* $(,)?])?
                $(, body = $body:path)?
                $(, query = $query:path)?
                $(, query_native = $query_native:path)?
                $(, require_headers = $require_headers:literal)?
            );* $(;)?
        }
        $( extra { $($extra:tt)* } )?
    ) => {
        #[::async_trait::async_trait]
        impl<S: $crate::AuthSchema> $crate::AuthPlugin<S> for $plugin {
            fn name(&self) -> &'static str { $name }

            fn routes(&self) -> Vec<$crate::AuthRoute> {
                vec![
                    $( $crate::AuthRoute::new($crate::impl_auth_plugin!(@pat $method), $path, $op_id)
                        $(.allowed_media_types(&[$($media_type),*]))?
                        $(.body_validator($body))?
                        $(.query_validator($query))?
                        $(.query_validator_native($query_native))?
                        $(.require_headers($require_headers))?, )*
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

pub use crate::endpoint_input::{BodyValidator, QueryValidator};

/// Route definition for plugins
#[derive(Clone)]
pub struct AuthRoute {
    /// Native-only endpoints cannot match HTTP routing.
    pub server_only: bool,
    /// HTTP matching template with `{parameter}` segments. Native dispatch uses `:parameter` segments.
    pub path: String,
    pub method: HttpMethod,
    /// Identifier used as the OpenAPI `operationId` for this route.
    pub operation_id: String,
    /// Explicit OpenAPI documentation. This does not validate endpoint input.
    pub openapi: Option<crate::openapi::OpenApiRouteMetadata>,
    /// Upstream API key used when excluding plugin endpoints that replace core endpoints.
    pub endpoint_key: Option<String>,
    /// HTTP media types accepted before endpoint middleware. Empty uses the JSON default.
    pub allowed_media_types: Vec<String>,
    /// Query validation runs after before hooks and before endpoint middleware.
    pub query_validator: Option<QueryValidator>,
    pub body_validator: Option<BodyValidator>,
    /// Header presence is validated after body and query, before endpoint middleware.
    pub require_headers: bool,
}

/// Initialization context passed to plugin setup.
pub struct AuthInitContext<S: AuthSchema> {
    logger: crate::observability::Logger,
    request_runtime: crate::request_runtime::RequestRuntime,
    database_hooks: Vec<Arc<dyn crate::store::database_hooks::DatabaseHooks<S>>>,
    runtime: crate::plugin_runtime::PluginRuntime<S>,
    pub extensions: crate::RuntimeExtensions,
    pub email_verification_policy: crate::email::EmailVerificationRuntimePolicy,
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub secondary_storage: Option<Arc<dyn crate::store::SecondaryStorage>>,
    pub password_policy: crate::utils::password::PasswordRuntimePolicy,
    pub metadata: MetadataMap,
}

/// Context passed to plugin methods. Clones retain the same mutable runtime URL.
/// HTTP handlers and endpoint dispatches create separate runtime contexts.
pub struct AuthContext<S: AuthSchema> {
    logger: crate::observability::Logger,
    clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    pub(crate) request_runtime: crate::request_runtime::RequestRuntime,
    pub extensions: crate::RuntimeExtensions,
    pub email_verification_policy: crate::email::EmailVerificationRuntimePolicy,
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub secondary_storage: Option<Arc<dyn crate::store::SecondaryStorage>>,
    pub password_policy: crate::utils::password::PasswordRuntimePolicy,
    pub metadata: MetadataMap,
}

impl<S: AuthSchema> Clone for AuthContext<S> {
    fn clone(&self) -> Self {
        Self {
            logger: self.logger.clone(),
            clock: self.clock.clone(),
            request_runtime: self.request_runtime.clone(),
            extensions: self.extensions.clone(),
            email_verification_policy: self.email_verification_policy.clone(),
            config: self.config.clone(),
            database: self.database.clone(),
            email_provider: self.email_provider.clone(),
            secondary_storage: self.secondary_storage.clone(),
            password_policy: self.password_policy.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl std::fmt::Debug for AuthRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRoute")
            .field("path", &self.path)
            .field("method", &self.method)
            .field("operation_id", &self.operation_id)
            .field("openapi", &self.openapi)
            .field("endpoint_key", &self.endpoint_key)
            .field("allowed_media_types", &self.allowed_media_types)
            .field(
                "query_validator",
                &self.query_validator.as_ref().map(|_| "configured"),
            )
            .field("require_headers", &self.require_headers)
            .field(
                "body_validator",
                &self.body_validator.as_ref().map(|_| "configured"),
            )
            .finish()
    }
}

impl AuthRoute {
    /// Define an endpoint that is available only through trusted native facades.
    pub fn server_only(method: HttpMethod, operation_id: impl Into<String>) -> Self {
        let mut route = Self::new(method, "/", operation_id);
        route.server_only = true;
        route
    }

    /// Match the method and slash-separated path, including named `{parameter}` segments.
    pub fn matches(&self, method: &HttpMethod, path: &str) -> bool {
        if self.server_only || self.method != *method {
            return false;
        }
        let mut actual = path.split('/');
        for expected in self.path.split('/') {
            let Some(actual) = actual.next() else {
                return false;
            };
            if expected != actual
                && !(expected.starts_with('{') && expected.ends_with('}') && !actual.is_empty())
            {
                return false;
            }
        }
        actual.next().is_none()
    }

    pub fn openapi(mut self, metadata: crate::openapi::OpenApiRouteMetadata) -> Self {
        self.openapi = Some(metadata);
        self
    }

    pub fn endpoint_key(mut self, key: impl Into<String>) -> Self {
        self.endpoint_key = Some(key.into());
        self
    }

    /// Install a body validator. Body validation precedes query validation.
    pub fn body_validator(
        mut self,
        validator: impl Fn(&AuthRequest) -> AuthResult<crate::endpoint_input::ValidatedBody>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.body_validator = Some(BodyValidator::new(validator));
        self
    }

    /// Install an asynchronous body validator at the same phase as synchronous validation.
    pub fn body_validator_async<F, Fut>(mut self, validator: F) -> Self
    where
        F: Fn(AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = AuthResult<crate::endpoint_input::ValidatedBody>>
            + Send
            + 'static,
    {
        self.body_validator = Some(BodyValidator::new_async(validator));
        self
    }

    /// Install a JSON query validator through an explicit JSON projection bridge.
    /// Use `query_validator_native` when the schema must observe native values or getters.
    pub fn query_validator(
        mut self,
        validator: fn(Option<serde_json::Value>) -> AuthResult<Option<serde_json::Value>>,
    ) -> Self {
        self.query_validator = Some(QueryValidator::new(move |request| {
            Ok(crate::endpoint_input::ValidatedInput::unvalidated(
                validator(request.input_query()?)?,
            ))
        }));
        self
    }

    /// Install a query validator without projecting native input before validation.
    pub fn query_validator_native(
        mut self,
        validator: impl Fn(&AuthRequest) -> AuthResult<crate::endpoint_input::ValidatedInput>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.query_validator = Some(QueryValidator::new(validator));
        self
    }

    /// Install an asynchronous native query validator after body validation.
    pub fn query_validator_async<F, Fut>(mut self, validator: F) -> Self
    where
        F: Fn(AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = AuthResult<crate::endpoint_input::ValidatedInput>>
            + Send
            + 'static,
    {
        self.query_validator = Some(QueryValidator::new_async(validator));
        self
    }

    pub fn require_headers(mut self, required: bool) -> Self {
        self.require_headers = required;
        self
    }

    pub fn allowed_media_types(mut self, types: &[&str]) -> Self {
        self.allowed_media_types = types.iter().map(|value| (*value).to_owned()).collect();
        self
    }

    pub fn new(
        method: HttpMethod,
        path: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            server_only: false,
            path: path.into(),
            method,
            operation_id: operation_id.into(),
            openapi: None,
            endpoint_key: None,
            allowed_media_types: Vec::new(),
            query_validator: None,
            body_validator: None,
            require_headers: false,
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
    /// Instance logger with renderer options resolved before plugin initialization.
    pub fn logger(&self) -> &crate::observability::Logger {
        &self.logger
    }

    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> AuthResult<Self> {
        let mut config = config;
        if config.resolved_logger.is_none() {
            Arc::make_mut(&mut config).initialize_logger()?;
        }
        let email_provider = config.email_provider.clone();
        let password_policy = crate::utils::password::PasswordRuntimePolicy::new(&config.password);
        Ok(Self {
            logger: config.logger()?,
            request_runtime: Default::default(),
            database_hooks: Vec::new(),
            runtime: Default::default(),
            extensions: crate::RuntimeExtensions::default(),
            email_verification_policy: crate::email::EmailVerificationRuntimePolicy::default(),
            config,
            database,
            email_provider,
            secondary_storage: None,
            password_policy,
            metadata: MetadataMap::new(),
        })
    }

    /// Run a plugin initializer while retaining the logger created for this instance.
    #[doc(hidden)]
    pub async fn initialize_plugin(&mut self, plugin: &dyn AuthPlugin<S>) -> AuthResult<()> {
        let result = plugin.on_init(self).await;
        Arc::make_mut(&mut self.config).resolved_logger = Some(self.logger.clone());
        result
    }

    /// Resolve initial URL and trust options before plugin initialization.
    pub async fn initialize_request_context(&mut self) -> AuthResult<()> {
        let mut context = AuthContext::new(self.config.clone(), self.database.clone())?;
        context.request_runtime = self.request_runtime.clone();
        let context = context.initialize_request_context().await?;
        self.config = context.config.clone();
        self.request_runtime = context.request_runtime.clone();
        Ok(())
    }

    /// Register a database hook before application-owned adapter hooks.
    pub fn register_database_hook(
        &mut self,
        hook: Arc<dyn crate::store::database_hooks::DatabaseHooks<S>>,
    ) {
        self.database_hooks.push(hook);
    }

    /// Obtain a weak handle that resolves after all store facades are installed.
    pub fn runtime(&self) -> crate::plugin_runtime::PluginRuntime<S> {
        self.runtime.clone()
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        _ = self.metadata.insert(key.into(), value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    pub fn into_parts(self) -> AuthInitParts<S> {
        AuthInitParts {
            request_runtime: self.request_runtime,
            database_hooks: self.database_hooks,
            runtime: self.runtime,
            extensions: self.extensions,
            email_verification_policy: self.email_verification_policy,
            metadata: self.metadata,
            email_provider: self.email_provider,
            secondary_storage: self.secondary_storage,
            password_policy: self.password_policy,
        }
    }
}

impl<S: AuthSchema> AuthContext<S> {
    /// Read this context's wall clock. The default clock is `Utc::now`.
    pub fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// Set the wall clock used by context-aware plugin operations.
    /// Clones and request dispatches retain the same clock.
    /// Stores, storage backends, and other runtime components retain their own clocks.
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Instance logger with renderer options resolved before plugin initialization.
    pub fn logger(&self) -> &crate::observability::Logger {
        &self.logger
    }

    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> AuthResult<Self> {
        let mut config = config;
        if config.resolved_logger.is_none() {
            Arc::make_mut(&mut config).initialize_logger()?;
        }
        let email_provider = config.email_provider.clone();
        let password_policy = crate::utils::password::PasswordRuntimePolicy::new(&config.password);
        Ok(Self {
            logger: config.logger()?,
            clock: Arc::new(Utc::now),
            request_runtime: Default::default(),
            extensions: crate::RuntimeExtensions::default(),
            email_verification_policy: crate::email::EmailVerificationRuntimePolicy::default(),
            config,
            database,
            email_provider,
            secondary_storage: None,
            password_policy,
            metadata: MetadataMap::new(),
        })
    }

    pub fn with_metadata(
        config: Arc<AuthConfig>,
        database: Arc<dyn AuthStore<S>>,
        metadata: MetadataMap,
    ) -> AuthResult<Self> {
        let mut context = Self::new(config, database)?;
        context.metadata = metadata;
        Ok(context)
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

    /// Explicit application storage configuration; adapter wrappers do not establish authority.
    pub fn store_capabilities(&self) -> crate::store::StoreCapabilities {
        self.extensions
            .get::<crate::store::StoreCapabilities>()
            .copied()
            .unwrap_or_default()
    }

    /// Create a `SessionManager` from this context's config and database.
    pub fn session_manager(&self) -> crate::session::SessionManager<S> {
        crate::session::SessionManager::new(self.config.clone(), self.database.clone())
            .with_store_capabilities(self.store_capabilities())
            .with_user_metadata(self.metadata.clone())
            .with_adapter_user_fields(self.adapter_user_fields().clone())
            .with_cookie_signer(
                self.extensions
                    .get::<Arc<dyn crate::session::SessionCookieSigner<S>>>()
                    .cloned(),
            )
    }

    /// Select parsed application fields without executing field policies again.
    pub fn select_application_user_fields(&self, parsed: &crate::FieldMap) -> crate::FieldMap {
        let application = self
            .extensions
            .get::<crate::plugin_runtime::ApplicationUserFields>()
            .map_or(&self.config.user, |fields| &fields.0);
        let mut selected: crate::FieldMap = application
            .fields()
            .keys()
            .filter_map(|name| parsed.get(name).map(|value| (name.clone(), value.clone())))
            .collect();
        selected.sort_property_order();
        selected
    }

    /// User policy used by the adapter before public output filtering.
    pub fn adapter_user_fields(&self) -> &crate::user_fields::UserConfig {
        self.extensions
            .get::<crate::plugin_runtime::AdapterUserFields>()
            .map_or(&self.config.user, |fields| &fields.0)
    }

    /// Project a user through the active user schema before returning public data.
    pub async fn user_view(
        &self,
        user: &impl crate::entity::AuthUser,
    ) -> AuthResult<crate::wire::UserView> {
        crate::wire::UserView::with_field_policies(
            user,
            self.adapter_user_fields(),
            &self.config.user,
            &self.metadata,
            self.database.supports_native_json(),
        )
        .await
    }

    /// Keep hidden user fields available to trusted callbacks.
    pub async fn internal_user_view(
        &self,
        user: &impl crate::entity::AuthUser,
    ) -> AuthResult<crate::wire::UserView> {
        crate::wire::UserView::with_internal_fields_for_adapter(
            user,
            self.adapter_user_fields(),
            &self.metadata,
            self.database.supports_native_json(),
        )
        .await
    }

    /// Preserve cached session fields without repeating database output transforms.
    pub async fn session_view(
        &self,
        session: &impl crate::entity::AuthSession,
    ) -> AuthResult<crate::wire::SessionView> {
        self.session_manager().session_view(session).await
    }

    /// Parse public user fields with the final application and plugin declarations.
    pub fn parse_user_input(
        &self,
        input: &serde_json::Map<String, serde_json::Value>,
        create: bool,
    ) -> AuthResult<crate::FieldMap> {
        let input = crate::FieldMap::from_json(input.clone())?;
        self.config.user.parse_input(&input, create)
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

    /// Resolve an endpoint Session with upstream getSessionFromCtx reuse and failure semantics.
    pub async fn native_session(
        &self,
        req: &AuthRequest,
        read: crate::session::SessionRead,
    ) -> AuthResult<Option<crate::session::NativeSessionData>> {
        let authoritative = matches!(read, crate::session::SessionRead::Authoritative)
            && self.store_capabilities().server_sessions();
        if authoritative {
            req.replace_native_session_snapshot(None)?;
        } else if let Some(data) = req.native_session_snapshot()? {
            return Ok(Some(data));
        }
        let mut nested = req.with_separate_response_headers();
        nested.method = crate::HttpMethod::Get;
        // Failed nested endpoints do not publish their queued headers to the outer response.
        let data = match self
            .session_manager()
            .resolve_native_for_endpoint(&nested, read)
            .await
        {
            Ok(resolved) => {
                for (name, value) in nested.take_response_headers()? {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        req.append_response_header(&name, value)?;
                    } else if !name.eq_ignore_ascii_case("cache-control")
                        && !name.eq_ignore_ascii_case("pragma")
                    {
                        req.set_response_header(&name, value)?;
                    }
                }
                resolved.data
            }
            // getSessionFromCtx treats endpoint failures as an absent Session.
            Err(_) => None,
        };
        req.replace_native_session_snapshot(data.clone())?;
        Ok(data)
    }

    /// Require a session while preserving the public User object selected by the adapter.
    pub async fn require_native_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<crate::session::NativeSessionData> {
        self.require_native_session_with_read(req, crate::session::SessionRead::Cached)
            .await
    }

    /// Read the server store without requiring the selected relationship to contain one User.
    pub async fn require_authoritative_native_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<crate::session::NativeSessionData> {
        self.require_native_session_with_read(req, crate::session::SessionRead::Authoritative)
            .await
    }

    async fn require_native_session_with_read(
        &self,
        req: &AuthRequest,
        read: crate::session::SessionRead,
    ) -> AuthResult<crate::session::NativeSessionData> {
        self.native_session(req, read)
            .await?
            .ok_or(AuthError::Unauthenticated)
    }

    async fn require_session_with_read(
        &self,
        req: &AuthRequest,
        read: crate::session::SessionRead,
    ) -> AuthResult<(crate::wire::UserView, crate::wire::SessionView)> {
        let resolved = self.session_manager().resolve(req, read).await?;
        req.set_session_snapshot(resolved.data.clone().map(Into::into))?;
        let data = resolved.data.ok_or(AuthError::Unauthenticated)?;
        Ok((data.user, data.session))
    }
}

impl<S: AuthSchema> AuthInitParts<S> {
    /// Preserve the initialized trust snapshot and auth-instance identity in the final context.
    pub fn apply_request_runtime(&self, context: &mut AuthContext<S>) {
        context.request_runtime = self.request_runtime.clone();
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
mod tests {
    mod async_body_dispatch;
    mod native_session_hooks;
    mod raw_api_errors;
    mod response_headers;
    mod response_status;
    mod response_values;
    mod route_paths;

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
        let ctx = AuthContext::new(config.clone(), db).unwrap();
        assert!(ctx.email_provider.is_none());
        assert!(ctx.metadata.is_empty());
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The clock regression asserts callback retention across context constructors, clones, and native dispatch."
    )]
    async fn auth_context_clock_survives_clone_and_native_dispatch() -> AuthResult<()> {
        use std::sync::atomic::{AtomicI64, Ordering};

        const NOW: i64 = 2_000_000_000_000;
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.base_url = "http://clock.test".into();
        let config = Arc::new(config);
        let database = test_database().await;
        for context in [
            AuthContext::new(config.clone(), database.clone())?,
            AuthContext::with_metadata(config.clone(), database.clone(), MetadataMap::new())?,
        ] {
            let time = Arc::new(AtomicI64::new(NOW));
            let clock = time.clone();
            let mut context = context.with_clock(move || {
                DateTime::UNIX_EPOCH + chrono::Duration::milliseconds(clock.load(Ordering::Relaxed))
            });
            let route = AuthRoute::get("/clock", "clockProbe");
            context
                .extensions
                .insert(Arc::new(crate::endpoint_dispatch::EndpointDispatcher::<
                    crate::store::StatelessSchema,
                >::new(
                    Arc::new(Vec::new()),
                    Default::default(),
                    [route.clone()],
                )));
            let cloned = context.clone();
            assert_eq!(cloned.now().timestamp_millis(), NOW);
            time.store(NOW + 1, Ordering::Relaxed);
            let response = cloned
                .dispatch_native(
                    crate::NativeRequest::default(),
                    route,
                    None,
                    None,
                    |_, dispatched| async move {
                        let cloned = dispatched.as_ref().clone();
                        AuthResponse::json(None, &cloned.now().timestamp_millis())
                    },
                )
                .await?;
            assert_eq!(response.body.json()?, Some(serde_json::json!(NOW + 1)));
            assert_eq!(context.now().timestamp_millis(), NOW + 1);
        }
        Ok(())
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_context_metadata() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let mut ctx = AuthContext::new(config, db).unwrap();

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
        let ctx = AuthContext::new(config, db).unwrap();
        assert!(ctx.email_provider().is_err());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[tokio::test]
    async fn auth_context_require_session_unauthenticated() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let db = test_database().await;
        let ctx = AuthContext::new(config, db).unwrap();
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
        let ctx = AuthContext::new(config.clone(), db).unwrap();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                crate::utils::cookie_utils::sign_cookie_value(
                    session.token.typed().unwrap(),
                    config.signing_secret()
                )
            ),
        );

        let (found_user, _found_session) = ctx.require_session(&req).await.unwrap();
        assert_eq!(found_user.id(), user.id());
    }
}
