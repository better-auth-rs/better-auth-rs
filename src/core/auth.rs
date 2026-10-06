use std::sync::Arc;

use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthSchema, AuthStore, EmailProvider, HttpMethod, OkResponse, OpenApiRegistry,
    OpenApiSpec, SessionManager, UpdateUser, core_paths,
    entity::AuthUser,
    hooks::{RequestHookContext, set_request_hook_route, with_request_hook_context_value},
    middleware::{
        self, BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig,
        CsrfMiddleware, Middleware, RateLimitConfig, RateLimitMiddleware,
    },
};

fn endpoint_error(error: AuthError, request: &AuthRequest) -> AuthResult<AuthError> {
    if !error.is_api_error() {
        return Ok(error);
    }
    Ok(error.capture_endpoint_headers(request.take_response_headers()?))
}

pub(crate) fn core_routes() -> [better_auth_core::AuthRoute; 4] {
    [
        better_auth_core::AuthRoute::get(core_paths::OK, "ok"),
        better_auth_core::AuthRoute::get(core_paths::ERROR, "error"),
        better_auth_core::AuthRoute::get(core_paths::OPENAPI_SPEC, "openapi_spec"),
        better_auth_core::AuthRoute::post(core_paths::UPDATE_USER, "updateUser")
            .body_validator(better_auth_core::endpoint_input::record_body),
    ]
}

pub struct BetterAuth<S: AuthSchema> {
    config: Arc<AuthConfig>,
    plugins: Arc<Vec<Box<dyn AuthPlugin<S>>>>,
    middlewares: Vec<Box<dyn Middleware>>,
    http_middlewares: Vec<Box<dyn Middleware>>,
    body_limit: BodyLimitConfig,
    store: Arc<dyn AuthStore<S>>,
    session_manager: SessionManager<S>,
    context: Arc<AuthContext<S>>,
}

type EphemeralStoreFactory<S> = Box<dyn FnOnce(Arc<AuthConfig>) -> Arc<dyn AuthStore<S>> + Send>;

/// Initial builder for configuring BetterAuth.
pub struct AuthBuilder<S: AuthSchema> {
    config: AuthConfig,
    hooks: better_auth_core::observability::EndpointHooks<S>,
    validate_user_info:
        Option<Arc<dyn better_auth_api::plugins::user_admission::ValidateUserInfo<S>>>,
    api_error_handler: Option<Arc<dyn better_auth_core::api_error::ApiErrorHandler<S>>>,
    store: Option<Arc<dyn AuthStore<S>>>,
    ephemeral_store: Option<EphemeralStoreFactory<S>>,
    secondary_storage: Option<Arc<dyn better_auth_core::store::SecondaryStorage>>,
    plugins: Vec<Box<dyn AuthPlugin<S>>>,
    csrf_config: Option<CsrfConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    cors_config: Option<CorsConfig>,
    body_limit_config: Option<BodyLimitConfig>,
    custom_middlewares: Vec<Box<dyn Middleware>>,
}

impl<S: AuthSchema> AuthBuilder<S> {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            hooks: Default::default(),
            validate_user_info: None,
            api_error_handler: None,
            store: None,
            ephemeral_store: None,
            secondary_storage: None,
            plugins: Vec::new(),
            csrf_config: None,
            rate_limit_config: None,
            cors_config: None,
            body_limit_config: None,
            custom_middlewares: Vec::new(),
        }
    }

    /// Set the shared auth store implementation.
    pub fn store<T>(mut self, store: T) -> Self
    where
        T: AuthStore<S> + 'static,
    {
        self.store = Some(Arc::new(store));
        self
    }

    /// Set the shared auth store implementation using an existing [`Arc`].
    pub fn store_arc(mut self, store: Arc<dyn AuthStore<S>>) -> Self {
        self.store = Some(store);
        self
    }

    /// Install shared secondary storage for authentication plugins.
    pub fn secondary_storage(
        mut self,
        storage: Arc<dyn better_auth_core::store::SecondaryStorage>,
    ) -> Self {
        self.secondary_storage = Some(storage);
        self
    }

    /// Validate user provisioning and OAuth link/sign-in data before persistence.
    pub fn validate_user_info(
        mut self,
        callback: Arc<dyn better_auth_api::plugins::user_admission::ValidateUserInfo<S>>,
    ) -> Self {
        self.validate_user_info = Some(callback);
        self
    }

    /// Observe HTTP routing failures. Native calls bypass this callback.
    pub fn on_api_error(
        mut self,
        callback: Arc<dyn better_auth_core::api_error::ApiErrorHandler<S>>,
    ) -> Self {
        self.api_error_handler = Some(callback);
        self
    }

    /// Install global user hooks before the corresponding plugin hooks.
    pub fn hooks(mut self, hooks: better_auth_core::observability::EndpointHooks<S>) -> Self {
        self.hooks = hooks;
        self
    }

    /// Add a plugin to the authentication system.
    pub fn plugin<P: AuthPlugin<S> + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Configure CSRF protection.
    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Configure rate limiting.
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    /// Configure CORS.
    pub fn cors(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(config);
        self
    }

    /// Configure body size limit.
    pub fn body_limit(mut self, config: BodyLimitConfig) -> Self {
        self.body_limit_config = Some(config);
        self
    }

    /// Set the email provider.
    pub fn email_provider<E: EmailProvider + 'static>(mut self, provider: E) -> Self {
        self.config.email_provider = Some(Arc::new(provider));
        self
    }

    /// Add a custom middleware.
    pub fn middleware<M: Middleware + 'static>(mut self, mw: M) -> Self {
        self.custom_middlewares.push(Box::new(mw));
        self
    }

    /// Build the BetterAuth instance.
    pub async fn build(mut self) -> AuthResult<BetterAuth<S>> {
        self.config.resolve_secrets()?;

        let capabilities = better_auth_core::store::StoreCapabilities {
            database: self.store.is_some(),
            secondary: self.secondary_storage.is_some(),
        };
        self.config.resolve_storage_defaults(capabilities);
        let config = Arc::new(self.config);
        let store = self
            .store
            .or_else(|| self.ephemeral_store.map(|create| create(config.clone())))
            .ok_or_else(|| AuthError::config("Auth store not configured"))?;

        let mut init_context = AuthInitContext::new(config.clone(), store.clone());
        init_context.initialize_request_context().await?;
        init_context.extensions.insert(capabilities);
        init_context
            .extensions
            .insert(self.csrf_config.clone().unwrap_or_default());
        init_context.secondary_storage = self.secondary_storage;
        let has_api_error_handler = self.api_error_handler.is_some();
        if let Some(callback) = self.api_error_handler {
            init_context.extensions.insert(callback);
        }
        if let Some(callback) = self.validate_user_info {
            init_context.extensions.insert(callback);
        }

        for plugin in &self.plugins {
            if let Some(hasher) = plugin.password_hasher() {
                init_context.password_policy.hasher = Some(hasher);
            }
        }

        let telemetry = better_auth_api::observability::initialize_telemetry(&init_context.config);
        if telemetry.enabled() {
            let payload = super::telemetry::init_payload(
                &config,
                &self.plugins,
                super::telemetry::InitOptions {
                    database: capabilities.database,
                    adapter: store.adapter_id(),
                    before: self.hooks.before.is_some(),
                    after: self.hooks.after.is_some(),
                    secondary: init_context.secondary_storage.is_some(),
                    on_error: has_api_error_handler,
                    rate_limit: self.rate_limit_config.as_ref(),
                    rate_limit_model: store.rate_limit_model_declaration(),
                    database_hooks: store.database_hook_metadata(),
                },
            )?;
            super::telemetry::start_init(telemetry.clone(), payload).await?;
        }
        init_context.extensions.insert(telemetry);

        // Initialize all plugins.
        let mut registered_model_fields = Vec::with_capacity(self.plugins.len());
        for plugin in &self.plugins {
            plugin.on_init(&mut init_context).await?;
            registered_model_fields.push(init_context.take_registered_model_field_names());
        }

        let config = init_context.config.clone();
        let mut init_parts = init_context.into_parts();
        let mut context = AuthContext::new(config.clone(), store.clone());
        init_parts.apply_request_runtime(&mut context);
        let (adapter_config, endpoint_config, mut model_fields) =
            init_parts.plugin_fields.resolve(&config);
        let adapter_fields = adapter_config.user.clone();
        let adapter_config = Arc::new(adapter_config);
        let rate_limit_config = self.rate_limit_config.unwrap_or_default();
        let schema_configuration = better_auth_core::store::schema::SchemaConfiguration {
            config: adapter_config.clone(),
            plugins: self.plugins.iter().map(|plugin| plugin.name()).collect(),
            metadata: init_parts.metadata.clone(),
            secondary_storage: init_parts.secondary_storage.is_some(),
            database_rate_limit: rate_limit_config.storage
                == Some(better_auth_core::middleware::RateLimitStorageKind::Database),
        };
        model_fields.set_schema_configuration(&schema_configuration);
        let openapi_fields = model_fields.clone();
        let store = store.with_runtime(
            adapter_config.clone(),
            init_parts.database_hooks,
            model_fields,
        )?;
        let config = Arc::new(endpoint_config);
        init_parts
            .extensions
            .insert(better_auth_core::plugin_runtime::AdapterUserFields(
                adapter_fields,
            ));

        let schema_check = store.schema_check(&schema_configuration)?;
        let schema_validation =
            schema_check.map(|check| better_auth_core::store::schema::SchemaValidation {
                check,
                runtime_enabled: config.advanced.database.validate_schema != Some(false),
            });
        if schema_validation.is_none() {
            match config.advanced.database.validate_schema {
                Some(true) => tracing::warn!(
                    "The database adapter does not support runtime schema validation"
                ),
                None => tracing::debug!(
                    "The database adapter does not support runtime schema validation"
                ),
                Some(false) => {}
            }
        }

        let store: Arc<dyn AuthStore<S>> = if let Some(secondary) = &init_parts.secondary_storage {
            Arc::new(
                better_auth_core::store::secondary::SecondaryStore::new(
                    store,
                    secondary.clone(),
                    adapter_config.clone(),
                    init_parts.metadata.clone(),
                )?
                .with_schema_validation(schema_validation.clone()),
            )
        } else {
            Arc::new(
                better_auth_core::store::secondary::SecondaryStore::without_secondary(
                    store,
                    adapter_config.clone(),
                    init_parts.metadata.clone(),
                )
                .with_schema_validation(schema_validation.clone()),
            )
        };

        let openapi = OpenApiRegistry::new(
            &adapter_config,
            &config.user,
            self.plugins
                .iter()
                .zip(registered_model_fields)
                .map(|(plugin, groups)| {
                    plugin
                        .openapi()
                        .map(|metadata| metadata.registered_field_names(groups))
                })
                .collect::<AuthResult<Vec<_>>>()?,
            init_parts.secondary_storage.is_some(),
            rate_limit_config.storage == Some(better_auth_core::RateLimitStorageKind::Database),
            &openapi_fields,
        )?;
        init_parts.extensions.insert(openapi);

        let plugins = Arc::new(self.plugins);
        init_parts.extensions.insert(Arc::new(
            better_auth_core::endpoint_dispatch::EndpointDispatcher::new(
                plugins.clone(),
                self.hooks,
                core_routes(),
            ),
        ));
        // Create context
        context.config = config.clone();
        context.database = store.clone();
        context.metadata = init_parts.metadata;
        context.password_policy = init_parts.password_policy;
        context.secondary_storage = init_parts.secondary_storage;
        context.extensions = init_parts.extensions;
        context.email_verification_policy = init_parts.email_verification_policy;
        let context = Arc::new(context);
        init_parts.runtime.bind(&context)?;
        if let Some(validation) = &schema_validation {
            validation.start();
        }
        let session_manager = context.session_manager();

        let body_limit = self.body_limit_config.unwrap_or_default();
        let mut plugin_limits = Vec::new();
        for plugin in plugins.iter() {
            plugin_limits.extend(plugin.rate_limits()?);
        }

        // HTTP plugins run after rate limiting but before endpoint origin and body checks.
        config.advanced.ip_address.warn_invalid_proxies();
        let http_middlewares: Vec<Box<dyn Middleware>> = vec![
            Box::new(BodyLimitMiddleware::new(body_limit.clone())),
            Box::new(RateLimitMiddleware::from_context(
                rate_limit_config,
                &context,
                plugin_limits,
            )),
        ];
        let mut middlewares: Vec<Box<dyn Middleware>> = vec![Box::new(CorsMiddleware::new(
            self.cors_config.unwrap_or_default(),
        ))];

        middlewares.extend(self.custom_middlewares);

        Ok(BetterAuth {
            config,
            plugins,
            middlewares,
            http_middlewares,
            body_limit,
            store,
            session_manager,
            context,
        })
    }
}

impl BetterAuth<better_auth_core::store::StatelessSchema> {
    /// Configure authentication without an application database schema.
    /// Process-local records do not make cookie sessions server-authoritative.
    pub fn stateless(config: AuthConfig) -> AuthBuilder<better_auth_core::store::StatelessSchema> {
        AuthBuilder::new(config).database_hooks(Vec::new())
    }
}

impl AuthBuilder<better_auth_core::store::StatelessSchema> {
    /// Install database lifecycle hooks on the process-local adapter.
    /// An explicit `store` uses that adapter's own hook configuration instead.
    pub fn database_hooks(
        mut self,
        hooks: Vec<
            Arc<
                dyn better_auth_core::store::database_hooks::DatabaseHooks<
                        better_auth_core::store::StatelessSchema,
                    >,
            >,
        >,
    ) -> Self {
        self.ephemeral_store = Some(Box::new(move |config| {
            Arc::new(better_auth_core::store::EphemeralStore::new(config).with_hooks(hooks))
        }));
        self
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Create a new BetterAuth builder.
    #[expect(
        clippy::new_ret_no_self,
        reason = "returns AuthBuilder by design — builder pattern entry point"
    )]
    pub fn new(config: AuthConfig) -> AuthBuilder<S> {
        AuthBuilder::new(config)
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Handle an authentication request.
    ///
    /// Endpoint API errors retain their public body and headers. Ordinary endpoint
    /// failures return an empty 500. HTTP request-hook failures propagate to the host.
    pub async fn handle_request(&self, req: AuthRequest) -> AuthResult<AuthResponse> {
        // Ignore any caller-supplied virtual session value; only internal
        // before_request hooks may inject this during dispatch.
        let url = req.url().cloned();
        let mounted = req.base_relative_path().is_some();
        let query = req.query.or_else(|| {
            Some(better_auth_core::query::parse_url_query(
                url.as_ref().and_then(|url| url.query()).unwrap_or_default(),
            ))
        });
        let mut req = AuthRequest::from_parts(req.method, req.path, req.headers, req.body, query);
        if mounted {
            req = req.with_base_relative_path();
        }
        if let Some(url) = url {
            req = req.with_url(url);
        }

        let mut request_context = RequestHookContext::from_request(&req);
        request_context.is_http = true;
        request_context.meta = better_auth_core::RequestMeta::from_request_with_config(
            &req,
            &self.config.advanced.ip_address,
        );
        let original = req.clone();
        self.context
            .with_http_context(&original, |context| async move {
                with_request_hook_context_value(request_context, async {
                    if let Some(response) = self.handle_http_phase(&req, &context).await? {
                        return middleware::run_after(&self.middlewares, &req, response).await;
                    }
                    let original_request = req.clone();
                    let response = match self.parse_endpoint_http_body(&mut req, &context) {
                        Ok(Some(response)) => response,
                        Err(error) => {
                            better_auth_core::api_error::handle_http_error(error, &context).await?
                        }
                        Ok(None) => match self.dispatch_endpoint(&mut req, true, &context).await {
                            Ok(response) => response,
                            Err(error) => {
                                better_auth_core::api_error::handle_http_error(error, &context)
                                    .await?
                            }
                        },
                    };
                    self.finish_http_response(&original_request, response, &context)
                        .await
                })
                .await
            })
            .await
    }

    async fn handle_http_phase(
        &self,
        req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let path = super::http_routing::disabled_path(req, context.base_path());
        if context.config.is_path_disabled(path) {
            return Ok(Some(
                AuthResponse::text(404, "Not Found")
                    .with_header("content-type", "text/plain;charset=UTF-8"),
            ));
        }
        if let Some(validation) = context.database.schema_validation() {
            validation.check_runtime().await?;
        }
        if let Some(response) = middleware::run_before(&self.http_middlewares, req).await? {
            return Ok(Some(response));
        }
        for plugin in self.plugins.iter() {
            if let Some(response) = plugin.on_http_request(req, context).await? {
                return Ok(Some(response));
            }
        }
        Ok(None)
    }

    async fn finish_http_response(
        &self,
        request: &AuthRequest,
        mut response: AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        for plugin in self.plugins.iter() {
            if let Some(replacement) = plugin
                .on_http_response(request, &mut response, context)
                .await?
            {
                response = replacement;
                break;
            }
        }
        middleware::run_after(&self.middlewares, request, response).await
    }

    fn parse_endpoint_http_body(
        &self,
        req: &mut AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let Some(path) = super::http_routing::route_path(req, context.base_path()) else {
            return Ok(Some(AuthResponse::new(404)));
        };
        let selected = core_routes()
            .into_iter()
            .chain(self.plugins.iter().flat_map(|plugin| plugin.routes()))
            .find_map(|route| {
                super::http_routing::matched_path(
                    &route,
                    req.method(),
                    path,
                    context.config.advanced.skip_trailing_slashes,
                )
                .map(|path| (route, path))
            });
        let Some((route, path)) = selected else {
            return Ok(Some(AuthResponse::new(404)));
        };
        set_request_hook_route(&path, Some(&route));
        // Dispatch uses the matched declaration's slash shape. Keep the transport URL unchanged.
        req.path = path;
        let allowed = if route.allowed_media_types.is_empty() {
            vec!["application/json".to_owned()]
        } else {
            route.allowed_media_types
        };
        req.parse_http_body(&allowed)?;
        Ok(None)
    }

    pub(crate) async fn dispatch_endpoint(
        &self,
        req: &mut AuthRequest,
        http: bool,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        use better_auth_core::observability::{SpanAttributes, with_span};
        let snapshot = better_auth_core::hooks::current_request_hook_context();
        let route = snapshot.as_ref().map_or_else(
            || req.path().to_owned(),
            |snapshot| snapshot.path.clone().unwrap_or_else(|| "/:virtual".into()),
        );
        let operation_id = snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.operation_id.as_deref())
            .unwrap_or(&route);
        let method = match req.method() {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Head => "HEAD",
        };
        with_span(
            &context.config.experimental.instrumentation,
            &format!("{method} {route}"),
            SpanAttributes {
                route: Some(&route),
                operation_id: Some(operation_id),
                ..Default::default()
            },
            self.dispatch_endpoint_inner(req, http, context),
        )
        .await
    }

    async fn dispatch_endpoint_inner(
        &self,
        req: &mut AuthRequest,
        http: bool,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        if http {
            let csrf = CsrfMiddleware::from_context(
                context
                    .extensions
                    .get::<CsrfConfig>()
                    .cloned()
                    .unwrap_or_default(),
                context,
            );
            if let Some(mut response) = csrf.before_request(req).await? {
                response.headers.merge(req.take_response_headers()?);
                return Ok(response);
            }
            match middleware::run_before(&self.middlewares, req).await {
                Ok(Some(mut response)) => {
                    response.headers.merge(req.take_response_headers()?);
                    return Ok(response);
                }
                Err(error) => return Err(endpoint_error(error, req)?),
                Ok(None) => {}
            }
        }

        context
            .extensions
            .get::<Arc<better_auth_core::endpoint_dispatch::EndpointDispatcher<S>>>()
            .ok_or_else(|| AuthError::config("Endpoint dispatcher is not initialized"))?
            .run(req, http, context, None, |request| async move {
                self.execute_endpoint(&request, context).await
            })
            .await
    }

    async fn execute_endpoint(
        &self,
        internal_req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        // Handle core endpoints first
        if let Some(response) = self.handle_core_request(internal_req, context).await? {
            return Ok(response);
        }

        // Try each plugin until one handles the request
        for plugin in self.plugins.iter() {
            if let Some(response) = plugin.on_request(internal_req, context).await? {
                return Ok(response);
            }
        }

        // No handler found
        Err(AuthError::not_found("No handler found for this request"))
    }

    /// Get the configuration.
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Return the initialized context for server-only plugin APIs.
    ///
    /// The context includes metadata registered by every installed plugin.
    pub fn context(&self) -> &AuthContext<S> {
        &self.context
    }

    /// Get the shared auth store used by Better Auth.
    pub fn store(&self) -> &Arc<dyn AuthStore<S>> {
        &self.store
    }

    /// Get the effective request body size limit.
    ///
    /// Transports read the body before any middleware runs, so they need this
    /// to bound the read itself rather than rejecting after buffering.
    pub fn body_limit(&self) -> &BodyLimitConfig {
        &self.body_limit
    }

    /// Get the session manager.
    pub fn session_manager(&self) -> &SessionManager<S> {
        &self.session_manager
    }

    /// Get all routes from plugins.
    pub fn routes(&self) -> Vec<(String, &dyn AuthPlugin<S>)> {
        let mut routes = Vec::new();
        for plugin in self.plugins.iter() {
            for route in plugin.routes() {
                routes.push((route.path, plugin.as_ref()));
            }
        }
        routes
    }

    /// Get all plugins.
    pub fn plugins(&self) -> &[Box<dyn AuthPlugin<S>>] {
        &self.plugins
    }

    /// Get plugin by name.
    pub fn get_plugin(&self, name: &str) -> Option<&dyn AuthPlugin<S>> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// List all plugin names.
    pub fn plugin_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }

    /// Generate documentation for the configured instance and its initialized base URL.
    pub fn openapi_spec(&self) -> AuthResult<OpenApiSpec> {
        self.context
            .extensions
            .get::<OpenApiRegistry>()
            .map(|registry| registry.generate(self.context.base_url()))
            .ok_or_else(|| AuthError::config("OpenAPI registry is not initialized"))
    }

    /// Handle core authentication requests.
    async fn handle_core_request(
        &self,
        req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, core_paths::OK) => {
                Ok(Some(AuthResponse::json(200, &OkResponse { ok: true })?))
            }
            (HttpMethod::Get, core_paths::ERROR) => Ok(Some(context.error_page_response(req)?)),
            (HttpMethod::Get, core_paths::OPENAPI_SPEC) => {
                let spec = context
                    .extensions
                    .get::<OpenApiRegistry>()
                    .ok_or_else(|| AuthError::config("OpenAPI registry is not initialized"))?
                    .generate(context.base_url());
                Ok(Some(AuthResponse::json(200, &spec)?))
            }
            (HttpMethod::Post, core_paths::UPDATE_USER) => {
                Ok(Some(self.handle_update_user(req, context).await?))
            }
            _ => Ok(None),
        }
    }

    /// Handle user profile update.
    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let mut body = better_auth_core::endpoint_input::record_input(req)?;
        let (current_user, session) =
            context
                .require_session(req)
                .await
                .map_err(|error| match error {
                    AuthError::Unauthenticated => AuthError::Upstream {
                        status: 401,
                        code: "UNAUTHORIZED",
                        message: "Unauthorized",
                    },
                    error => error,
                })?;

        if body
            .get("email")
            .is_some_and(better_auth_core::user_fields::is_truthy)
        {
            return Err(AuthError::bad_request("Email can not be updated"));
        }
        let _ = body.remove("email");

        let clear_phone_number = context.get_metadata("phone-number.enabled")
            == Some(&serde_json::Value::Bool(true))
            && body.get("phoneNumber") == Some(&serde_json::Value::Null);
        let name = better_auth_core::SchemaValue::from_json(body.remove("name"));
        let image = better_auth_core::SchemaValue::from_json(body.remove("image"));
        let additional_fields = context.parse_user_input(&body, false)?;

        let has_changes = clear_phone_number
            || !name.is_undefined()
            || !image.is_undefined()
            || !additional_fields.is_empty();
        if !has_changes {
            return Err(AuthError::bad_request("No fields to update"));
        }

        let mut update_user = UpdateUser {
            additional_fields: Default::default(),
            email: None,
            name,
            image,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            is_anonymous: None,
            phone_number: clear_phone_number.then_some(None),
            phone_number_verified: clear_phone_number.then_some(false),
            metadata: None,
        };

        update_user.assign_user_fields(additional_fields)?;
        let mut fallback = current_user.clone();
        if !update_user.name.is_undefined() {
            fallback.name = update_user.name.clone();
        }
        if !update_user.image.is_undefined() {
            fallback.image = update_user.image.clone();
        }
        if let Some(fields) = &mut fallback.visible_fields {
            if !update_user.name.is_undefined() {
                let _ = fields.insert("name".into());
            }
            if !update_user.image.is_undefined() {
                let _ = fields.insert("image".into());
            }
        }
        fallback
            .additional_fields
            .extend(update_user.additional_fields.clone());
        let user = self
            .store
            .update_user_optional(current_user.id().typed()?, update_user)
            .await?
            .unwrap_or(fallback);
        context
            .session_manager()
            .set_session_cookie(
                req,
                better_auth_core::session::SessionData {
                    user: context.internal_user_view(&user).await?,
                    session,
                },
                None,
            )
            .await?;
        Ok(AuthResponse::json(
            200,
            &better_auth_core::StatusResponse { status: true },
        )?)
    }
}
