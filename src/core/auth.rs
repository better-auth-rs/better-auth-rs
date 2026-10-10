use std::sync::Arc;

use better_auth_core::utils::username::{
    UsernameValidationError, normalize_username_fields, validate_username,
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthSchema, AuthStore, BeforeRequestAction, EmailProvider,
    ErrorCodeMessageResponse, HttpMethod, OkResponse, OpenApiBuilder, OpenApiSpec, SessionManager,
    UpdateUser, UpdateUserRequest, core_paths,
    entity::AuthUser,
    hooks::{RequestHookContext, with_request_hook_context_value},
    middleware::{
        self, BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig,
        CsrfMiddleware, Middleware, RateLimitConfig, RateLimitMiddleware,
    },
};

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: Some(code.to_string()),
            message: message.to_string(),
        },
    )
    .map_err(AuthError::from)
}

/// Whether the body claims JSON (better-call's `application/(...+)?json`) and isn't.
fn malformed_json(req: &AuthRequest) -> bool {
    let Some(body) = req.body.as_deref().filter(|body| !body.is_empty()) else {
        return false;
    };
    let content_type = req
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    let Some(subtype) = content_type.strip_prefix("application/") else {
        return false;
    };
    let json = subtype.starts_with("json")
        || subtype.split_once("+json").is_some_and(|(suffix, _)| {
            suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
        });
    json && serde_json::from_slice::<serde::de::IgnoredAny>(body).is_err()
}

pub struct BetterAuth<S: AuthSchema> {
    config: Arc<AuthConfig>,
    plugins: Vec<Box<dyn AuthPlugin<S>>>,
    middlewares: Vec<Box<dyn Middleware>>,
    body_limit: BodyLimitConfig,
    store: Arc<dyn AuthStore<S>>,
    session_manager: SessionManager<S>,
    context: AuthContext<S>,
}

/// Initial builder for configuring BetterAuth.
pub struct AuthBuilder<S: AuthSchema> {
    config: AuthConfig,
    store: Option<Arc<dyn AuthStore<S>>>,
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
            store: None,
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
    pub async fn build(self) -> AuthResult<BetterAuth<S>> {
        // Validate configuration
        self.config.validate()?;

        let config = Arc::new(self.config);
        let store = self
            .store
            .ok_or_else(|| AuthError::config("Auth store not configured"))?;

        let mut init_context = AuthInitContext::new(config.clone(), store.clone());

        // Initialize all plugins.
        for plugin in &self.plugins {
            plugin.on_init(&mut init_context).await?;
        }

        let init_parts = init_context.into_parts();

        // Create session manager
        let session_manager = SessionManager::new(config.clone(), store.clone());

        // Create context
        let context =
            AuthContext::with_metadata(config.clone(), store.clone(), init_parts.metadata);

        let body_limit = self.body_limit_config.unwrap_or_default();
        let mut rate_limit_config = self.rate_limit_config.unwrap_or_default();
        for plugin in &self.plugins {
            for (path, limit) in plugin.rate_limits()? {
                let _ = rate_limit_config.per_endpoint.entry(path).or_insert(limit);
            }
        }
        // Middleware receives the public path before the router removes the base path.
        for (path, limit) in rate_limit_config.per_endpoint.clone() {
            let public_path = format!("{}{}", config.base_path.trim_end_matches('/'), path);
            let _ = rate_limit_config
                .per_endpoint
                .entry(public_path)
                .or_insert(limit);
        }

        // Build middleware chain (order matters: body limit → rate limit → CSRF → CORS → custom)
        let mut middlewares: Vec<Box<dyn Middleware>> = vec![
            Box::new(BodyLimitMiddleware::new(body_limit.clone())),
            Box::new(RateLimitMiddleware::new(rate_limit_config)),
            Box::new(CsrfMiddleware::new(
                self.csrf_config.unwrap_or_default(),
                config.clone(),
            )),
            Box::new(CorsMiddleware::new(self.cors_config.unwrap_or_default())),
        ];

        middlewares.extend(self.custom_middlewares);

        Ok(BetterAuth {
            config,
            plugins: self.plugins,
            middlewares,
            body_limit,
            store,
            session_manager,
            context,
        })
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
    /// Errors from plugins and core handlers are automatically converted
    /// into standardized JSON responses via [`AuthError::to_auth_response`],
    /// producing `{ "message": "..." }` with the appropriate HTTP status code.
    pub async fn handle_request(&self, req: AuthRequest) -> AuthResult<AuthResponse> {
        // Ignore any caller-supplied virtual session value; only internal
        // before_request hooks may inject this during dispatch.
        let mut req =
            AuthRequest::from_parts(req.method, req.path, req.headers, req.body, req.query);

        let request_context = RequestHookContext::from_request(&req);
        with_request_hook_context_value(request_context, async {
            let mut response = match self.handle_request_inner(&mut req).await {
                Ok(response) => response,
                Err(error) => error.to_auth_response(),
            };
            self.session_manager
                .finish_response(&req, &mut response)
                .await?;
            middleware::run_after(&self.middlewares, &req, response).await
        })
        .await
    }

    /// Inner request handler that may return errors.
    async fn handle_request_inner(&self, req: &mut AuthRequest) -> AuthResult<AuthResponse> {
        // better-call parses the body in its router, before any endpoint middleware, so a
        // malformed JSON body is refused before the origin and CSRF checks.
        if malformed_json(req) {
            return Err(AuthError::Upstream {
                status: 400,
                code: "BAD_REQUEST",
                message: "Invalid JSON in request body",
            });
        }

        // Run before-request middleware chain
        if let Some(response) = middleware::run_before(&self.middlewares, req).await? {
            return Ok(response);
        }

        // Strip base_path prefix from the request path for internal routing.
        // This happens BEFORE plugin hooks so that `before_request` sees the
        // same normalised path that `on_request` / core handlers use.
        // External callers send e.g. "/api/auth/sign-in/email"; internally
        // handlers match against "/sign-in/email".
        let base_path = &self.config.base_path;
        let stripped_path = if !base_path.is_empty() && base_path != "/" {
            req.path().strip_prefix(base_path).unwrap_or(req.path())
        } else {
            req.path()
        };

        // Build a request with the stripped path for all subsequent dispatch
        let mut internal_req = if stripped_path != req.path() {
            let mut r = req.clone();
            r.path = stripped_path.to_string();
            r
        } else {
            req.clone()
        };

        // Check if this path is disabled
        if self.config.is_path_disabled(internal_req.path()) {
            return Err(AuthError::not_found("This endpoint has been disabled"));
        }

        // Run plugin before_request hooks (e.g. API-key → session emulation)
        // Plugins now see the normalised (base_path-stripped) path.
        for plugin in &self.plugins {
            if let Some(action) = plugin.before_request(&internal_req, &self.context).await? {
                match action {
                    BeforeRequestAction::Respond(response) => {
                        return Ok(response);
                    }
                    BeforeRequestAction::InjectSession { session } => {
                        internal_req.set_virtual_session(*session);
                    }
                }
            }
        }

        // Handle core endpoints first
        if let Some(response) = self.handle_core_request(&internal_req).await? {
            return Ok(response);
        }

        // Try each plugin until one handles the request
        for plugin in &self.plugins {
            if let Some(response) = plugin.on_request(&internal_req, &self.context).await? {
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
        for plugin in &self.plugins {
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

    /// Generate the OpenAPI spec for all registered routes.
    pub fn openapi_spec(&self) -> OpenApiSpec {
        let mut builder = OpenApiBuilder::new("Better Auth", env!("CARGO_PKG_VERSION"))
            .description("Authentication API")
            .core_routes();

        for plugin in &self.plugins {
            builder = builder.plugin(plugin.as_ref());
        }

        builder.build()
    }

    /// Handle core authentication requests.
    async fn handle_core_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, core_paths::OK) => {
                Ok(Some(AuthResponse::json(200, &OkResponse { ok: true })?))
            }
            (HttpMethod::Get, core_paths::ERROR) => {
                let error_code = req
                    .query
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                let error_description = req.query.get("error_description").map(String::as_str);
                let html = better_auth_core::config::core_paths::error_page_html_with_description(
                    &error_code,
                    error_description,
                );
                Ok(Some(AuthResponse::html(200, html)))
            }
            (HttpMethod::Get, core_paths::OPENAPI_SPEC) => {
                let spec = self.openapi_spec();
                Ok(Some(AuthResponse::json(200, &spec)?))
            }
            (HttpMethod::Post, core_paths::UPDATE_USER) => {
                Ok(Some(self.handle_update_user(req).await?))
            }
            _ => Ok(None),
        }
    }

    /// Handle user profile update.
    async fn handle_update_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        let current_user = self.extract_current_user(req).await?;
        let body: serde_json::Value = req
            .body_as_json()
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;
        let body = match body.as_object() {
            Some(body) => body,
            None => {
                let actual = match &body {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "record",
                };
                return Ok(AuthResponse::json(
                    400,
                    &better_auth_core::ErrorCodeMessageResponse {
                        code: Some("VALIDATION_ERROR".to_string()),
                        message: format!(
                            "[body] Invalid input: expected record, received {}",
                            actual
                        ),
                    },
                )?);
            }
        };

        if body.contains_key("email") {
            return Err(AuthError::bad_request("Email can not be updated"));
        }

        let mut body = body.clone();
        if self.context.get_metadata("username.enabled") != Some(&serde_json::Value::Bool(true)) {
            _ = body.remove("username");
            _ = body.remove("displayUsername");
        }
        let update_req: UpdateUserRequest = serde_json::from_value(serde_json::Value::Object(body))
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;
        let (username, display_username) =
            normalize_username_fields(update_req.username, update_req.display_username);

        if let Some(username) = username.as_deref() {
            match validate_username(username) {
                Ok(()) => {}
                Err(UsernameValidationError::TooShort) => {
                    return username_error_response(
                        400,
                        "USERNAME_TOO_SHORT",
                        "Username is too short",
                    );
                }
                Err(UsernameValidationError::TooLong) => {
                    return username_error_response(
                        400,
                        "USERNAME_TOO_LONG",
                        "Username is too long",
                    );
                }
                Err(UsernameValidationError::Invalid) => {
                    return username_error_response(400, "INVALID_USERNAME", "Username is invalid");
                }
            }

            if let Some(existing_user) = self.store.get_user_by_username(username).await?
                && existing_user.id() != current_user.id()
            {
                return username_error_response(
                    400,
                    "USERNAME_IS_ALREADY_TAKEN",
                    "Username is already taken. Please try another.",
                );
            }
        }

        let has_changes = update_req.name.is_some()
            || update_req.image.is_some()
            || username.is_some()
            || display_username.is_some()
            || update_req.role.is_some()
            || update_req.metadata.is_some();
        if !has_changes {
            return Err(AuthError::bad_request("No fields to update"));
        }

        let update_user = UpdateUser {
            email: None,
            name: update_req.name,
            image: update_req.image,
            email_verified: None,
            username,
            display_username,
            role: update_req.role,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: update_req.metadata,
        };

        _ = self
            .store
            .update_user(&current_user.id(), update_user)
            .await?;

        let mut response =
            AuthResponse::json(200, &better_auth_core::StatusResponse { status: true })?;

        if let Some(token) = self.session_manager.extract_session_token(req) {
            let cookie_header =
                better_auth_core::utils::cookie_utils::create_session_cookie(&token, &self.config);
            response = response.with_header("Set-Cookie", cookie_header);
        }

        Ok(response)
    }

    /// Resolve the authoritative user for a profile update.
    async fn extract_current_user(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.context
            .require_authoritative_session(req)
            .await
            .map(|(user, _)| user)
    }
}
