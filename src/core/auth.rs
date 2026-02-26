use std::sync::Arc;

use serde::Deserialize;

use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    BeforeRequestAction, DatabaseAdapter, DatabaseHooks, DeleteUserResponse, EmailProvider,
    HttpMethod, OkResponse, OpenApiBuilder, OpenApiSpec, SessionManager, StatusMessageResponse,
    StatusResponse, UpdateUser, UpdateUserRequest,
    entity::{AuthAccount, AuthSession, AuthUser, AuthVerification},
    middleware::{
        self, BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig,
        CsrfMiddleware, Middleware, RateLimitConfig, RateLimitMiddleware,
    },
};

#[derive(Debug, Deserialize)]
struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    new_email: String,
}

/// The main BetterAuth instance, generic over the database adapter.
pub struct BetterAuth<DB: DatabaseAdapter> {
    config: Arc<AuthConfig>,
    plugins: Vec<Box<dyn AuthPlugin<DB>>>,
    middlewares: Vec<Box<dyn Middleware>>,
    database: Arc<DB>,
    session_manager: SessionManager<DB>,
    context: AuthContext<DB>,
}

/// Initial builder for configuring BetterAuth.
///
/// Call `.database(adapter)` to obtain a [`TypedAuthBuilder`] that can
/// accept plugins and hooks.
pub struct AuthBuilder {
    config: AuthConfig,
    csrf_config: Option<CsrfConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    cors_config: Option<CorsConfig>,
    body_limit_config: Option<BodyLimitConfig>,
    custom_middlewares: Vec<Box<dyn Middleware>>,
}

/// Typed builder returned by [`AuthBuilder::database`].
///
/// Accepts plugins, hooks, and middleware before calling `.build()`.
pub struct TypedAuthBuilder<DB: DatabaseAdapter> {
    config: AuthConfig,
    database: Arc<DB>,
    plugins: Vec<Box<dyn AuthPlugin<DB>>>,
    hooks: Vec<Arc<dyn DatabaseHooks<DB>>>,
    csrf_config: Option<CsrfConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    cors_config: Option<CorsConfig>,
    body_limit_config: Option<BodyLimitConfig>,
    custom_middlewares: Vec<Box<dyn Middleware>>,
}

impl AuthBuilder {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            csrf_config: None,
            rate_limit_config: None,
            cors_config: None,
            body_limit_config: None,
            custom_middlewares: Vec::new(),
        }
    }

    /// Set the database adapter, returning a [`TypedAuthBuilder`].
    pub fn database<DB: DatabaseAdapter>(self, database: DB) -> TypedAuthBuilder<DB> {
        TypedAuthBuilder {
            config: self.config,
            database: Arc::new(database),
            plugins: Vec::new(),
            hooks: Vec::new(),
            csrf_config: self.csrf_config,
            rate_limit_config: self.rate_limit_config,
            cors_config: self.cors_config,
            body_limit_config: self.body_limit_config,
            custom_middlewares: self.custom_middlewares,
        }
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
}

impl<DB: DatabaseAdapter> TypedAuthBuilder<DB> {
    /// Add a plugin to the authentication system.
    pub fn plugin<P: AuthPlugin<DB> + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Add a database lifecycle hook.
    pub fn hook<H: DatabaseHooks<DB> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
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

    /// Set the email provider for sending emails.
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
    pub async fn build(self) -> AuthResult<BetterAuth<DB>> {
        // Validate configuration
        self.config.validate()?;

        let config = Arc::new(self.config);

        // If hooks are registered, the user should wrap the adapter themselves:
        //   let db = HookedDatabaseAdapter::new(Arc::new(my_db)).with_hook(hook);
        //   BetterAuth::new(config).database(db).plugin(...).build().await
        if !self.hooks.is_empty() {
            return Err(AuthError::config(
                "Use HookedDatabaseAdapter directly: \
                 BetterAuth::new(config).database(HookedDatabaseAdapter::new(Arc::new(db)).with_hook(h))",
            ));
        }

        let database = self.database;

        // Create session manager
        let session_manager = SessionManager::new(config.clone(), database.clone());

        // Create context
        let mut context = AuthContext::new(config.clone(), database.clone());

        // Initialize all plugins
        for plugin in &self.plugins {
            plugin.on_init(&mut context).await?;
        }

        // Build middleware chain (order matters: body limit → rate limit → CSRF → CORS → custom)
        let mut middlewares: Vec<Box<dyn Middleware>> = vec![
            Box::new(BodyLimitMiddleware::new(
                self.body_limit_config.unwrap_or_default(),
            )),
            Box::new(RateLimitMiddleware::new(
                self.rate_limit_config.unwrap_or_default(),
            )),
            Box::new(CsrfMiddleware::new(
                self.csrf_config.unwrap_or_default(),
                &config.base_url,
            )),
            Box::new(CorsMiddleware::new(self.cors_config.unwrap_or_default())),
        ];

        middlewares.extend(self.custom_middlewares);

        Ok(BetterAuth {
            config,
            plugins: self.plugins,
            middlewares,
            database,
            session_manager,
            context,
        })
    }
}

impl<DB: DatabaseAdapter> BetterAuth<DB> {
    /// Create a new BetterAuth builder.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(config: AuthConfig) -> AuthBuilder {
        AuthBuilder::new(config)
    }

    /// Handle an authentication request.
    ///
    /// Errors from plugins and core handlers are automatically converted
    /// into standardized JSON responses via [`AuthError::into_response`],
    /// producing `{ "message": "..." }` with the appropriate HTTP status code.
    pub async fn handle_request(&self, mut req: AuthRequest) -> AuthResult<AuthResponse> {
        match self.handle_request_inner(&mut req).await {
            Ok(response) => {
                // Run after-request middleware chain
                middleware::run_after(&self.middlewares, &req, response).await
            }
            Err(err) => {
                // Convert error to standardized response, then run after-middleware
                let response = err.into_response();
                middleware::run_after(&self.middlewares, &req, response).await
            }
        }
    }

    /// Inner request handler that may return errors.
    async fn handle_request_inner(&self, req: &mut AuthRequest) -> AuthResult<AuthResponse> {
        // Run before-request middleware chain
        if let Some(response) = middleware::run_before(&self.middlewares, req).await? {
            return Ok(response);
        }

        // Run plugin before_request hooks (e.g. API-key → session emulation)
        for plugin in &self.plugins {
            if let Some(action) = plugin.before_request(req, &self.context).await? {
                match action {
                    BeforeRequestAction::Respond(response) => {
                        return Ok(response);
                    }
                    BeforeRequestAction::InjectSession {
                        user_id,
                        session_token: _,
                    } => {
                        // Set the virtual user id on the request so that
                        // `extract_current_user` can resolve the user without
                        // creating a real database session.  This mirrors the
                        // TypeScript `ctx.context.session` virtual-session
                        // approach — no DB writes on every API-key request.
                        req.virtual_user_id = Some(user_id);
                    }
                }
            }
        }

        // Handle core endpoints first
        if let Some(response) = self.handle_core_request(req).await? {
            return Ok(response);
        }

        // Try each plugin until one handles the request
        for plugin in &self.plugins {
            if let Some(response) = plugin.on_request(req, &self.context).await? {
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

    /// Get the database adapter.
    pub fn database(&self) -> &Arc<DB> {
        &self.database
    }

    /// Get the session manager.
    pub fn session_manager(&self) -> &SessionManager<DB> {
        &self.session_manager
    }

    /// Get all routes from plugins.
    pub fn routes(&self) -> Vec<(String, &dyn AuthPlugin<DB>)> {
        let mut routes = Vec::new();
        for plugin in &self.plugins {
            for route in plugin.routes() {
                routes.push((route.path, plugin.as_ref()));
            }
        }
        routes
    }

    /// Get all plugins.
    pub fn plugins(&self) -> &[Box<dyn AuthPlugin<DB>>] {
        &self.plugins
    }

    /// Get plugin by name.
    pub fn get_plugin(&self, name: &str) -> Option<&dyn AuthPlugin<DB>> {
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
            (HttpMethod::Get, "/ok") => {
                Ok(Some(AuthResponse::json(200, &OkResponse { ok: true })?))
            }
            (HttpMethod::Get, "/error") => {
                Ok(Some(AuthResponse::json(200, &OkResponse { ok: false })?))
            }
            (HttpMethod::Get, "/reference/openapi.json") => {
                let spec = self.openapi_spec();
                Ok(Some(AuthResponse::json(200, &spec)?))
            }
            (HttpMethod::Post, "/update-user") => Ok(Some(self.handle_update_user(req).await?)),
            (HttpMethod::Post | HttpMethod::Delete, "/delete-user") => {
                Ok(Some(self.handle_delete_user(req).await?))
            }
            (HttpMethod::Post, "/change-email") => Ok(Some(self.handle_change_email(req).await?)),
            (HttpMethod::Get, "/delete-user/callback") => {
                Ok(Some(self.handle_delete_user_callback(req).await?))
            }
            _ => Ok(None),
        }
    }

    /// Handle user profile update.
    async fn handle_update_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        let current_user = self.extract_current_user(req).await?;

        let update_req: UpdateUserRequest = req
            .body_as_json()
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;

        let update_user = UpdateUser {
            email: update_req.email,
            name: update_req.name,
            image: update_req.image,
            email_verified: None,
            username: update_req.username,
            display_username: update_req.display_username,
            role: update_req.role,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: update_req.metadata,
        };

        self.database
            .update_user(current_user.id(), update_user)
            .await?;

        Ok(AuthResponse::json(200, &StatusResponse { status: true })?)
    }

    /// Handle user deletion.
    async fn handle_delete_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        let current_user = self.extract_current_user(req).await?;

        self.database
            .delete_user_sessions(current_user.id())
            .await?;
        self.database.delete_user(current_user.id()).await?;

        let response = DeleteUserResponse {
            success: true,
            message: "User account successfully deleted".to_string(),
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    /// Handle email change.
    async fn handle_change_email(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        let current_user = self.extract_current_user(req).await?;

        let change_req: ChangeEmailRequest = req
            .body_as_json()
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;

        if !change_req.new_email.contains('@') || change_req.new_email.is_empty() {
            return Err(AuthError::bad_request("Invalid email address"));
        }

        if self
            .database
            .get_user_by_email(&change_req.new_email)
            .await?
            .is_some()
        {
            return Err(AuthError::conflict("A user with this email already exists"));
        }

        let update_user = UpdateUser {
            email: Some(change_req.new_email),
            name: None,
            image: None,
            email_verified: Some(false),
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: None,
        };

        self.database
            .update_user(current_user.id(), update_user)
            .await?;

        Ok(AuthResponse::json(
            200,
            &StatusMessageResponse {
                status: true,
                message: "Email updated".to_string(),
            },
        )?)
    }

    /// Handle delete-user callback (token-based deletion confirmation).
    async fn handle_delete_user_callback(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        let token = req
            .query
            .get("token")
            .ok_or_else(|| AuthError::bad_request("Deletion token is required"))?;

        let verification = self
            .database
            .get_verification_by_value(token)
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid or expired deletion token"))?;

        let user_id = verification.identifier();

        self.database.delete_user_sessions(user_id).await?;

        let accounts = self.database.get_user_accounts(user_id).await?;
        for account in accounts {
            self.database.delete_account(account.id()).await?;
        }

        self.database.delete_user(user_id).await?;
        self.database.delete_verification(verification.id()).await?;

        let response = DeleteUserResponse {
            success: true,
            message: "User account successfully deleted".to_string(),
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    /// Extract current user from request (validates session).
    ///
    /// If a virtual session was injected by a `before_request` hook (e.g.
    /// API-key session emulation), the user is resolved directly by ID
    /// **without** a database session lookup — matching the TypeScript
    /// `ctx.context.session` virtual-session behaviour.
    async fn extract_current_user(&self, req: &AuthRequest) -> AuthResult<DB::User> {
        // Fast path: virtual session injected by before_request hook
        if let Some(uid) = &req.virtual_user_id {
            return self
                .database
                .get_user_by_id(uid)
                .await?
                .ok_or(AuthError::UserNotFound);
        }

        let token = self
            .session_manager
            .extract_session_token(req)
            .ok_or(AuthError::Unauthenticated)?;

        let session = self
            .session_manager
            .get_session(&token)
            .await?
            .ok_or(AuthError::SessionNotFound)?;

        let user = self
            .database
            .get_user_by_id(session.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok(user)
    }
}
