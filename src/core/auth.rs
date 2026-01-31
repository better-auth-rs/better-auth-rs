use std::sync::Arc;
use chrono;

use better_auth_core::{
    AuthRequest, AuthResponse, UpdateUserRequest, UpdateUserResponse,
    DeleteUserResponse, UpdateUser, HttpMethod, User,
    AuthError, AuthResult,
    DatabaseAdapter,
    AuthConfig, AuthPlugin, AuthContext, SessionManager,
    DatabaseHooks, HookedDatabaseAdapter,
    OpenApiBuilder, OpenApiSpec,
    middleware::{self, Middleware, CsrfMiddleware, CsrfConfig,
        RateLimitMiddleware, RateLimitConfig,
        CorsMiddleware, CorsConfig,
        BodyLimitMiddleware, BodyLimitConfig},
};

/// The main BetterAuth instance
pub struct BetterAuth {
    config: Arc<AuthConfig>,
    plugins: Vec<Box<dyn AuthPlugin>>,
    middlewares: Vec<Box<dyn Middleware>>,
    database: Arc<dyn DatabaseAdapter>,
    session_manager: SessionManager,
    context: AuthContext,
}

/// Builder for configuring BetterAuth
pub struct AuthBuilder {
    config: AuthConfig,
    plugins: Vec<Box<dyn AuthPlugin>>,
    hooks: Vec<Arc<dyn DatabaseHooks>>,
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
            plugins: Vec::new(),
            hooks: Vec::new(),
            csrf_config: None,
            rate_limit_config: None,
            cors_config: None,
            body_limit_config: None,
            custom_middlewares: Vec::new(),
        }
    }

    /// Add a plugin to the authentication system
    pub fn plugin<P: AuthPlugin + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Set the database adapter
    pub fn database<D: DatabaseAdapter + 'static>(mut self, database: D) -> Self {
        self.config.database = Some(Arc::new(database));
        self
    }

    /// Configure CSRF protection
    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Configure rate limiting
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    /// Configure CORS
    pub fn cors(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(config);
        self
    }

    /// Configure body size limit
    pub fn body_limit(mut self, config: BodyLimitConfig) -> Self {
        self.body_limit_config = Some(config);
        self
    }

    /// Add a database lifecycle hook
    pub fn hook<H: DatabaseHooks + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    /// Add a custom middleware
    pub fn middleware<M: Middleware + 'static>(mut self, mw: M) -> Self {
        self.custom_middlewares.push(Box::new(mw));
        self
    }

    /// Build the BetterAuth instance
    pub async fn build(self) -> AuthResult<BetterAuth> {
        // Validate configuration
        self.config.validate()?;

        let config = Arc::new(self.config);
        let raw_database = config.database.as_ref().unwrap().clone();

        // Wrap database with hooks if any were registered
        let database: Arc<dyn DatabaseAdapter> = if self.hooks.is_empty() {
            raw_database
        } else {
            let mut hooked = HookedDatabaseAdapter::new(raw_database);
            for hook in self.hooks {
                hooked.add_hook(hook);
            }
            Arc::new(hooked)
        };

        // Create session manager
        let session_manager = SessionManager::new(config.clone(), database.clone());

        // Create context
        let mut context = AuthContext::new(config.clone(), database.clone());

        // Initialize all plugins
        for plugin in &self.plugins {
            plugin.on_init(&mut context).await?;
        }

        // Build middleware chain (order matters: body limit → rate limit → CSRF → CORS → custom)
        let mut middlewares: Vec<Box<dyn Middleware>> = Vec::new();

        middlewares.push(Box::new(BodyLimitMiddleware::new(
            self.body_limit_config.unwrap_or_default(),
        )));

        middlewares.push(Box::new(RateLimitMiddleware::new(
            self.rate_limit_config.unwrap_or_default(),
        )));

        middlewares.push(Box::new(CsrfMiddleware::new(
            self.csrf_config.unwrap_or_default(),
            &config.base_url,
        )));

        middlewares.push(Box::new(CorsMiddleware::new(
            self.cors_config.unwrap_or_default(),
        )));

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

impl BetterAuth {
    /// Create a new BetterAuth builder
    pub fn new(config: AuthConfig) -> AuthBuilder {
        AuthBuilder::new(config)
    }

    /// Handle an authentication request.
    ///
    /// Errors from plugins and core handlers are automatically converted
    /// into standardized JSON responses via [`AuthError::into_response`],
    /// producing `{ "message": "..." }` with the appropriate HTTP status code.
    pub async fn handle_request(&self, req: AuthRequest) -> AuthResult<AuthResponse> {
        match self.handle_request_inner(&req).await {
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
    /// Errors are caught by `handle_request` and converted to responses.
    async fn handle_request_inner(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        // Run before-request middleware chain
        if let Some(response) = middleware::run_before(&self.middlewares, req).await? {
            return Ok(response);
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

    /// Get the configuration
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Get the database adapter
    pub fn database(&self) -> &Arc<dyn DatabaseAdapter> {
        &self.database
    }

    /// Get the session manager
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get all routes from plugins
    pub fn routes(&self) -> Vec<(String, &dyn AuthPlugin)> {
        let mut routes = Vec::new();
        for plugin in &self.plugins {
            for route in plugin.routes() {
                routes.push((route.path, plugin.as_ref()));
            }
        }
        routes
    }

    /// Get all plugins (useful for Axum integration)
    pub fn plugins(&self) -> &Vec<Box<dyn AuthPlugin>> {
        &self.plugins
    }

    /// Get plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&dyn AuthPlugin> {
        self.plugins.iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// List all plugin names
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

    /// Handle core authentication requests (user profile management + status endpoints)
    async fn handle_core_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/ok") => {
                Ok(Some(AuthResponse::json(200, &serde_json::json!({ "status": true }))?))
            },
            (HttpMethod::Get, "/error") => {
                Ok(Some(AuthResponse::json(200, &serde_json::json!({ "status": false }))?))
            },
            (HttpMethod::Get, "/reference/openapi.json") => {
                let spec = self.openapi_spec();
                Ok(Some(AuthResponse::json(200, &spec)?))
            },
            (HttpMethod::Post, "/update-user") => {
                Ok(Some(self.handle_update_user(req).await?))
            },
            (HttpMethod::Post, "/delete-user") => {
                Ok(Some(self.handle_delete_user(req).await?))
            },
            _ => Ok(None), // Not a core endpoint
        }
    }

    /// Handle user profile update
    async fn handle_update_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        // Extract and validate session
        let current_user = self.extract_current_user(req).await?;

        // Parse request body
        let update_req: UpdateUserRequest = req.body_as_json()
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;

        // Convert to UpdateUser
        let update_user = UpdateUser {
            email: update_req.email,
            name: update_req.name,
            image: update_req.image,
            email_verified: None, // Don't allow changing verification status through this endpoint
            username: update_req.username,
            display_username: update_req.display_username,
            role: update_req.role,
            banned: None, // Don't allow changing banned status through this endpoint
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None, // Don't allow changing 2FA status through this endpoint
            metadata: update_req.metadata,
        };

        // Update user in database
        let updated_user = self.database.update_user(&current_user.id, update_user).await?;

        let response = UpdateUserResponse {
            user: updated_user,
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    /// Handle user deletion
    async fn handle_delete_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        // Extract and validate session
        let current_user = self.extract_current_user(req).await?;

        // Delete all user sessions first
        self.database.delete_user_sessions(&current_user.id).await?;

        // Delete the user
        self.database.delete_user(&current_user.id).await?;

        let response = DeleteUserResponse {
            success: true,
            message: "User account successfully deleted".to_string(),
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    /// Extract current user from request (validates session)
    async fn extract_current_user(&self, req: &AuthRequest) -> AuthResult<User> {
        // Extract token from Authorization header
        let token = self.extract_bearer_token(req)
            .ok_or_else(|| AuthError::Unauthenticated)?;

        // Get session from database
        let session = self.database.get_session(&token).await?
            .ok_or_else(|| AuthError::SessionNotFound)?;

        // Check if session is expired
        if session.expires_at < chrono::Utc::now() {
            return Err(AuthError::SessionNotFound);
        }

        // Get user from database
        let user = self.database.get_user_by_id(&session.user_id).await?
            .ok_or_else(|| AuthError::UserNotFound)?;

        Ok(user)
    }

    /// Extract Bearer token from Authorization header
    fn extract_bearer_token(&self, req: &AuthRequest) -> Option<String> {
        req.headers.get("authorization")
            .and_then(|auth| {
                if auth.starts_with("Bearer ") {
                    Some(auth[7..].to_string())
                } else {
                    None
                }
            })
    }
}
