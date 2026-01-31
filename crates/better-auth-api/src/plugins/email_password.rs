use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use validator::Validate;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};

use better_auth_core::{AuthPlugin, AuthRoute, AuthContext};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod, CreateUser, User};
use better_auth_core::{AuthError, AuthResult};

/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
}

#[derive(Debug, Clone)]
pub struct EmailPasswordConfig {
    pub enable_signup: bool,
    pub require_email_verification: bool,
    pub password_min_length: usize,
}

#[derive(Debug, Deserialize, Validate)]
struct SignUpRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    name: String,
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    username: Option<String>,
    #[serde(rename = "displayUsername")]
    display_username: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct SignInRequest {
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
struct SignInUsernameRequest {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SignUpResponse {
    token: Option<String>,
    user: User,
}

#[derive(Debug, Serialize)]
struct SignInResponse {
    redirect: bool,
    token: String,
    url: Option<String>,
    user: User,
}

impl EmailPasswordPlugin {
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
        }
    }

    pub fn with_config(config: EmailPasswordConfig) -> Self {
        Self { config }
    }

    pub fn enable_signup(mut self, enable: bool) -> Self {
        self.config.enable_signup = enable;
        self
    }

    pub fn require_email_verification(mut self, require: bool) -> Self {
        self.config.require_email_verification = require;
        self
    }

    pub fn password_min_length(mut self, length: usize) -> Self {
        self.config.password_min_length = length;
        self
    }

    async fn handle_sign_up(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        if !self.config.enable_signup {
            return Err(AuthError::forbidden("User registration is not enabled"));
        }

        let signup_req: SignUpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validate password
        self.validate_password(&signup_req.password, ctx)?;

        // Check if user already exists
        if ctx.database.get_user_by_email(&signup_req.email).await?.is_some() {
            return Err(AuthError::conflict("A user with this email already exists"));
        }

        // Hash password
        let password_hash = self.hash_password(&signup_req.password)?;

        // Create user with password hash in metadata
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));

        let mut create_user = CreateUser::new()
            .with_email(&signup_req.email)
            .with_name(&signup_req.name);
        if let Some(username) = signup_req.username {
            create_user = create_user.with_username(username);
        }
        if let Some(display_username) = signup_req.display_username {
            create_user.display_username = Some(display_username);
        }
        create_user.metadata = Some(metadata);

        let user = ctx.database.create_user(create_user).await?;

        // Create session
        let session_manager = better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = SignUpResponse {
            token: Some(session.token.clone()),
            user,
        };

        // Create session cookie
        let cookie_header = self.create_session_cookie(&session.token, ctx);

        Ok(AuthResponse::json(200, &response)?
            .with_header("Set-Cookie", cookie_header))
    }

    async fn handle_sign_in(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let signin_req: SignInRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Get user by email
        let user = ctx.database.get_user_by_email(&signin_req.email).await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify password
        let stored_hash = user.metadata.get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        self.verify_password(&signin_req.password, stored_hash)?;

        // Create session
        let session_manager = better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = SignInResponse {
            redirect: false,
            token: session.token.clone(),
            url: None,
            user,
        };

        // Create session cookie
        let cookie_header = self.create_session_cookie(&session.token, ctx);

        Ok(AuthResponse::json(200, &response)?
            .with_header("Set-Cookie", cookie_header))
    }

    async fn handle_sign_in_username(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let signin_req: SignInUsernameRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Get user by username
        let user = ctx.database.get_user_by_username(&signin_req.username).await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify password
        let stored_hash = user.metadata.get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        self.verify_password(&signin_req.password, stored_hash)?;

        // Create session
        let session_manager = better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = SignInResponse {
            redirect: false,
            token: session.token.clone(),
            url: None,
            user,
        };

        // Create session cookie
        let cookie_header = self.create_session_cookie(&session.token, ctx);

        Ok(AuthResponse::json(200, &response)?
            .with_header("Set-Cookie", cookie_header))
    }

    fn validate_password(&self, password: &str, ctx: &AuthContext) -> AuthResult<()> {
        if password.len() < ctx.config.password.min_length {
            return Err(AuthError::bad_request(format!(
                "Password must be at least {} characters long",
                ctx.config.password.min_length
            )));
        }
        Ok(())
    }

    fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;

        Ok(password_hash.to_string())
    }

    fn create_session_cookie(&self, token: &str, ctx: &AuthContext) -> String {
        let session_config = &ctx.config.session;
        let secure = if session_config.cookie_secure { "; Secure" } else { "" };
        let http_only = if session_config.cookie_http_only { "; HttpOnly" } else { "" };
        let same_site = match session_config.cookie_same_site {
            better_auth_core::config::SameSite::Strict => "; SameSite=Strict",
            better_auth_core::config::SameSite::Lax => "; SameSite=Lax",
            better_auth_core::config::SameSite::None => "; SameSite=None",
        };

        let expires = chrono::Utc::now() + session_config.expires_in;
        let expires_str = expires.format("%a, %d %b %Y %H:%M:%S GMT");

        format!("{}={}; Path=/; Expires={}{}{}{}",
                session_config.cookie_name,
                token,
                expires_str,
                secure,
                http_only,
                same_site)
    }

    fn verify_password(&self, password: &str, hash: &str) -> AuthResult<()> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(())
    }
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enable_signup: true,
            require_email_verification: false,
            password_min_length: 8,
        }
    }
}

#[async_trait]
impl AuthPlugin for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            AuthRoute::post("/sign-in/email", "sign_in_email"),
            AuthRoute::post("/sign-in/username", "sign_in_username"),
        ];

        if self.config.enable_signup {
            routes.push(AuthRoute::post("/sign-up/email", "sign_up_email"));
        }

        routes
    }

    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up/email") if self.config.enable_signup => {
                Ok(Some(self.handle_sign_up(req, ctx).await?))
            },
            (HttpMethod::Post, "/sign-in/email") => {
                Ok(Some(self.handle_sign_in(req, ctx).await?))
            },
            (HttpMethod::Post, "/sign-in/username") => {
                Ok(Some(self.handle_sign_in_username(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }

    async fn on_user_created(&self, user: &User, _ctx: &AuthContext) -> AuthResult<()> {
        if self.config.require_email_verification && !user.email_verified {
            if let Some(email) = &user.email {
                println!("Email verification required for user: {}", email);
            }
        }
        Ok(())
    }
}
