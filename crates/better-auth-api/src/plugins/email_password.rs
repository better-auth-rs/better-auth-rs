use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};

use crate::core::{AuthPlugin, AuthRoute, AuthContext, PluginCapabilities};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, CreateUser, User};
use crate::error::{AuthError, AuthResult};

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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SignUpRequest {
    name: String,
    email: String,
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SignInRequest {
    email: String,
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
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
            return Ok(AuthResponse::json(403, &serde_json::json!({
                "error": "Signup disabled",
                "message": "User registration is not enabled"
            }))?);
        }
        
        let signup_req: SignUpRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Validate password
        if let Err(e) = self.validate_password(&signup_req.password, ctx) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid request", 
                "message": e.to_string()
            }))?);
        }
        
        // Check if user already exists
        if let Some(_) = ctx.database.get_user_by_email(&signup_req.email).await? {
            return Ok(AuthResponse::json(409, &serde_json::json!({
                "error": "User exists",
                "message": "A user with this email already exists"
            }))?);
        }
        
        // Hash password
        let password_hash = self.hash_password(&signup_req.password)?;
        
        // Create user with password hash in metadata
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let create_user = CreateUser::new()
            .with_email(&signup_req.email)
            .with_name(&signup_req.name);
        
        let mut create_user = create_user;
        create_user.metadata = Some(metadata);
            
        let user = ctx.database.create_user(create_user).await?;
        let _ = ctx.emit_user_created(&user).await;
        
        // Create session
        let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;
        let _ = ctx.emit_session_created(&session).await;
        
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
        let signin_req: SignInRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Get user by email
        let user = match ctx.database.get_user_by_email(&signin_req.email).await? {
            Some(user) => user,
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Invalid credentials",
                    "message": "Email or password is incorrect"
                }))?);
            }
        };
        
        // Verify password (assuming password is stored in metadata)
        let stored_hash = match user.metadata.get("password_hash").and_then(|v| v.as_str()) {
            Some(hash) => hash,
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Invalid credentials",
                    "message": "Email or password is incorrect"
                }))?);
            }
        };

        if self.config.require_email_verification && !user.email_verified {
            return Ok(AuthResponse::json(403, &serde_json::json!({
                "error": "Email not verified",
                "message": "Please verify your email before signing in"
            }))?);
        }
            
        if let Err(_) = self.verify_password(&signin_req.password, stored_hash) {
            return Ok(AuthResponse::json(401, &serde_json::json!({
                "error": "Invalid credentials",
                "message": "Email or password is incorrect"
            }))?);
        }
        
        // Create session
        let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;
        let _ = ctx.emit_session_created(&session).await;
        
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
            return Err(AuthError::InvalidRequest(format!(
                "Password must be at least {} characters long",
                ctx.config.password.min_length
            )));
        }
        
        // Add more password validation rules here
        
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
            crate::core::config::SameSite::Strict => "; SameSite=Strict",
            crate::core::config::SameSite::Lax => "; SameSite=Lax", 
            crate::core::config::SameSite::None => "; SameSite=None",
        };
        
        // Set expiration based on session config
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
        ];
        
        if self.config.enable_signup {
            routes.push(AuthRoute::post("/sign-up/email", "sign_up_email"));
        }
        
        routes
    }

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            needs_database: true,
            ..PluginCapabilities::default()
        }
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<crate::types::AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up/email") if self.config.enable_signup => {
                Ok(Some(self.handle_sign_up(req, ctx).await?))
            },
            (HttpMethod::Post, "/sign-in/email") => {
                Ok(Some(self.handle_sign_in(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
    
    async fn on_user_created(&self, user: &User, _ctx: &AuthContext) -> AuthResult<()> {
        // Send verification email if required
        if self.config.require_email_verification && !user.email_verified {
            if let Some(email) = &user.email {
                println!("📧 Email verification required for user: {}", email);
                // The email verification plugin will handle sending the email
                // via its on_user_created hook
            }
        }
        
        Ok(())
    }
} 
