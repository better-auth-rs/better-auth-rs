use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;

use crate::core::{AuthPlugin, AuthRoute, AuthContext, PluginCapabilities};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, User, UpdateUser, CreateVerification};
use crate::error::{AuthError, AuthResult};

/// Password management plugin for password reset and change functionality
pub struct PasswordManagementPlugin {
    config: PasswordManagementConfig,
}

#[derive(Debug, Clone)]
pub struct PasswordManagementConfig {
    pub reset_token_expiry_hours: i64,
    pub require_current_password: bool,
    pub send_email_notifications: bool,
}

// Request structures for password endpoints
#[derive(Debug, Deserialize)]
struct ForgetPasswordRequest {
    email: String,
    #[serde(rename = "redirectTo")]
    redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    new_password: String,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    new_password: String,
    #[serde(rename = "currentPassword")]
    current_password: String,
    #[serde(default, rename = "revokeOtherSessions", deserialize_with = "deserialize_bool_or_string")]
    revoke_other_sessions: Option<bool>,
}

/// Deserialize a value that can be either a boolean or a string ("true"/"false") into Option<bool>.
/// This is needed because the better-auth TypeScript SDK sends `revokeOtherSessions` as a boolean,
/// while some clients may send it as a string.
fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom(format!("invalid value for revokeOtherSessions: {}", s))),
        },
        Some(other) => Err(serde::de::Error::custom(format!("invalid type for revokeOtherSessions: {}", other))),
    }
}

// Response structures
#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    status: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChangePasswordResponse {
    token: Option<String>,
    user: User,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResetPasswordTokenResponse {
    token: String,
}

impl PasswordManagementPlugin {
    pub fn new() -> Self {
        Self {
            config: PasswordManagementConfig::default(),
        }
    }
    
    pub fn with_config(config: PasswordManagementConfig) -> Self {
        Self { config }
    }
    
    pub fn reset_token_expiry_hours(mut self, hours: i64) -> Self {
        self.config.reset_token_expiry_hours = hours;
        self
    }
    
    pub fn require_current_password(mut self, require: bool) -> Self {
        self.config.require_current_password = require;
        self
    }
    
    pub fn send_email_notifications(mut self, send: bool) -> Self {
        self.config.send_email_notifications = send;
        self
    }
}

impl Default for PasswordManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PasswordManagementConfig {
    fn default() -> Self {
        Self {
            reset_token_expiry_hours: 24, // 24 hours default expiry
            require_current_password: true,
            send_email_notifications: true,
        }
    }
}

#[async_trait]
impl AuthPlugin for PasswordManagementPlugin {
    fn name(&self) -> &'static str {
        "password-management"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/forget-password", "forget_password"),
            AuthRoute::post("/reset-password", "reset_password"),
            AuthRoute::get("/reset-password/{token}", "reset_password_token"),
            AuthRoute::post("/change-password", "change_password"),
        ]
    }

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            needs_database: true,
            ..PluginCapabilities::default()
        }
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/forget-password") => {
                Ok(Some(self.handle_forget_password(req, ctx).await?))
            },
            (HttpMethod::Post, "/reset-password") => {
                Ok(Some(self.handle_reset_password(req, ctx).await?))
            },
            (HttpMethod::Post, "/change-password") => {
                Ok(Some(self.handle_change_password(req, ctx).await?))
            },
            (HttpMethod::Get, path) if path.starts_with("/reset-password/") => {
                let token = &path[16..]; // Remove "/reset-password/" prefix
                Ok(Some(self.handle_reset_password_token(token, req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl PasswordManagementPlugin {
    async fn handle_forget_password(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let forget_req: ForgetPasswordRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Check if user exists
        let user = match ctx.database.get_user_by_email(&forget_req.email).await? {
            Some(user) => user,
            None => {
                // Don't reveal whether email exists or not for security
                let response = StatusResponse { status: true };
                return Ok(AuthResponse::json(200, &response)?);
            }
        };
        
        // Generate password reset token
        let reset_token = format!("reset_{}", Uuid::new_v4());
        let expires_at = Utc::now() + Duration::hours(self.config.reset_token_expiry_hours);
        
        // Create verification token
        let create_verification = CreateVerification {
            identifier: user.email.clone().unwrap_or_default(),
            value: reset_token.clone(),
            expires_at,
        };
        
        ctx.database.create_verification(create_verification).await?;
        
        // TODO: Send email with reset link
        // In a real implementation, you would send an email here
        if self.config.send_email_notifications {
            let reset_url = if let Some(redirect_to) = &forget_req.redirect_to {
                format!("{}?token={}", redirect_to, reset_token)
            } else {
                format!("{}/reset-password?token={}", ctx.config.base_url, reset_token)
            };
            
            println!("Password reset email would be sent to {} with URL: {}", forget_req.email, reset_url);
        }
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_reset_password(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let reset_req: ResetPasswordRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Validate password
        if let Err(e) = self.validate_password(&reset_req.new_password, ctx) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid password",
                "message": e.to_string()
            }))?);
        }
        
        // Find user by reset token
        let token = reset_req.token.as_deref().unwrap_or("");
        if token.is_empty() {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid request",
                "message": "Reset token is required"
            }))?);
        }
        
        let (user, verification) = match self.find_user_by_reset_token(token, ctx).await? {
            Some((user, verification)) => (user, verification),
            None => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid token",
                    "message": "Invalid or expired reset token"
                }))?);
            }
        };
        
        // Hash new password
        let password_hash = self.hash_password(&reset_req.new_password)?;
        
        // Update user password
        let mut metadata = user.metadata.clone();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let update_user = UpdateUser {
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: Some(metadata),
        };
        
        ctx.database.update_user(&user.id, update_user).await?;
        
        // Delete the used verification token
        ctx.database.delete_verification(&verification.id).await?;
        
        // Revoke all existing sessions for security
        ctx.database.delete_user_sessions(&user.id).await?;
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_change_password(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let change_req: ChangePasswordRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Get current user from session (this would normally be extracted from auth middleware)
        // For now, we'll extract from Authorization header or session
        let user = match self.get_current_user(req, ctx).await? {
            Some(user) => user,
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Verify current password
        if self.config.require_current_password {
            let stored_hash = match user.metadata.get("password_hash").and_then(|v| v.as_str()) {
                Some(hash) => hash,
                None => {
                    return Ok(AuthResponse::json(400, &serde_json::json!({
                        "error": "Invalid request",
                        "message": "No password set for this user"
                    }))?);
                }
            };
            
            if let Err(_) = self.verify_password(&change_req.current_password, stored_hash) {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid password",
                    "message": "Current password is incorrect"
                }))?);
            }
        }
        
        // Validate new password
        if let Err(e) = self.validate_password(&change_req.new_password, ctx) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid password",
                "message": e.to_string()
            }))?);
        }
        
        // Hash new password
        let password_hash = self.hash_password(&change_req.new_password)?;
        
        // Update user password
        let mut metadata = user.metadata.clone();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let update_user = UpdateUser {
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: Some(metadata),
        };
        
        let updated_user = ctx.database.update_user(&user.id, update_user).await?;
        
        // Handle session revocation
        let new_token = if change_req.revoke_other_sessions == Some(true) {
            // Revoke all sessions except current one
            ctx.database.delete_user_sessions(&user.id).await?;
            
            // Create new session
            let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
            let session = session_manager.create_session(&updated_user, None, None).await?;
            let _ = ctx.emit_session_created(&session).await;
            Some(session.token)
        } else {
            None
        };
        
        let response = ChangePasswordResponse {
            token: new_token.clone(),
            user: updated_user,
        };
        
        let auth_response = AuthResponse::json(200, &response)?;
        
        // Set session cookie if a new session was created
        if let Some(token) = new_token {
            let cookie_header = self.create_session_cookie(&token, ctx);
            Ok(auth_response.with_header("Set-Cookie", cookie_header))
        } else {
            Ok(auth_response)
        }
    }
    
    async fn handle_reset_password_token(&self, token: &str, _req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Check if token is valid and get callback URL from query parameters
        let callback_url = _req.query.get("callbackURL").cloned();
        
        // Validate the reset token exists and is not expired
        let (_user, _verification) = match self.find_user_by_reset_token(token, ctx).await? {
            Some((user, verification)) => (user, verification),
            None => {
                // Redirect to callback URL with error if provided
                if let Some(callback_url) = callback_url {
                    let redirect_url = format!("{}?error=INVALID_TOKEN", callback_url);
                    let mut headers = std::collections::HashMap::new();
                    headers.insert("Location".to_string(), redirect_url);
                    return Ok(AuthResponse {
                        status: 302,
                        headers,
                        body: Vec::new(),
                    });
                }
                
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid token",
                    "message": "Invalid or expired reset token"
                }))?);
            }
        };
        
        // If callback URL is provided, redirect with valid token
        if let Some(callback_url) = callback_url {
            let redirect_url = format!("{}?token={}", callback_url, token);
            let mut headers = std::collections::HashMap::new();
            headers.insert("Location".to_string(), redirect_url);
            return Ok(AuthResponse {
                status: 302,
                headers,
                body: Vec::new(),
            });
        }
        
        // Otherwise return the token directly
        let response = ResetPasswordTokenResponse {
            token: token.to_string(),
        };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn find_user_by_reset_token(&self, token: &str, ctx: &AuthContext) -> AuthResult<Option<(User, crate::types::Verification)>> {
        // Find verification token by value
        let verification = match ctx.database.get_verification_by_value(token).await? {
            Some(verification) => verification,
            None => return Ok(None),
        };
        
        // Get user by email (stored in identifier field)
        let user = match ctx.database.get_user_by_email(&verification.identifier).await? {
            Some(user) => user,
            None => return Ok(None),
        };
        
        Ok(Some((user, verification)))
    }
    
    async fn get_current_user(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<User>> {
        // Extract session token from Authorization header or cookies
        let token = if let Some(auth_header) = req.headers.get("authorization") {
            if auth_header.starts_with("Bearer ") {
                Some(&auth_header[7..])
            } else {
                None
            }
        } else {
            None
        };
        
        if let Some(token) = token {
            let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
            if let Some(session) = session_manager.get_session(token).await? {
                return ctx.database.get_user_by_id(&session.user_id).await;
            }
        }
        
        Ok(None)
    }
    
    fn validate_password(&self, password: &str, ctx: &AuthContext) -> AuthResult<()> {
        let config = &ctx.config.password;
        
        if password.len() < config.min_length {
            return Err(AuthError::InvalidRequest(format!(
                "Password must be at least {} characters long",
                config.min_length
            )));
        }
        
        if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AuthError::InvalidRequest(
                "Password must contain at least one uppercase letter".to_string()
            ));
        }
        
        if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AuthError::InvalidRequest(
                "Password must contain at least one lowercase letter".to_string()
            ));
        }
        
        if config.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AuthError::InvalidRequest(
                "Password must contain at least one number".to_string()
            ));
        }
        
        if config.require_special && !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
            return Err(AuthError::InvalidRequest(
                "Password must contain at least one special character".to_string()
            ));
        }
        
        Ok(())
    }
    
    fn hash_password(&self, password: &str) -> AuthResult<String> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        
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
        use argon2::{Argon2, PasswordVerifier};
        use argon2::password_hash::PasswordHash;
        
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;
            
        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;
            
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::{AuthConfig, PasswordConfig, Argon2Config};
    use crate::adapters::{MemoryDatabaseAdapter, DatabaseAdapter};
    use crate::types::{CreateUser, CreateSession, CreateVerification, Session, User};
    use chrono::{Utc, Duration};
    use std::collections::HashMap;
    use std::sync::Arc;
    
    async fn create_test_context_with_user() -> (AuthContext, User, Session) {
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        config.password = PasswordConfig {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            argon2_config: Argon2Config::default(),
        };
        
        let config = Arc::new(config);
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config.clone(), database.clone());
        
        // Create test user with hashed password
        let plugin = PasswordManagementPlugin::new();
        let password_hash = plugin.hash_password("Password123!").unwrap();
        
        let mut metadata = HashMap::new();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let create_user = CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_metadata(metadata);
        let user = database.create_user(create_user).await.unwrap();
        
        // Create test session
        let create_session = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session = database.create_session(create_session).await.unwrap();
        
        (ctx, user, session)
    }
    
    fn create_auth_request(method: HttpMethod, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }
        
        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body,
            query: HashMap::new(),
        }
    }
    
    #[tokio::test]
    async fn test_forget_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000/reset"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/forget-password",
            None,
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_forget_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
    }
    
    #[tokio::test]
    async fn test_forget_password_unknown_email() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "email": "unknown@example.com"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/forget-password",
            None,
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_forget_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        // Should return success even for unknown emails (security)
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
    }
    
    #[tokio::test]
    async fn test_reset_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;
        
        // Create verification token
        let reset_token = format!("reset_{}", uuid::Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: user.email.clone().unwrap(),
            value: reset_token.clone(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        ctx.database.create_verification(create_verification).await.unwrap();
        
        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        
        // Verify password was updated
        let updated_user = ctx.database.get_user_by_id(&user.id).await.unwrap().unwrap();
        let stored_hash = updated_user.metadata.get("password_hash").unwrap().as_str().unwrap();
        assert!(plugin.verify_password("NewPassword123!", stored_hash).is_ok());
        
        // Verify token was deleted
        let verification_check = ctx.database.get_verification_by_value(&reset_token).await.unwrap();
        assert!(verification_check.is_none());
    }
    
    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": "invalid_token"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);
    }
    
    #[tokio::test]
    async fn test_reset_password_weak_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;
        
        // Create verification token
        let reset_token = format!("reset_{}", uuid::Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: user.email.clone().unwrap(),
            value: reset_token.clone(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        ctx.database.create_verification(create_verification).await.unwrap();
        
        let body = serde_json::json!({
            "newPassword": "weak",
            "token": reset_token
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);
    }
    
    #[tokio::test]
    async fn test_change_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": "false"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: ChangePasswordResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.token.is_none()); // No new token when not revoking sessions
        
        // Verify password was updated by checking the database directly
        let updated_user = ctx.database.get_user_by_id(&response_data.user.id).await.unwrap().unwrap();
        let stored_hash = updated_user.metadata.get("password_hash").unwrap().as_str().unwrap();
        assert!(plugin.verify_password("NewPassword123!", stored_hash).is_ok());
    }
    
    #[tokio::test]
    async fn test_change_password_with_session_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": "true"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: ChangePasswordResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.token.is_some()); // New token when revoking sessions
    }

    #[tokio::test]
    async fn test_change_password_sets_cookie_on_session_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify Set-Cookie header is present
        let set_cookie = response.headers.get("Set-Cookie");
        assert!(
            set_cookie.is_some(),
            "Set-Cookie header must be set when revokeOtherSessions is true"
        );

        let cookie_value = set_cookie.unwrap();
        assert!(cookie_value.contains(&ctx.config.session.cookie_name),
            "Cookie must contain the session cookie name");
        assert!(cookie_value.contains("Path=/"),
            "Cookie must contain Path=/");
        assert!(cookie_value.contains("Expires="),
            "Cookie must contain an expiration");
    }

    #[tokio::test]
    async fn test_change_password_no_cookie_without_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify Set-Cookie header is NOT present when not revoking sessions
        let set_cookie = response.headers.get("Set-Cookie");
        assert!(
            set_cookie.is_none(),
            "Set-Cookie header must not be set when revokeOtherSessions is not true"
        );
    }

    #[tokio::test]
    async fn test_change_password_revoke_with_boolean() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Send revokeOtherSessions as a boolean (as better-auth TS SDK does)
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: ChangePasswordResponse = serde_json::from_str(&body_str).unwrap();
        assert!(
            response_data.token.is_some(),
            "New token must be returned when revokeOtherSessions is boolean true"
        );
    }
    
    #[tokio::test]
    async fn test_change_password_wrong_current_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "currentPassword": "WrongPassword123!",
            "newPassword": "NewPassword123!"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);
    }
    
    #[tokio::test]
    async fn test_change_password_unauthorized() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;
        
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });
        
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            None,
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
    }
    
    #[tokio::test]
    async fn test_reset_password_token_endpoint_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;
        
        // Create verification token
        let reset_token = format!("reset_{}", uuid::Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: user.email.clone().unwrap(),
            value: reset_token.clone(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        ctx.database.create_verification(create_verification).await.unwrap();
        
        let req = create_auth_request(HttpMethod::Get, "/reset-password/token", None, None);
        
        let response = plugin.handle_reset_password_token(&reset_token, &req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: ResetPasswordTokenResponse = serde_json::from_str(&body_str).unwrap();
        assert_eq!(response_data.token, reset_token);
    }
    
    #[tokio::test]
    async fn test_reset_password_token_endpoint_with_callback() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;
        
        // Create verification token
        let reset_token = format!("reset_{}", uuid::Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: user.email.clone().unwrap(),
            value: reset_token.clone(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        ctx.database.create_verification(create_verification).await.unwrap();
        
        let mut query = HashMap::new();
        query.insert("callbackURL".to_string(), "http://localhost:3000/reset".to_string());
        
        let req = AuthRequest {
            method: HttpMethod::Get,
            path: "/reset-password/token".to_string(),
            headers: HashMap::new(),
            body: None,
            query,
        };
        
        let response = plugin.handle_reset_password_token(&reset_token, &req, &ctx).await.unwrap();
        assert_eq!(response.status, 302);
        
        // Check redirect URL
        let location_header = response.headers.iter()
            .find(|(key, _)| *key == "Location")
            .map(|(_, value)| value);
        assert!(location_header.is_some());
        assert!(location_header.unwrap().contains("http://localhost:3000/reset"));
        assert!(location_header.unwrap().contains(&reset_token));
    }
    
    #[tokio::test]
    async fn test_reset_password_token_endpoint_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;
        
        let req = create_auth_request(HttpMethod::Get, "/reset-password/token", None, None);
        
        let response = plugin.handle_reset_password_token("invalid_token", &req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);
    }
    
    #[tokio::test]
    async fn test_password_validation() {
        let plugin = PasswordManagementPlugin::new();
        let mut config = AuthConfig::new("test-secret");
        config.password = PasswordConfig {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            argon2_config: Argon2Config::default(),
        };
        let ctx = AuthContext::new(Arc::new(config), Arc::new(MemoryDatabaseAdapter::new()));
        
        // Test valid password
        assert!(plugin.validate_password("Password123!", &ctx).is_ok());
        
        // Test too short
        assert!(plugin.validate_password("Pass1!", &ctx).is_err());
        
        // Test missing uppercase
        assert!(plugin.validate_password("password123!", &ctx).is_err());
        
        // Test missing lowercase
        assert!(plugin.validate_password("PASSWORD123!", &ctx).is_err());
        
        // Test missing number
        assert!(plugin.validate_password("Password!", &ctx).is_err());
        
        // Test missing special character
        assert!(plugin.validate_password("Password123", &ctx).is_err());
    }
    
    #[tokio::test]
    async fn test_password_hashing_and_verification() {
        let plugin = PasswordManagementPlugin::new();
        
        let password = "TestPassword123!";
        let hash = plugin.hash_password(password).unwrap();
        
        // Should verify correctly
        assert!(plugin.verify_password(password, &hash).is_ok());
        
        // Should fail with wrong password
        assert!(plugin.verify_password("WrongPassword123!", &hash).is_err());
    }
    
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = PasswordManagementPlugin::new();
        let routes = plugin.routes();
        
        assert_eq!(routes.len(), 4);
        assert!(routes.iter().any(|r| r.path == "/forget-password" && r.method == HttpMethod::Post));
        assert!(routes.iter().any(|r| r.path == "/reset-password" && r.method == HttpMethod::Post));
        assert!(routes.iter().any(|r| r.path == "/reset-password/{token}" && r.method == HttpMethod::Get));
        assert!(routes.iter().any(|r| r.path == "/change-password" && r.method == HttpMethod::Post));
    }
    
    #[tokio::test]
    async fn test_plugin_on_request_routing() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        // Test forget password
        let body = serde_json::json!({"email": "test@example.com"});
        let req = create_auth_request(
            HttpMethod::Post,
            "/forget-password",
            None,
            Some(body.to_string().into_bytes())
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);
        
        // Test change password
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes())
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);
        
        // Test invalid route
        let req = create_auth_request(HttpMethod::Get, "/invalid-route", None, None);
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());
    }
    
    #[tokio::test]
    async fn test_configuration() {
        let config = PasswordManagementConfig {
            reset_token_expiry_hours: 48,
            require_current_password: false,
            send_email_notifications: false,
        };
        
        let plugin = PasswordManagementPlugin::with_config(config);
        assert_eq!(plugin.config.reset_token_expiry_hours, 48);
        assert!(!plugin.config.require_current_password);
        assert!(!plugin.config.send_email_notifications);
    }
}
