use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateVerification, HttpMethod, UpdateUser};
use better_auth_core::{AuthSession, AuthUser, AuthVerification, DatabaseAdapter};

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
#[derive(Debug, Deserialize, Validate)]
struct ForgetPasswordRequest {
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[serde(rename = "redirectTo")]
    redirect_to: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    new_password: String,
    token: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct SetPasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    new_password: String,
    #[serde(rename = "currentPassword")]
    #[validate(length(min = 1, message = "Current password is required"))]
    current_password: String,
    #[serde(rename = "revokeOtherSessions")]
    revoke_other_sessions: Option<String>,
}

// Response structures
#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    status: bool,
}

#[derive(Debug, Serialize)]
struct ChangePasswordResponse<U: Serialize> {
    token: Option<String>,
    user: U,
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
impl<DB: DatabaseAdapter> AuthPlugin<DB> for PasswordManagementPlugin {
    fn name(&self) -> &'static str {
        "password-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/forget-password", "forget_password"),
            AuthRoute::post("/reset-password", "reset_password"),
            AuthRoute::get("/reset-password/{token}", "reset_password_token"),
            AuthRoute::post("/change-password", "change_password"),
            AuthRoute::post("/set-password", "set_password"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/forget-password") => {
                Ok(Some(self.handle_forget_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/reset-password") => {
                Ok(Some(self.handle_reset_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/change-password") => {
                Ok(Some(self.handle_change_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/set-password") => {
                Ok(Some(self.handle_set_password(req, ctx).await?))
            }
            (HttpMethod::Get, path) if path.starts_with("/reset-password/") => {
                let token = &path[16..]; // Remove "/reset-password/" prefix
                Ok(Some(
                    self.handle_reset_password_token(token, req, ctx).await?,
                ))
            }
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl PasswordManagementPlugin {
    async fn handle_forget_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let forget_req: ForgetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
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
            identifier: user.email().unwrap_or_default().to_string(),
            value: reset_token.clone(),
            expires_at,
        };

        ctx.database
            .create_verification(create_verification)
            .await?;

        // Send email with reset link
        if self.config.send_email_notifications {
            let reset_url = if let Some(redirect_to) = &forget_req.redirect_to {
                format!("{}?token={}", redirect_to, reset_token)
            } else {
                format!(
                    "{}/reset-password?token={}",
                    ctx.config.base_url, reset_token
                )
            };

            if let Ok(provider) = ctx.email_provider() {
                let subject = "Reset your password";
                let html = format!(
                    "<p>Click the link below to reset your password:</p>\
                     <p><a href=\"{url}\">Reset Password</a></p>",
                    url = reset_url
                );
                let text = format!("Reset your password: {}", reset_url);

                if let Err(e) = provider
                    .send(&forget_req.email, subject, &html, &text)
                    .await
                {
                    eprintln!(
                        "[password-management] Failed to send reset email to {}: {}",
                        forget_req.email, e
                    );
                }
            } else {
                eprintln!(
                    "[password-management] No email provider configured, skipping password reset email for {}",
                    forget_req.email
                );
            }
        }

        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let reset_req: ResetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validate password
        self.validate_password(&reset_req.new_password, ctx)?;

        // Find user by reset token
        let token = reset_req.token.as_deref().unwrap_or("");
        if token.is_empty() {
            return Err(AuthError::bad_request("Reset token is required"));
        }

        let (user, verification) = self
            .find_user_by_reset_token(token, ctx)
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid or expired reset token"))?;

        // Hash new password
        let password_hash = self.hash_password(&reset_req.new_password)?;

        // Update user password
        let mut metadata = user.metadata().clone();
        metadata["password_hash"] = serde_json::Value::String(password_hash);

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

        ctx.database.update_user(user.id(), update_user).await?;

        // Delete the used verification token
        ctx.database.delete_verification(verification.id()).await?;

        // Revoke all existing sessions for security
        ctx.database.delete_user_sessions(user.id()).await?;

        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_change_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let change_req: ChangePasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Get current user from session
        let user = self
            .get_current_user(req, ctx)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        // Verify current password
        if self.config.require_current_password {
            let stored_hash = user
                .metadata()
                .get("password_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AuthError::bad_request("No password set for this user"))?;

            self.verify_password(&change_req.current_password, stored_hash)
                .map_err(|_| AuthError::InvalidCredentials)?;
        }

        // Validate new password
        self.validate_password(&change_req.new_password, ctx)?;

        // Hash new password
        let password_hash = self.hash_password(&change_req.new_password)?;

        // Update user password
        let mut metadata = user.metadata().clone();
        metadata["password_hash"] = serde_json::Value::String(password_hash);

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

        let updated_user = ctx.database.update_user(user.id(), update_user).await?;

        // Handle session revocation
        let new_token = if change_req.revoke_other_sessions.as_deref() == Some("true") {
            // Revoke all sessions except current one
            ctx.database.delete_user_sessions(user.id()).await?;

            // Create new session
            let session_manager =
                better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
            let session = session_manager
                .create_session(&updated_user, None, None)
                .await?;
            Some(session.token().to_string())
        } else {
            None
        };

        let response = ChangePasswordResponse {
            token: new_token,
            user: updated_user,
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_set_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let set_req: SetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Authenticate user
        let user = self
            .get_current_user(req, ctx)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        // Verify the user does NOT already have a password
        if user
            .metadata()
            .get("password_hash")
            .and_then(|v| v.as_str())
            .is_some()
        {
            return Err(AuthError::bad_request(
                "User already has a password. Use /change-password instead.",
            ));
        }

        // Validate new password
        self.validate_password(&set_req.new_password, ctx)?;

        // Hash and store the new password
        let password_hash = self.hash_password(&set_req.new_password)?;

        let mut metadata = user.metadata().clone();
        metadata["password_hash"] = serde_json::Value::String(password_hash);

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

        ctx.database.update_user(user.id(), update_user).await?;

        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password_token<DB: DatabaseAdapter>(
        &self,
        token: &str,
        _req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
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

                return Err(AuthError::bad_request("Invalid or expired reset token"));
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

    async fn find_user_by_reset_token<DB: DatabaseAdapter>(
        &self,
        token: &str,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<(DB::User, DB::Verification)>> {
        // Find verification token by value
        let verification = match ctx.database.get_verification_by_value(token).await? {
            Some(verification) => verification,
            None => return Ok(None),
        };

        // Get user by email (stored in identifier field)
        let user = match ctx
            .database
            .get_user_by_email(verification.identifier())
            .await?
        {
            Some(user) => user,
            None => return Ok(None),
        };

        Ok(Some((user, verification)))
    }

    async fn get_current_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<DB::User>> {
        let session_manager =
            better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
        {
            return ctx.database.get_user_by_id(session.user_id()).await;
        }

        Ok(None)
    }

    fn validate_password<DB: DatabaseAdapter>(
        &self,
        password: &str,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        let config = &ctx.config.password;

        if password.len() < config.min_length {
            return Err(AuthError::bad_request(format!(
                "Password must be at least {} characters long",
                config.min_length
            )));
        }

        if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AuthError::bad_request(
                "Password must contain at least one uppercase letter",
            ));
        }

        if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AuthError::bad_request(
                "Password must contain at least one lowercase letter",
            ));
        }

        if config.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AuthError::bad_request(
                "Password must contain at least one number",
            ));
        }

        if config.require_special
            && !password
                .chars()
                .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            return Err(AuthError::bad_request(
                "Password must contain at least one special character",
            ));
        }

        Ok(())
    }

    fn hash_password(&self, password: &str) -> AuthResult<String> {
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        use argon2::{Argon2, PasswordHasher};

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;

        Ok(password_hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> AuthResult<()> {
        use argon2::password_hash::PasswordHash;
        use argon2::{Argon2, PasswordVerifier};

        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps, VerificationOps};
    use better_auth_core::config::{Argon2Config, AuthConfig, PasswordConfig};
    use better_auth_core::{CreateSession, CreateUser, CreateVerification, Session, User};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn create_test_context_with_user() -> (AuthContext<MemoryDatabaseAdapter>, User, Session)
    {
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

        let metadata = serde_json::json!({
            "password_hash": password_hash,
        });

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

    fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> AuthRequest {
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
            Some(body.to_string().into_bytes()),
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
            Some(body.to_string().into_bytes()),
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
        ctx.database
            .create_verification(create_verification)
            .await
            .unwrap();

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);

        // Verify password was updated
        let updated_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        let stored_hash = updated_user
            .metadata
            .get("password_hash")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(
            plugin
                .verify_password("NewPassword123!", stored_hash)
                .is_ok()
        );

        // Verify token was deleted
        let verification_check = ctx
            .database
            .get_verification_by_value(&reset_token)
            .await
            .unwrap();
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
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
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
        ctx.database
            .create_verification(create_verification)
            .await
            .unwrap();

        let body = serde_json::json!({
            "newPassword": "weak",
            "token": reset_token
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
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
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(response_data["token"].is_null()); // No new token when not revoking sessions

        // Verify password was updated by checking the database directly
        let user_id = response_data["user"]["id"].as_str().unwrap();
        let updated_user = ctx.database.get_user_by_id(user_id).await.unwrap().unwrap();
        let stored_hash = updated_user
            .metadata
            .get("password_hash")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(
            plugin
                .verify_password("NewPassword123!", stored_hash)
                .is_ok()
        );
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
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(response_data["token"].is_string()); // New token when revoking sessions
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
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
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
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
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
        ctx.database
            .create_verification(create_verification)
            .await
            .unwrap();

        let req = create_auth_request(HttpMethod::Get, "/reset-password/token", None, None);

        let response = plugin
            .handle_reset_password_token(&reset_token, &req, &ctx)
            .await
            .unwrap();
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
        ctx.database
            .create_verification(create_verification)
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_string(),
            "http://localhost:3000/reset".to_string(),
        );

        let req = AuthRequest {
            method: HttpMethod::Get,
            path: "/reset-password/token".to_string(),
            headers: HashMap::new(),
            body: None,
            query,
        };

        let response = plugin
            .handle_reset_password_token(&reset_token, &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);

        // Check redirect URL
        let location_header = response
            .headers
            .iter()
            .find(|(key, _)| *key == "Location")
            .map(|(_, value)| value);
        assert!(location_header.is_some());
        assert!(
            location_header
                .unwrap()
                .contains("http://localhost:3000/reset")
        );
        assert!(location_header.unwrap().contains(&reset_token));
    }

    #[tokio::test]
    async fn test_reset_password_token_endpoint_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let req = create_auth_request(HttpMethod::Get, "/reset-password/token", None, None);

        let err = plugin
            .handle_reset_password_token("invalid_token", &req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);
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
        let routes = AuthPlugin::<MemoryDatabaseAdapter>::routes(&plugin);

        assert_eq!(routes.len(), 5);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/forget-password" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/reset-password" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/reset-password/{token}" && r.method == HttpMethod::Get)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/change-password" && r.method == HttpMethod::Post)
        );
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
            Some(body.to_string().into_bytes()),
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
            Some(body.to_string().into_bytes()),
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
