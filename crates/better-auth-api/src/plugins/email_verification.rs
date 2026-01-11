use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;

use crate::core::{AuthPlugin, AuthRoute, AuthContext, PluginCapabilities};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, User, UpdateUser, CreateVerification};
use crate::error::{AuthError, AuthResult};

/// Email verification plugin for handling email verification flows
pub struct EmailVerificationPlugin {
    config: EmailVerificationConfig,
}

#[derive(Debug, Clone)]
pub struct EmailVerificationConfig {
    pub verification_token_expiry_hours: i64,
    pub send_email_notifications: bool,
    pub require_verification_for_signin: bool,
    pub auto_verify_new_users: bool,
    pub resend_cooldown_seconds: i64,
}

// Request structures for email verification endpoints
#[derive(Debug, Deserialize)]
struct SendVerificationEmailRequest {
    email: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

// Response structures
#[derive(Debug, Serialize)]
struct EmailVerificationResponse {
    success: bool,
    message: String,
    user: Option<User>,
}

impl EmailVerificationPlugin {
    pub fn new() -> Self {
        Self {
            config: EmailVerificationConfig::default(),
        }
    }
    
    pub fn with_config(config: EmailVerificationConfig) -> Self {
        Self { config }
    }
    
    pub fn verification_token_expiry_hours(mut self, hours: i64) -> Self {
        self.config.verification_token_expiry_hours = hours;
        self
    }
    
    pub fn send_email_notifications(mut self, send: bool) -> Self {
        self.config.send_email_notifications = send;
        self
    }
    
    pub fn require_verification_for_signin(mut self, require: bool) -> Self {
        self.config.require_verification_for_signin = require;
        self
    }
    
    pub fn auto_verify_new_users(mut self, auto_verify: bool) -> Self {
        self.config.auto_verify_new_users = auto_verify;
        self
    }

    pub fn resend_cooldown_seconds(mut self, seconds: i64) -> Self {
        self.config.resend_cooldown_seconds = seconds;
        self
    }
}

impl Default for EmailVerificationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for EmailVerificationConfig {
    fn default() -> Self {
        Self {
            verification_token_expiry_hours: 24, // 24 hours default expiry
            send_email_notifications: true,
            require_verification_for_signin: false,
            auto_verify_new_users: false,
            resend_cooldown_seconds: 60,
        }
    }
}

#[async_trait]
impl AuthPlugin for EmailVerificationPlugin {
    fn name(&self) -> &'static str {
        "email-verification"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/send-verification-email", "send_verification_email"),
            AuthRoute::get("/verify-email", "verify_email"),
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
            (HttpMethod::Post, "/send-verification-email") => {
                Ok(Some(self.handle_send_verification_email(req, ctx).await?))
            },
            (HttpMethod::Get, "/verify-email") => {
                Ok(Some(self.handle_verify_email(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
    
    async fn on_user_created(&self, user: &User, ctx: &AuthContext) -> AuthResult<()> {
        if self.config.auto_verify_new_users && !user.email_verified {
            let update_user = UpdateUser {
                email: None,
                name: None,
                image: None,
                email_verified: Some(true),
                username: None,
                display_username: None,
                role: None,
                banned: None,
                ban_reason: None,
                ban_expires: None,
                two_factor_enabled: None,
                metadata: None,
            };

            let _ = ctx.database.update_user(&user.id, update_user).await?;
            return Ok(());
        }

        // Send verification email for new users if configured
        if self.config.send_email_notifications && !user.email_verified {
            if let Some(email) = &user.email {
                let _ = self.send_verification_email_internal(email, None, ctx).await;
            }
        }
        Ok(())
    }
}

// Implementation methods outside the trait
impl EmailVerificationPlugin {
    async fn handle_send_verification_email(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let send_req: SendVerificationEmailRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Check if user exists
        let user = match ctx.database.get_user_by_email(&send_req.email).await? {
            Some(user) => user,
            None => {
                return Ok(AuthResponse::json(400, &EmailVerificationResponse {
                    success: false,
                    message: "No user found with this email address".to_string(),
                    user: None,
                })?);
            }
        };
        
        // Check if user is already verified
        if user.email_verified {
            return Ok(AuthResponse::json(400, &EmailVerificationResponse {
                success: false,
                message: "Email is already verified".to_string(),
                user: None,
            })?);
        }
        
        // Send verification email
        if let Err(err) = self.send_verification_email_internal(&send_req.email, send_req.callback_url.as_deref(), ctx).await {
            if let AuthError::InvalidRequest(ref message) = err {
                if message == "Verification email recently sent" {
                    return Ok(AuthResponse::json(429, &EmailVerificationResponse {
                        success: false,
                        message: message.to_string(),
                        user: None,
                    })?);
                }
            }
            return Err(err);
        }
        
        let response = EmailVerificationResponse {
            success: true,
            message: "Verification email sent successfully".to_string(),
            user: None,
        };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_verify_email(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Extract token and callback URL from query parameters
        let token = match req.query.get("token") {
            Some(token) => token,
            None => {
                return Ok(AuthResponse::json(400, &EmailVerificationResponse {
                    success: false,
                    message: "Verification token is required".to_string(),
                    user: None,
                })?);
            }
        };
        
        let callback_url = req.query.get("callbackURL");
        
        // Find verification token
        let verification = match ctx.database.get_verification_by_value(token).await? {
            Some(verification) => verification,
            None => {
                return Ok(AuthResponse::json(400, &EmailVerificationResponse {
                    success: false,
                    message: "Invalid or expired verification token".to_string(),
                    user: None,
                })?);
            }
        };

        if verification.expires_at < Utc::now() {
            let _ = ctx.database.delete_verification(&verification.id).await;
            return Ok(AuthResponse::json(400, &EmailVerificationResponse {
                success: false,
                message: "Invalid or expired verification token".to_string(),
                user: None,
            })?);
        }
        
        // Get user by email (stored in identifier field)
        let user = match ctx.database.get_user_by_email(&verification.identifier).await? {
            Some(user) => user,
            None => {
                return Ok(AuthResponse::json(400, &EmailVerificationResponse {
                    success: false,
                    message: "User associated with this token not found".to_string(),
                    user: None,
                })?);
            }
        };
        
        // Check if already verified
        if user.email_verified {
            let response = EmailVerificationResponse {
                success: true,
                message: "Email already verified".to_string(),
                user: Some(user),
            };
            return Ok(AuthResponse::json(200, &response)?);
        }
        
        // Update user email verification status
        let update_user = UpdateUser {
            email: None,
            name: None,
            image: None,
            email_verified: Some(true),
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: None,
        };
        
        let updated_user = ctx.database.update_user(&user.id, update_user).await?;
        
        // Delete the used verification token
        ctx.database.delete_verification(&verification.id).await?;
        
        // If callback URL is provided, handle redirect (in a real implementation)
        if let Some(callback_url) = callback_url {
            println!("Would redirect to: {}?verified=true", callback_url);
        }
        
        let response = EmailVerificationResponse {
            success: true,
            message: "Email verified successfully".to_string(),
            user: Some(updated_user),
        };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn send_verification_email_internal(
        &self,
        email: &str,
        callback_url: Option<&str>,
        ctx: &AuthContext,
    ) -> AuthResult<()> {
        if let Some(cache) = ctx.cache.as_ref() {
            let key = format!("email_verification:resend:{}", email);
            if cache.exists(&key).await? {
                return Err(AuthError::InvalidRequest("Verification email recently sent".to_string()));
            }
            cache.set(&key, "1", Duration::seconds(self.config.resend_cooldown_seconds)).await?;
        }

        // Generate verification token
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let expires_at = Utc::now() + Duration::hours(self.config.verification_token_expiry_hours);
        
        // Create verification token
        let create_verification = CreateVerification {
            identifier: email.to_string(),
            value: verification_token.clone(),
            expires_at,
        };
        
        ctx.database.create_verification(create_verification).await?;
        
        // Send email (in a real implementation, this would use an email service)
        if self.config.send_email_notifications {
            let verification_url = if let Some(callback_url) = callback_url {
                format!("{}?token={}", callback_url, verification_token)
            } else {
                format!("{}/verify-email?token={}", ctx.config.base_url, verification_token)
            };

            if let Some(mailer) = ctx.mailer.as_ref() {
                let subject = "Verify your email";
                let body = format!("Click the link to verify your email: {}", verification_url);
                mailer.send(email, subject, &body).await?;
            } else {
                println!("📧 Verification email would be sent to {} with URL: {}", email, verification_url);
            }
        }
        
        Ok(())
    }
    
    /// Check if email verification is required for signin
    pub fn is_verification_required(&self) -> bool {
        self.config.require_verification_for_signin
    }
    
    /// Check if user is verified or verification is not required
    pub async fn is_user_verified_or_not_required(&self, user: &User) -> bool {
        user.email_verified || !self.config.require_verification_for_signin
    }
}
