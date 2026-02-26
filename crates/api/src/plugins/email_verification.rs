use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateVerification, HttpMethod, UpdateUser};
use better_auth_core::{
    AuthSession, AuthUser, AuthVerification, DatabaseAdapter, SessionManager, User,
};

/// Trait for custom email sending logic.
///
/// When set on [`EmailVerificationConfig::send_verification_email`], this
/// callback overrides the default `EmailProvider`-based sending.
#[async_trait]
pub trait SendVerificationEmail: Send + Sync {
    async fn send(&self, user: &User, url: &str, token: &str) -> AuthResult<()>;
}

/// Shorthand for the async hook closure type used by
/// [`EmailVerificationConfig::before_email_verification`] and
/// [`EmailVerificationConfig::after_email_verification`].
pub type EmailVerificationHook =
    Arc<dyn Fn(&User) -> Pin<Box<dyn Future<Output = AuthResult<()>> + Send>> + Send + Sync>;

/// Convert any `AuthUser` implementor into the concrete [`User`] type so that
/// it can be passed to hooks and callbacks that require a known, sized type.
fn to_user(u: &impl AuthUser) -> User {
    User {
        id: u.id().to_owned(),
        name: u.name().map(str::to_owned),
        email: u.email().map(str::to_owned),
        email_verified: u.email_verified(),
        image: u.image().map(str::to_owned),
        created_at: u.created_at(),
        updated_at: u.updated_at(),
        username: u.username().map(str::to_owned),
        display_username: u.display_username().map(str::to_owned),
        two_factor_enabled: u.two_factor_enabled(),
        role: u.role().map(str::to_owned),
        banned: u.banned(),
        ban_reason: u.ban_reason().map(str::to_owned),
        ban_expires: u.ban_expires(),
        metadata: u.metadata().clone(),
    }
}

/// Email verification plugin for handling email verification flows
pub struct EmailVerificationPlugin {
    config: EmailVerificationConfig,
}

pub struct EmailVerificationConfig {
    /// How long a verification token stays valid. Default: 1 hour.
    pub verification_token_expiry: Duration,
    /// Whether to send email notifications (on sign-up). Default: true.
    pub send_email_notifications: bool,
    /// Whether email verification is required before sign-in. Default: false.
    pub require_verification_for_signin: bool,
    /// Whether to auto-verify newly created users. Default: false.
    pub auto_verify_new_users: bool,
    /// When true, automatically send a verification email on sign-in if the
    /// user is unverified. Default: false.
    pub send_on_sign_in: bool,
    /// When true, create a session after email verification and return the
    /// session token in the verify-email response. Default: false.
    pub auto_sign_in_after_verification: bool,
    /// Optional custom email sender. When set this overrides the default
    /// `EmailProvider`-based sending.
    pub send_verification_email: Option<Arc<dyn SendVerificationEmail>>,
    /// Hook invoked **before** email verification (before updating the user).
    pub before_email_verification: Option<EmailVerificationHook>,
    /// Hook invoked **after** email verification (after the user has been updated).
    pub after_email_verification: Option<EmailVerificationHook>,
}

impl EmailVerificationConfig {
    /// Backward-compatible helper: return the expiry duration expressed as
    /// whole hours (truncated).
    pub fn expiry_hours(&self) -> i64 {
        self.verification_token_expiry.num_hours()
    }
}

// Request structures for email verification endpoints
#[derive(Debug, Deserialize, Validate)]
struct SendVerificationEmailRequest {
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

// Response structures
#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

#[derive(Debug, Serialize)]
struct VerifyEmailResponse<U: Serialize> {
    user: U,
    status: bool,
}

#[derive(Debug, Serialize)]
struct VerifyEmailWithSessionResponse<U: Serialize, S: Serialize> {
    user: U,
    session: S,
    status: bool,
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

    /// Set the token expiry as a [`Duration`].
    pub fn verification_token_expiry(mut self, duration: Duration) -> Self {
        self.config.verification_token_expiry = duration;
        self
    }

    /// Backward-compatible builder: set token expiry in hours.
    pub fn verification_token_expiry_hours(mut self, hours: i64) -> Self {
        self.config.verification_token_expiry = Duration::hours(hours);
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

    pub fn send_on_sign_in(mut self, send: bool) -> Self {
        self.config.send_on_sign_in = send;
        self
    }

    pub fn auto_sign_in_after_verification(mut self, auto_sign_in: bool) -> Self {
        self.config.auto_sign_in_after_verification = auto_sign_in;
        self
    }

    pub fn custom_send_verification_email(
        mut self,
        sender: Arc<dyn SendVerificationEmail>,
    ) -> Self {
        self.config.send_verification_email = Some(sender);
        self
    }

    pub fn before_email_verification(mut self, hook: EmailVerificationHook) -> Self {
        self.config.before_email_verification = Some(hook);
        self
    }

    pub fn after_email_verification(mut self, hook: EmailVerificationHook) -> Self {
        self.config.after_email_verification = Some(hook);
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
            verification_token_expiry: Duration::hours(1),
            send_email_notifications: true,
            require_verification_for_signin: false,
            auto_verify_new_users: false,
            send_on_sign_in: false,
            auto_sign_in_after_verification: false,
            send_verification_email: None,
            before_email_verification: None,
            after_email_verification: None,
        }
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for EmailVerificationPlugin {
    fn name(&self) -> &'static str {
        "email-verification"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/send-verification-email", "send_verification_email"),
            AuthRoute::get("/verify-email", "verify_email"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/send-verification-email") => {
                Ok(Some(self.handle_send_verification_email(req, ctx).await?))
            }
            (HttpMethod::Get, "/verify-email") => {
                Ok(Some(self.handle_verify_email(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }

    async fn on_user_created(&self, user: &DB::User, ctx: &AuthContext<DB>) -> AuthResult<()> {
        // Send verification email for new users if configured.
        // Also fire when a custom sender is set, even if send_email_notifications is false.
        if (self.config.send_email_notifications || self.config.send_verification_email.is_some())
            && !user.email_verified()
            && let Some(email) = user.email()
            && let Err(e) = self
                .send_verification_email_for_user(user, email, None, ctx)
                .await
        {
            eprintln!(
                "[email-verification] Failed to send verification email to {}: {}",
                email, e
            );
        }
        Ok(())
    }
}

// Implementation methods outside the trait
impl EmailVerificationPlugin {
    async fn handle_send_verification_email<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let send_req: SendVerificationEmailRequest =
            match better_auth_core::validate_request_body(req) {
                Ok(v) => v,
                Err(resp) => return Ok(resp),
            };

        // Check if user exists
        let user = ctx
            .database
            .get_user_by_email(&send_req.email)
            .await?
            .ok_or_else(|| AuthError::not_found("No user found with this email address"))?;

        // Check if user is already verified
        if user.email_verified() {
            return Err(AuthError::bad_request("Email is already verified"));
        }

        // Send verification email
        self.send_verification_email_for_user(
            &user,
            &send_req.email,
            send_req.callback_url.as_deref(),
            ctx,
        )
        .await?;

        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_verify_email<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        // Extract token from query parameters
        let token = req
            .query
            .get("token")
            .ok_or_else(|| AuthError::bad_request("Verification token is required"))?;

        let callback_url = req.query.get("callbackURL");

        // Find verification token
        let verification = ctx
            .database
            .get_verification_by_value(token)
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid or expired verification token"))?;

        // Get user by email (stored in identifier field)
        let user = ctx
            .database
            .get_user_by_email(verification.identifier())
            .await?
            .ok_or_else(|| AuthError::not_found("User associated with this token not found"))?;

        // Check if already verified
        if user.email_verified() {
            let response = VerifyEmailResponse { user, status: true };
            return Ok(AuthResponse::json(200, &response)?);
        }

        // Run before_email_verification hook
        if let Some(ref hook) = self.config.before_email_verification {
            hook(&to_user(&user)).await?;
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

        let updated_user = ctx.database.update_user(user.id(), update_user).await?;

        // Delete the used verification token
        ctx.database.delete_verification(verification.id()).await?;

        // Run after_email_verification hook
        if let Some(ref hook) = self.config.after_email_verification {
            hook(&to_user(&updated_user)).await?;
        }

        // Optionally create a session when auto_sign_in_after_verification is
        // enabled.  The cookie is attached to **both** the redirect and the
        // JSON responses below.
        let session_cookie = if self.config.auto_sign_in_after_verification {
            let ip_address = req.headers.get("x-forwarded-for").cloned();
            let user_agent = req.headers.get("user-agent").cloned();
            let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
            let session = session_manager
                .create_session(&updated_user, ip_address, user_agent)
                .await?;
            Some((Self::create_session_cookie(session.token(), ctx), session))
        } else {
            None
        };

        // If callback URL is provided, redirect
        if let Some(callback_url) = callback_url {
            let redirect_url = format!("{}?verified=true", callback_url);
            let mut headers = std::collections::HashMap::new();
            headers.insert("Location".to_string(), redirect_url);
            if let Some((cookie, _)) = &session_cookie {
                headers.insert("Set-Cookie".to_string(), cookie.clone());
            }
            return Ok(AuthResponse {
                status: 302,
                headers,
                body: Vec::new(),
            });
        }

        // Return JSON — include session when auto sign-in was performed
        if let Some((cookie_header, session)) = session_cookie {
            let response = VerifyEmailWithSessionResponse {
                user: updated_user,
                session,
                status: true,
            };
            return Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header));
        }

        let response = VerifyEmailResponse {
            user: updated_user,
            status: true,
        };
        Ok(AuthResponse::json(200, &response)?)
    }

    /// Send a verification email for a specific user.
    ///
    /// If [`EmailVerificationConfig::send_verification_email`] is set the
    /// custom callback is used; otherwise the default `EmailProvider` path is
    /// taken.
    async fn send_verification_email_for_user<DB: DatabaseAdapter>(
        &self,
        user: &DB::User,
        email: &str,
        callback_url: Option<&str>,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        // Generate verification token
        let verification_token = format!("verify_{}", Uuid::new_v4());
        let expires_at = Utc::now() + self.config.verification_token_expiry;

        // Create verification token
        let create_verification = CreateVerification {
            identifier: email.to_string(),
            value: verification_token.clone(),
            expires_at,
        };

        ctx.database
            .create_verification(create_verification)
            .await?;

        let verification_url = if let Some(callback_url) = callback_url {
            format!("{}?token={}", callback_url, verification_token)
        } else {
            format!(
                "{}/verify-email?token={}",
                ctx.config.base_url, verification_token
            )
        };

        // Use custom sender if configured, otherwise fall back to EmailProvider
        if let Some(ref custom_sender) = self.config.send_verification_email {
            custom_sender
                .send(&to_user(user), &verification_url, &verification_token)
                .await?;
        } else if self.config.send_email_notifications {
            // Gracefully skip if no email provider is configured
            if ctx.email_provider.is_some() {
                let subject = "Verify your email address";
                let html = format!(
                    "<p>Click the link below to verify your email address:</p>\
                     <p><a href=\"{url}\">Verify Email</a></p>",
                    url = verification_url
                );
                let text = format!("Verify your email address: {}", verification_url);

                ctx.email_provider()?
                    .send(email, subject, &html, &text)
                    .await?;
            } else {
                eprintln!(
                    "[email-verification] No email provider configured, skipping verification email for {}",
                    email
                );
            }
        }

        Ok(())
    }

    /// Send a verification email on sign-in for an unverified user.
    ///
    /// Callers (e.g. the sign-in plugin) should invoke this when
    /// [`EmailVerificationConfig::send_on_sign_in`] is `true` and the user is
    /// not yet verified.
    pub async fn send_verification_on_sign_in<DB: DatabaseAdapter>(
        &self,
        user: &DB::User,
        callback_url: Option<&str>,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        if !self.config.send_on_sign_in {
            return Ok(());
        }

        if user.email_verified() {
            return Ok(());
        }

        if let Some(email) = user.email() {
            self.send_verification_email_for_user(user, email, callback_url, ctx)
                .await?;
        }

        Ok(())
    }

    /// Check if `send_on_sign_in` is enabled.
    pub fn should_send_on_sign_in(&self) -> bool {
        self.config.send_on_sign_in
    }

    /// Check if email verification is required for signin
    pub fn is_verification_required(&self) -> bool {
        self.config.require_verification_for_signin
    }

    /// Check if user is verified or verification is not required
    pub async fn is_user_verified_or_not_required(&self, user: &impl AuthUser) -> bool {
        user.email_verified() || !self.config.require_verification_for_signin
    }

    /// Build a `Set-Cookie` header value for a session token.
    fn create_session_cookie<DB: DatabaseAdapter>(token: &str, ctx: &AuthContext<DB>) -> String {
        let session_config = &ctx.config.session;
        let secure = if session_config.cookie_secure {
            "; Secure"
        } else {
            ""
        };
        let http_only = if session_config.cookie_http_only {
            "; HttpOnly"
        } else {
            ""
        };
        let same_site = match session_config.cookie_same_site {
            better_auth_core::config::SameSite::Strict => "; SameSite=Strict",
            better_auth_core::config::SameSite::Lax => "; SameSite=Lax",
            better_auth_core::config::SameSite::None => "; SameSite=None",
        };

        let expires = Utc::now() + session_config.expires_in;
        let expires_str = expires.format("%a, %d %b %Y %H:%M:%S GMT");

        format!(
            "{}={}; Path=/; Expires={}{}{}{}",
            session_config.cookie_name, token, expires_str, secure, http_only, same_site
        )
    }
}
