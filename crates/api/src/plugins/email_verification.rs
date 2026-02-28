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

use better_auth_core::utils::cookie_utils::create_session_cookie;

use super::StatusResponse;

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
pub(crate) struct SendVerificationEmailRequest {
    #[validate(email(message = "Invalid email address"))]
    pub(crate) email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Query parameters for `GET /verify-email`.
#[derive(Debug, Deserialize)]
pub(crate) struct VerifyEmailQuery {
    pub(crate) token: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

// Response structures

#[derive(Debug, Serialize)]
pub(crate) struct VerifyEmailResponse<U: Serialize> {
    pub(crate) user: U,
    pub(crate) status: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyEmailWithSessionResponse<U: Serialize, S: Serialize> {
    pub(crate) user: U,
    pub(crate) session: S,
    pub(crate) status: bool,
}

/// Result of the verify-email core function.
pub(crate) enum VerifyEmailResult<U: Serialize, S: Serialize> {
    /// Already verified -- return JSON with user.
    AlreadyVerified(VerifyEmailResponse<U>),
    /// Redirect to callback URL with optional session cookie.
    Redirect {
        url: String,
        session_token: Option<String>,
    },
    /// JSON response with user only (no auto sign-in).
    Json(VerifyEmailResponse<U>),
    /// JSON response with user + session (auto sign-in).
    JsonWithSession {
        response: VerifyEmailWithSessionResponse<U, S>,
        session_token: String,
    },
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
            verification_token_expiry: Duration::hours(24),
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
            tracing::warn!(
                email = %email,
                error = %e,
                "Failed to send verification email"
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Route handlers (delegate to core functions)
// ---------------------------------------------------------------------------

impl EmailVerificationPlugin {
    async fn handle_send_verification_email<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let body: SendVerificationEmailRequest =
            match better_auth_core::validate_request_body(req) {
                Ok(v) => v,
                Err(resp) => return Ok(resp),
            };
        let response =
            send_verification_email_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_verify_email<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let token = req
            .query
            .get("token")
            .ok_or_else(|| AuthError::bad_request("Verification token is required"))?;
        let callback_url = req.query.get("callbackURL").cloned();
        let query = VerifyEmailQuery {
            token: token.clone(),
            callback_url,
        };

        let ip_address = req.headers.get("x-forwarded-for").cloned();
        let user_agent = req.headers.get("user-agent").cloned();

        match verify_email_core(&query, &self.config, ip_address, user_agent, ctx).await? {
            VerifyEmailResult::AlreadyVerified(data) => {
                Ok(AuthResponse::json(200, &data)?)
            }
            VerifyEmailResult::Redirect { url, session_token } => {
                let mut headers = std::collections::HashMap::new();
                headers.insert("Location".to_string(), url);
                if let Some(token) = session_token {
                    let cookie = create_session_cookie(&token, &ctx.config);
                    headers.insert("Set-Cookie".to_string(), cookie);
                }
                Ok(AuthResponse {
                    status: 302,
                    headers,
                    body: Vec::new(),
                })
            }
            VerifyEmailResult::Json(data) => {
                Ok(AuthResponse::json(200, &data)?)
            }
            VerifyEmailResult::JsonWithSession { response, session_token } => {
                let cookie = create_session_cookie(&session_token, &ctx.config);
                Ok(AuthResponse::json(200, &response)?
                    .with_header("Set-Cookie", cookie))
            }
        }
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
            let user = User::from(user);
            custom_sender
                .send(&user, &verification_url, &verification_token)
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
                tracing::warn!(
                    email = %email,
                    "No email provider configured, skipping verification email"
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
}

// ---------------------------------------------------------------------------
// Core functions (framework-agnostic business logic)
// ---------------------------------------------------------------------------

pub(crate) async fn send_verification_email_core<DB: DatabaseAdapter>(
    body: &SendVerificationEmailRequest,
    config: &EmailVerificationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Check if user exists
    let user = ctx
        .database
        .get_user_by_email(&body.email)
        .await?
        .ok_or_else(|| AuthError::not_found("No user found with this email address"))?;

    // Check if user is already verified
    if user.email_verified() {
        return Err(AuthError::bad_request("Email is already verified"));
    }

    // Generate verification token
    let verification_token = format!("verify_{}", Uuid::new_v4());
    let expires_at = Utc::now() + config.verification_token_expiry;

    let create_verification = CreateVerification {
        identifier: body.email.to_string(),
        value: verification_token.clone(),
        expires_at,
    };

    ctx.database
        .create_verification(create_verification)
        .await?;

    let verification_url = if let Some(ref callback_url) = body.callback_url {
        format!("{}?token={}", callback_url, verification_token)
    } else {
        format!(
            "{}/verify-email?token={}",
            ctx.config.base_url, verification_token
        )
    };

    // Use custom sender if configured, otherwise fall back to EmailProvider
    if let Some(ref custom_sender) = config.send_verification_email {
        let user = User::from(&user);
        custom_sender
            .send(&user, &verification_url, &verification_token)
            .await?;
    } else if config.send_email_notifications {
        if ctx.email_provider.is_some() {
            let subject = "Verify your email address";
            let html = format!(
                "<p>Click the link below to verify your email address:</p>\
                 <p><a href=\"{url}\">Verify Email</a></p>",
                url = verification_url
            );
            let text = format!("Verify your email address: {}", verification_url);

            ctx.email_provider()?
                .send(&body.email, subject, &html, &text)
                .await?;
        } else {
            tracing::warn!(
                email = %body.email,
                "No email provider configured, skipping verification email"
            );
        }
    }

    Ok(StatusResponse { status: true })
}

pub(crate) async fn verify_email_core<DB: DatabaseAdapter>(
    query: &VerifyEmailQuery,
    config: &EmailVerificationConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<DB>,
) -> AuthResult<VerifyEmailResult<DB::User, DB::Session>> {
    // Find verification token
    let verification = ctx
        .database
        .get_verification_by_value(&query.token)
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
        return Ok(VerifyEmailResult::AlreadyVerified(VerifyEmailResponse {
            user,
            status: true,
        }));
    }

    // Run before_email_verification hook
    if let Some(ref hook) = config.before_email_verification {
        let hook_user = User::from(&user);
        hook(&hook_user).await?;
    }

    // Update user email verification status
    let update_user = UpdateUser {
        email_verified: Some(true),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(user.id(), update_user).await?;

    // Delete the used verification token
    ctx.database.delete_verification(verification.id()).await?;

    // Run after_email_verification hook
    if let Some(ref hook) = config.after_email_verification {
        let hook_user = User::from(&updated_user);
        hook(&hook_user).await?;
    }

    // Optionally create a session when auto_sign_in_after_verification is enabled.
    let session_info = if config.auto_sign_in_after_verification {
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager
            .create_session(&updated_user, ip_address, user_agent)
            .await?;
        let token = session.token().to_string();
        Some((session, token))
    } else {
        None
    };

    // If callback URL is provided, redirect
    if let Some(ref callback_url) = query.callback_url {
        let redirect_url = format!("{}?verified=true", callback_url);
        return Ok(VerifyEmailResult::Redirect {
            url: redirect_url,
            session_token: session_info.map(|(_, t)| t),
        });
    }

    // Return JSON
    match session_info {
        Some((session, token)) => Ok(VerifyEmailResult::JsonWithSession {
            response: VerifyEmailWithSessionResponse {
                user: updated_user,
                session,
                status: true,
            },
            session_token: token,
        }),
        None => Ok(VerifyEmailResult::Json(VerifyEmailResponse {
            user: updated_user,
            status: true,
        })),
    }
}

// ---------------------------------------------------------------------------
// Axum plugin
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::extract::{Extension, Query, State};
    use axum::response::IntoResponse;
    use axum::{Json, http::header};
    use better_auth_core::{AuthError, AuthState, ValidatedJson};

    /// Plugin state stored as an axum extension.
    ///
    /// `EmailVerificationConfig` is NOT Clone (callback fields are `Arc<dyn ...>`
    /// without `Clone`), so we clone each field individually.
    struct PluginState {
        config: EmailVerificationConfig,
    }

    fn clone_config(c: &EmailVerificationConfig) -> EmailVerificationConfig {
        EmailVerificationConfig {
            verification_token_expiry: c.verification_token_expiry,
            send_email_notifications: c.send_email_notifications,
            require_verification_for_signin: c.require_verification_for_signin,
            auto_verify_new_users: c.auto_verify_new_users,
            send_on_sign_in: c.send_on_sign_in,
            auto_sign_in_after_verification: c.auto_sign_in_after_verification,
            send_verification_email: c.send_verification_email.clone(),
            before_email_verification: c.before_email_verification.clone(),
            after_email_verification: c.after_email_verification.clone(),
        }
    }

    async fn handle_send_verification_email<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        ValidatedJson(body): ValidatedJson<SendVerificationEmailRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let response =
            send_verification_email_core(&body, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_verify_email<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        Query(query): Query<VerifyEmailQuery>,
    ) -> Result<axum::response::Response, AuthError> {
        let ctx = state.to_context();
        // Note: axum Query extractor doesn't give us headers; pass None for
        // ip/user-agent (these are only used for session creation metadata).
        match verify_email_core(&query, &ps.config, None, None, &ctx).await? {
            VerifyEmailResult::AlreadyVerified(data) => {
                Ok(Json(data).into_response())
            }
            VerifyEmailResult::Redirect { url, session_token } => {
                if let Some(token) = session_token {
                    let cookie = state.session_cookie(&token);
                    Ok((
                        [(header::SET_COOKIE, cookie)],
                        axum::response::Redirect::to(&url),
                    )
                        .into_response())
                } else {
                    Ok(axum::response::Redirect::to(&url).into_response())
                }
            }
            VerifyEmailResult::Json(data) => {
                Ok(Json(data).into_response())
            }
            VerifyEmailResult::JsonWithSession { response, session_token } => {
                let cookie = state.session_cookie(&session_token);
                Ok((
                    [(header::SET_COOKIE, cookie)],
                    Json(response),
                )
                    .into_response())
            }
        }
    }

    #[async_trait::async_trait]
    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for EmailVerificationPlugin {
        fn name(&self) -> &'static str {
            "email-verification"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: clone_config(&self.config),
            });

            axum::Router::new()
                .route(
                    "/send-verification-email",
                    post(handle_send_verification_email::<DB>),
                )
                .route("/verify-email", get(handle_verify_email::<DB>))
                .layer(Extension(plugin_state))
        }

        async fn on_user_created(
            &self,
            user: &DB::User,
            ctx: &better_auth_core::AuthContext<DB>,
        ) -> better_auth_core::AuthResult<()> {
            // Delegate to the AuthPlugin implementation logic
            if (self.config.send_email_notifications
                || self.config.send_verification_email.is_some())
                && !user.email_verified()
                && let Some(email) = user.email()
                && let Err(e) = self
                    .send_verification_email_for_user(user, email, None, ctx)
                    .await
            {
                tracing::warn!(
                    email = %email,
                    error = %e,
                    "Failed to send verification email"
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::adapters::{MemoryDatabaseAdapter, UserOps, VerificationOps};
    use better_auth_core::{CreateUser, CreateVerification};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ------------------------------------------------------------------
    // Config defaults
    // ------------------------------------------------------------------

    #[test]
    fn test_default_config() {
        let config = EmailVerificationConfig::default();
        assert_eq!(config.verification_token_expiry, Duration::hours(24));
        assert!(config.send_email_notifications);
        assert!(!config.require_verification_for_signin);
        assert!(!config.auto_verify_new_users);
        assert!(!config.send_on_sign_in);
        assert!(!config.auto_sign_in_after_verification);
        assert!(config.send_verification_email.is_none());
        assert!(config.before_email_verification.is_none());
        assert!(config.after_email_verification.is_none());
    }

    #[test]
    fn test_expiry_hours_helper() {
        let config = EmailVerificationConfig {
            verification_token_expiry: Duration::hours(3),
            ..Default::default()
        };
        assert_eq!(config.expiry_hours(), 3);
    }

    #[test]
    fn test_expiry_hours_truncates() {
        let config = EmailVerificationConfig {
            verification_token_expiry: Duration::minutes(90), // 1.5 hours
            ..Default::default()
        };
        assert_eq!(config.expiry_hours(), 1); // truncated
    }

    // ------------------------------------------------------------------
    // Builder methods
    // ------------------------------------------------------------------

    #[test]
    fn test_builder_verification_token_expiry() {
        let plugin =
            EmailVerificationPlugin::new().verification_token_expiry(Duration::minutes(30));
        assert_eq!(
            plugin.config.verification_token_expiry,
            Duration::minutes(30)
        );
    }

    #[test]
    fn test_builder_verification_token_expiry_hours() {
        let plugin = EmailVerificationPlugin::new().verification_token_expiry_hours(12);
        assert_eq!(plugin.config.verification_token_expiry, Duration::hours(12));
    }

    #[test]
    fn test_builder_send_on_sign_in() {
        let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
        assert!(plugin.config.send_on_sign_in);
    }

    #[test]
    fn test_builder_auto_sign_in_after_verification() {
        let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);
        assert!(plugin.config.auto_sign_in_after_verification);
    }

    #[test]
    fn test_builder_send_email_notifications() {
        let plugin = EmailVerificationPlugin::new().send_email_notifications(false);
        assert!(!plugin.config.send_email_notifications);
    }

    #[test]
    fn test_builder_require_verification_for_signin() {
        let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
        assert!(plugin.config.require_verification_for_signin);
    }

    #[test]
    fn test_builder_auto_verify_new_users() {
        let plugin = EmailVerificationPlugin::new().auto_verify_new_users(true);
        assert!(plugin.config.auto_verify_new_users);
    }

    #[test]
    fn test_builder_chaining() {
        let plugin = EmailVerificationPlugin::new()
            .verification_token_expiry(Duration::hours(2))
            .send_on_sign_in(true)
            .auto_sign_in_after_verification(true)
            .send_email_notifications(false)
            .require_verification_for_signin(true);
        assert_eq!(plugin.config.verification_token_expiry, Duration::hours(2));
        assert!(plugin.config.send_on_sign_in);
        assert!(plugin.config.auto_sign_in_after_verification);
        assert!(!plugin.config.send_email_notifications);
        assert!(plugin.config.require_verification_for_signin);
    }

    // ------------------------------------------------------------------
    // Custom sender builder
    // ------------------------------------------------------------------

    struct DummySender;

    #[async_trait]
    impl SendVerificationEmail for DummySender {
        async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
            Ok(())
        }
    }

    #[test]
    fn test_builder_custom_send_verification_email() {
        let plugin =
            EmailVerificationPlugin::new().custom_send_verification_email(Arc::new(DummySender));
        assert!(plugin.config.send_verification_email.is_some());
    }

    // ------------------------------------------------------------------
    // Hook builders
    // ------------------------------------------------------------------

    #[test]
    fn test_builder_before_email_verification_hook() {
        let hook: EmailVerificationHook = Arc::new(|_user: &User| Box::pin(async { Ok(()) }));
        let plugin = EmailVerificationPlugin::new().before_email_verification(hook);
        assert!(plugin.config.before_email_verification.is_some());
    }

    #[test]
    fn test_builder_after_email_verification_hook() {
        let hook: EmailVerificationHook = Arc::new(|_user: &User| Box::pin(async { Ok(()) }));
        let plugin = EmailVerificationPlugin::new().after_email_verification(hook);
        assert!(plugin.config.after_email_verification.is_some());
    }

    // ------------------------------------------------------------------
    // Helper methods
    // ------------------------------------------------------------------

    #[test]
    fn test_should_send_on_sign_in() {
        let plugin = EmailVerificationPlugin::new();
        assert!(!plugin.should_send_on_sign_in());

        let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
        assert!(plugin.should_send_on_sign_in());
    }

    #[test]
    fn test_is_verification_required() {
        let plugin = EmailVerificationPlugin::new();
        assert!(!plugin.is_verification_required());

        let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
        assert!(plugin.is_verification_required());
    }

    /// Helper to create a minimal User for unit tests.
    fn make_test_user(email: &str, verified: bool) -> User {
        User {
            id: "test-id".into(),
            name: Some("Test".into()),
            email: Some(email.into()),
            email_verified: verified,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: None,
            display_username: None,
            two_factor_enabled: false,
            role: None,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn test_is_user_verified_or_not_required() {
        let plugin = EmailVerificationPlugin::new();
        let user = make_test_user("a@b.com", false);
        // verification not required → true even if unverified
        assert!(plugin.is_user_verified_or_not_required(&user).await);

        let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
        // verification required + unverified → false
        assert!(!plugin.is_user_verified_or_not_required(&user).await);

        let verified_user = make_test_user("a@b.com", true);
        // verified → always true
        assert!(
            plugin
                .is_user_verified_or_not_required(&verified_user)
                .await
        );
    }

    // ------------------------------------------------------------------
    // to_user conversion
    // ------------------------------------------------------------------

    #[test]
    fn test_to_user_preserves_fields() {
        let user = User {
            id: "test-id".into(),
            name: Some("Test User".into()),
            email: Some("test@example.com".into()),
            email_verified: true,
            image: Some("https://img.example.com/a.png".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: Some("testuser".into()),
            display_username: Some("TestUser".into()),
            two_factor_enabled: true,
            role: Some("admin".into()),
            banned: true,
            ban_reason: Some("spam".into()),
            ban_expires: None,
            metadata: serde_json::Value::Null,
        };
        let converted = User::from(&user);
        assert_eq!(converted.id, "test-id");
        assert_eq!(converted.name.as_deref(), Some("Test User"));
        assert_eq!(converted.email.as_deref(), Some("test@example.com"));
        assert!(converted.email_verified);
        assert_eq!(
            converted.image.as_deref(),
            Some("https://img.example.com/a.png")
        );
        assert_eq!(converted.username.as_deref(), Some("testuser"));
        assert_eq!(converted.display_username.as_deref(), Some("TestUser"));
        assert!(converted.two_factor_enabled);
        assert_eq!(converted.role.as_deref(), Some("admin"));
        assert!(converted.banned);
        assert_eq!(converted.ban_reason.as_deref(), Some("spam"));
    }

    // ------------------------------------------------------------------
    // Plugin trait basics
    // ------------------------------------------------------------------

    #[test]
    fn test_plugin_name() {
        let plugin = EmailVerificationPlugin::new();
        assert_eq!(
            AuthPlugin::<MemoryDatabaseAdapter>::name(&plugin),
            "email-verification"
        );
    }

    #[test]
    fn test_plugin_routes() {
        let plugin = EmailVerificationPlugin::new();
        let routes = AuthPlugin::<MemoryDatabaseAdapter>::routes(&plugin);
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/send-verification-email" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/verify-email" && r.method == HttpMethod::Get)
        );
    }

    #[tokio::test]
    async fn test_on_request_unknown_route_returns_none() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();
        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/unknown",
            None,
            None,
            HashMap::new(),
        );
        let result = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // send_verification_on_sign_in
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_send_verification_on_sign_in_disabled() {
        let plugin = EmailVerificationPlugin::new().send_on_sign_in(false);
        let ctx = test_helpers::create_test_context();
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("unverified@test.com")
                    .with_name("Test"),
            )
            .await
            .unwrap();
        // Should return Ok(()) immediately when disabled
        plugin
            .send_verification_on_sign_in(&user, None, &ctx)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_send_verification_on_sign_in_verified_user() {
        let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
        let ctx = test_helpers::create_test_context();
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("verified@test.com")
                    .with_name("Test"),
            )
            .await
            .unwrap();
        // Mark user as verified
        let update = UpdateUser {
            email_verified: Some(true),
            ..Default::default()
        };
        let verified = ctx.database.update_user(&user.id, update).await.unwrap();
        // Should return Ok(()) for already-verified user
        plugin
            .send_verification_on_sign_in(&verified, None, &ctx)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_send_verification_on_sign_in_creates_token() {
        // Use a custom sender that records calls instead of needing an
        // email provider.
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();
        struct CountingSender(Arc<AtomicU32>);
        #[async_trait]
        impl SendVerificationEmail for CountingSender {
            async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let plugin = EmailVerificationPlugin::new()
            .send_on_sign_in(true)
            .send_email_notifications(false) // disable default path
            .custom_send_verification_email(Arc::new(CountingSender(counter)));

        let ctx = test_helpers::create_test_context();
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("unverified@test.com")
                    .with_name("Test"),
            )
            .await
            .unwrap();

        plugin
            .send_verification_on_sign_in(&user, None, &ctx)
            .await
            .unwrap();

        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    // ------------------------------------------------------------------
    // on_user_created – custom sender fires even when
    // send_email_notifications is false
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_on_user_created_custom_sender_fires_without_notifications() {
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();
        struct CountingSender(Arc<AtomicU32>);
        #[async_trait]
        impl SendVerificationEmail for CountingSender {
            async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let plugin = EmailVerificationPlugin::new()
            .send_email_notifications(false)
            .custom_send_verification_email(Arc::new(CountingSender(counter)));

        let ctx = test_helpers::create_test_context();
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("newuser@test.com")
                    .with_name("New"),
            )
            .await
            .unwrap();

        plugin.on_user_created(&user, &ctx).await.unwrap();

        // Custom sender should have been called even though
        // send_email_notifications is false.
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_on_user_created_verified_user_skips_email() {
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();
        struct CountingSender(Arc<AtomicU32>);
        #[async_trait]
        impl SendVerificationEmail for CountingSender {
            async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let plugin = EmailVerificationPlugin::new()
            .custom_send_verification_email(Arc::new(CountingSender(counter)));

        let ctx = test_helpers::create_test_context();
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("newuser@test.com")
                    .with_name("New"),
            )
            .await
            .unwrap();
        // Mark verified
        let update = UpdateUser {
            email_verified: Some(true),
            ..Default::default()
        };
        let verified = ctx.database.update_user(&user.id, update).await.unwrap();

        plugin.on_user_created(&verified, &ctx).await.unwrap();

        // Should NOT have been called because user is already verified.
        assert_eq!(call_count.load(Ordering::Relaxed), 0);
    }

    // ------------------------------------------------------------------
    // handle_verify_email – basic flow
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_email_basic_flow() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();

        // Create an unverified user
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("verify@test.com")
                    .with_name("Verify Me"),
            )
            .await
            .unwrap();

        // Create a verification token
        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "verify@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        // Call verify-email
        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value.clone());
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], true);
        assert_eq!(body["user"]["email"], "verify@test.com");

        // User should now be verified in the database
        let updated = ctx
            .database
            .get_user_by_email("verify@test.com")
            .await
            .unwrap()
            .unwrap();
        assert!(updated.email_verified);

        // Verification token should be deleted
        let v = ctx
            .database
            .get_verification_by_value(&token_value)
            .await
            .unwrap();
        assert!(v.is_none());
    }

    // ------------------------------------------------------------------
    // handle_verify_email – hooks are called
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_email_calls_before_and_after_hooks() {
        let before_count = Arc::new(AtomicU32::new(0));
        let after_count = Arc::new(AtomicU32::new(0));
        let bc = before_count.clone();
        let ac = after_count.clone();

        let before_hook: EmailVerificationHook = Arc::new(move |_user: &User| {
            let c = bc.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        });
        let after_hook: EmailVerificationHook = Arc::new(move |_user: &User| {
            let c = ac.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        });

        let plugin = EmailVerificationPlugin::new()
            .before_email_verification(before_hook)
            .after_email_verification(after_hook);

        let ctx = test_helpers::create_test_context();
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("hooks@test.com")
                    .with_name("Hooks"),
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "hooks@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value);
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        assert_eq!(before_count.load(Ordering::Relaxed), 1);
        assert_eq!(after_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_verify_email_before_hook_error_aborts() {
        let before_hook: EmailVerificationHook =
            Arc::new(|_user: &User| Box::pin(async { Err(AuthError::forbidden("hook rejected")) }));

        let plugin = EmailVerificationPlugin::new().before_email_verification(before_hook);

        let ctx = test_helpers::create_test_context();
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("hook-err@test.com")
                    .with_name("HookErr"),
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "hook-err@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value.clone());
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 403);

        // User should still be unverified
        let u = ctx
            .database
            .get_user_by_email("hook-err@test.com")
            .await
            .unwrap()
            .unwrap();
        assert!(!u.email_verified);
    }

    // ------------------------------------------------------------------
    // handle_verify_email – auto_sign_in_after_verification
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_email_auto_sign_in_creates_session() {
        let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);

        let ctx = test_helpers::create_test_context();
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("autosign@test.com")
                    .with_name("AutoSign"),
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "autosign@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value);
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], true);
        // Session should be present
        assert!(body["session"]["token"].is_string());

        // Set-Cookie header should be present
        assert!(response.headers.contains_key("Set-Cookie"));
        let cookie_header = &response.headers["Set-Cookie"];
        assert!(cookie_header.contains("better-auth.session"));
    }

    #[tokio::test]
    async fn test_verify_email_no_auto_sign_in_no_session() {
        let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(false);

        let ctx = test_helpers::create_test_context();
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("noautosign@test.com")
                    .with_name("NoAutoSign"),
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "noautosign@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value);
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], true);
        // No session field expected
        assert!(body.get("session").is_none());
        // No Set-Cookie header expected
        assert!(!response.headers.contains_key("Set-Cookie"));
    }

    // ------------------------------------------------------------------
    // handle_verify_email – auto_sign_in + callbackURL → 302 with cookie
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_email_auto_sign_in_redirect_includes_cookie() {
        let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);

        let ctx = test_helpers::create_test_context();
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("redirect@test.com")
                    .with_name("Redirect"),
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "redirect@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value);
        query.insert(
            "callbackURL".to_string(),
            "https://myapp.com/verified".to_string(),
        );
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 302);
        assert!(
            response.headers["Location"].starts_with("https://myapp.com/verified?verified=true")
        );
        // Session cookie should be present on the redirect
        assert!(response.headers.contains_key("Set-Cookie"));
        assert!(response.headers["Set-Cookie"].contains("better-auth.session"));
    }

    #[tokio::test]
    async fn test_verify_email_redirect_without_auto_sign_in_no_cookie() {
        let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(false);

        let ctx = test_helpers::create_test_context();
        let _user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("redir-nocookie@test.com")
                    .with_name("Redir"),
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "redir-nocookie@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value);
        query.insert(
            "callbackURL".to_string(),
            "https://myapp.com/verified".to_string(),
        );
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 302);
        assert!(!response.headers.contains_key("Set-Cookie"));
    }

    // ------------------------------------------------------------------
    // handle_verify_email – invalid token
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_email_invalid_token() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();

        let mut query = HashMap::new();
        query.insert("token".to_string(), "bogus-token".to_string());
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn test_verify_email_missing_token() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();

        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/verify-email",
            None,
            None,
            HashMap::new(),
        );
        let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // ------------------------------------------------------------------
    // handle_verify_email – already-verified user returns early
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_email_already_verified_returns_ok() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();

        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("already@test.com")
                    .with_name("Already"),
            )
            .await
            .unwrap();
        // Mark verified
        ctx.database
            .update_user(
                &user.id,
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let token_value = format!("verify_{}", Uuid::new_v4());
        ctx.database
            .create_verification(CreateVerification {
                identifier: "already@test.com".to_string(),
                value: token_value.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_string(), token_value);
        let req =
            test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
        let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], true);
    }

    // ------------------------------------------------------------------
    // handle_send_verification_email
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_send_verification_email_already_verified_returns_error() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();

        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("verified@test.com")
                    .with_name("Verified"),
            )
            .await
            .unwrap();
        ctx.database
            .update_user(
                &user.id,
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let body = serde_json::json!({ "email": "verified@test.com" });
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/send-verification-email".to_string(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let err = plugin
            .handle_send_verification_email(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn test_send_verification_email_user_not_found() {
        let plugin = EmailVerificationPlugin::new();
        let ctx = test_helpers::create_test_context();

        let body = serde_json::json!({ "email": "nobody@test.com" });
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/send-verification-email".to_string(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let err = plugin
            .handle_send_verification_email(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 404);
    }

    // ------------------------------------------------------------------
    // create_session_cookie – uses cookie crate
    // ------------------------------------------------------------------

    #[test]
    fn test_create_session_cookie_format() {
        let ctx = test_helpers::create_test_context();
        let cookie_str = create_session_cookie("my-token-123", &ctx.config);
        // Should contain the cookie name and value
        assert!(cookie_str.contains("better-auth.session-token=my-token-123"));
        // Should contain Path
        assert!(cookie_str.contains("Path=/"));
        // Should contain HttpOnly (default)
        assert!(cookie_str.contains("HttpOnly"));
        // Should contain SameSite
        assert!(cookie_str.contains("SameSite=Lax"));
    }

    #[test]
    fn test_create_session_cookie_special_characters_in_token() {
        let ctx = test_helpers::create_test_context();
        let token = "token+with/special=chars&more";
        let cookie_str = create_session_cookie(token, &ctx.config);
        // The cookie crate should handle encoding properly
        assert!(cookie_str.contains("better-auth.session-token="));
    }
}
