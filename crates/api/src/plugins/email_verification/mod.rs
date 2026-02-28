use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateVerification};
use better_auth_core::{AuthUser, DatabaseAdapter, User};

use better_auth_core::utils::cookie_utils::create_session_cookie;

use super::StatusResponse;

pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

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

better_auth_core::impl_auth_plugin! {
    EmailVerificationPlugin, "email-verification";
    routes {
        post "/send-verification-email" => handle_send_verification_email, "send_verification_email";
        get "/verify-email" => handle_verify_email, "verify_email";
    }
    extra {
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
        let body: SendVerificationEmailRequest = match better_auth_core::validate_request_body(req)
        {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = send_verification_email_core(&body, &self.config, ctx).await?;
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
            VerifyEmailResult::AlreadyVerified(data) => Ok(AuthResponse::json(200, &data)?),
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
            VerifyEmailResult::Json(data) => Ok(AuthResponse::json(200, &data)?),
            VerifyEmailResult::JsonWithSession {
                response,
                session_token,
            } => {
                let cookie = create_session_cookie(&session_token, &ctx.config);
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie))
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
        let response = send_verification_email_core(&body, &ps.config, &ctx).await?;
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
            VerifyEmailResult::AlreadyVerified(data) => Ok(Json(data).into_response()),
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
            VerifyEmailResult::Json(data) => Ok(Json(data).into_response()),
            VerifyEmailResult::JsonWithSession {
                response,
                session_token,
            } => {
                let cookie = state.session_cookie(&session_token);
                Ok(([(header::SET_COOKIE, cookie)], Json(response)).into_response())
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
