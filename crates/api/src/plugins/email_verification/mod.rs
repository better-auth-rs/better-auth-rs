use async_trait::async_trait;
use chrono::Duration;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use better_auth_core::AuthUser;
use better_auth_core::wire::UserView;
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use better_auth_core::utils::cookie_utils::create_session_cookie;

use super::StatusResponse;

pub(super) mod handlers;
pub(crate) mod token;
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
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()>;
}

/// Shorthand for the async hook closure type used by
/// [`EmailVerificationConfig::before_email_verification`] and
/// [`EmailVerificationConfig::after_email_verification`].
pub type EmailVerificationHook =
    Arc<dyn Fn(&UserView) -> Pin<Box<dyn Future<Output = AuthResult<()>> + Send>> + Send + Sync>;

/// Email verification plugin for handling email verification flows
pub struct EmailVerificationPlugin {
    config: EmailVerificationConfig,
}

#[derive(better_auth_core::PluginConfig)]
#[plugin(name = "EmailVerificationPlugin")]
pub struct EmailVerificationConfig {
    /// How long a verification token stays valid. Default: 24 hours.
    #[config(default = Duration::hours(24))]
    pub verification_token_expiry: Duration,
    /// Whether to send email notifications (on sign-up). Default: true.
    #[config(default = true)]
    pub send_email_notifications: bool,
    /// Whether email verification is required before sign-in. Default: false.
    #[config(default = false)]
    pub require_verification_for_signin: bool,
    /// Whether to auto-verify newly created users. Default: false.
    #[config(default = false)]
    pub auto_verify_new_users: bool,
    /// When true, automatically send a verification email on sign-in if the
    /// user is unverified. Default: false.
    #[config(default = false)]
    pub send_on_sign_in: bool,
    /// When true, create a session after email verification and return the
    /// session token in the verify-email response. Default: false.
    #[config(default = false)]
    pub auto_sign_in_after_verification: bool,
    /// Optional custom email sender. When set this overrides the default
    /// `EmailProvider`-based sending.
    #[config(default = None, skip)]
    pub send_verification_email: Option<Arc<dyn SendVerificationEmail>>,
    /// Hook invoked **before** email verification (before updating the user).
    #[config(default = None)]
    pub before_email_verification: Option<EmailVerificationHook>,
    /// Hook invoked **after** email verification (after the user has been updated).
    #[config(default = None)]
    pub after_email_verification: Option<EmailVerificationHook>,
}

impl EmailVerificationPlugin {
    pub fn custom_send_verification_email(
        mut self,
        sender: Arc<dyn SendVerificationEmail>,
    ) -> Self {
        self.config.send_verification_email = Some(sender);
        self
    }
}

better_auth_core::impl_auth_plugin! {
    EmailVerificationPlugin, "email-verification";
    routes {
        post "/send-verification-email" => handle_send_verification_email, "send_verification_email";
        get "/verify-email" => handle_verify_email, "verify_email";
    }
    extra {
        async fn on_user_created(&self, user: &S::User, ctx: &AuthContext<S>) -> AuthResult<()> {
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
    async fn handle_send_verification_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SendVerificationEmailRequest = match better_auth_core::validate_request_body(req)
        {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let current_user = ctx.require_session(req).await.ok().map(|(user, _)| user);
        let response =
            send_verification_email_core(&body, current_user.as_ref(), &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_verify_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let token = req
            .query
            .get("token")
            .ok_or_else(|| AuthError::bad_request("Verification token is required"))?;
        let callback_url = req.query.get("callbackURL").cloned();

        // Validate callbackURL against trusted origins, matching the TS
        // `originCheck` middleware applied to the verify-email endpoint.
        if let Some(ref url) = callback_url
            && !ctx.config.advanced.disable_origin_check
            && !ctx.config.is_redirect_target_trusted(url)
        {
            return Ok(AuthError::forbidden("Invalid callbackURL").to_auth_response());
        }

        let query = VerifyEmailQuery {
            token: token.clone(),
            callback_url,
        };

        let ip_address = req.headers.get("x-forwarded-for").cloned();
        let user_agent = req.headers.get("user-agent").cloned();
        let current_session = ctx.require_session(req).await.ok();

        match verify_email_core(
            &query,
            current_session,
            &self.config,
            ip_address,
            user_agent,
            ctx,
        )
        .await?
        {
            VerifyEmailResult::Redirect { url, session_token } => {
                let mut headers = better_auth_core::Headers::new();
                _ = headers.insert("Location".to_string(), url);
                _ = headers.insert("content-type".to_string(), "application/json".to_string());
                if let Some(token) = session_token {
                    let cookie = create_session_cookie(&token, &ctx.config);
                    headers.append("Set-Cookie".to_string(), cookie);
                }
                Ok(AuthResponse {
                    status: 302,
                    headers,
                    body: Vec::new(),
                })
            }
            VerifyEmailResult::Json {
                body,
                session_token,
            } => {
                let mut response = AuthResponse::json(200, &body)?;
                if let Some(token) = session_token {
                    let cookie = create_session_cookie(&token, &ctx.config);
                    response = response.with_header("Set-Cookie", cookie);
                }
                Ok(response)
            }
        }
    }

    /// Send a verification email for a specific user.
    ///
    /// If [`EmailVerificationConfig::send_verification_email`] is set the
    /// custom callback is used; otherwise the default `EmailProvider` path is
    /// taken.
    async fn send_verification_email_for_user(
        &self,
        user: &impl AuthUser,
        email: &str,
        callback_url: Option<&str>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        let verification_token = token::create_email_verification_token(
            &ctx.config.secret,
            email,
            None,
            self.config.verification_token_expiry,
            None,
        )?;
        let callback_url = callback_url.unwrap_or("/");
        let verification_url = format!(
            "{}/verify-email?token={}&callbackURL={}",
            ctx.config.base_url,
            verification_token,
            urlencoding::encode(callback_url),
        );

        // Use custom sender if configured, otherwise fall back to EmailProvider
        if let Some(ref custom_sender) = self.config.send_verification_email {
            let user = UserView::from(user);
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
    pub async fn send_verification_on_sign_in(
        &self,
        user: &impl AuthUser,
        callback_url: Option<&str>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
    pub fn is_user_verified_or_not_required(&self, user: &impl AuthUser) -> bool {
        user.email_verified() || !self.config.require_verification_for_signin
    }
}

// ---------------------------------------------------------------------------
// Axum plugin
// ---------------------------------------------------------------------------
