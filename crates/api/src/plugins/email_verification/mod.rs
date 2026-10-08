use chrono::Duration;
use std::sync::Arc;

use better_auth_core::AuthUser;
pub use better_auth_core::email::{EmailVerificationHook, SendVerificationEmail};
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use super::StatusResponse;

pub(super) mod handlers;
pub(crate) mod token;
pub(super) mod types;

mod callbacks;
pub(crate) mod delivery;
pub use callbacks::{EmailVerificationCallbacks, VerificationEmail};

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

/// Email verification plugin for handling email verification flows
pub struct EmailVerificationPlugin {
    config: EmailVerificationConfig,
}

#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "EmailVerificationPlugin")]
pub struct EmailVerificationConfig {
    /// How long a verification token stays valid. Default: one hour.
    #[config(default = None)]
    pub verification_token_expiry: Option<Duration>,
    /// Whether sign-in sends through the default email provider. Default: true.
    /// Custom senders are independent of this setting.
    #[config(default = true)]
    pub send_email_notifications: bool,
    /// Whether email verification is required before sign-in. Default: false.
    #[config(default = false)]
    pub require_verification_for_signin: bool,
    /// When true, automatically send a verification email on sign-in if the
    /// user is unverified. Default: false.
    #[config(default = false)]
    pub send_on_sign_in: bool,
    /// Send for new unverified OAuth users; defaults to the provider verification requirement.
    #[config(default = None)]
    pub send_on_sign_up: Option<bool>,
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

impl EmailVerificationConfig {
    /// Read the verification-token lifetime. Omission uses one hour.
    pub fn verification_token_expiry(&self) -> Duration {
        self.verification_token_expiry
            .unwrap_or_else(|| Duration::hours(1))
    }
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
        post "/send-verification-email" => handle_send_verification_email, "sendVerificationEmail", body = types::body;
        get "/verify-email" => handle_verify_email, "verifyEmail", query = crate::plugins::query_input::verify_email;
    }
    extra {
        fn telemetry_plugin_id(&self) -> Option<&'static str> {
            None
        }

        fn telemetry(&self, options: &mut better_auth_core::observability::telemetry::PluginTelemetry) {
            let options = &mut options.email_verification;
            options.expires_in = self.config.verification_token_expiry;
            options.send_verification_email = self.config.send_verification_email.is_some();
            options.send_on_sign_up = self.config.send_on_sign_up == Some(true);
            options.send_on_sign_in = self.config.send_on_sign_in;
            options.auto_sign_in_after_verification = self.config.auto_sign_in_after_verification;
            options.before_email_verification = self.config.before_email_verification.is_some();
            options.after_email_verification = self.config.after_email_verification.is_some();
        }

        async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
            ctx.extensions.insert(self.config.clone());
            ctx.email_verification_policy.auto_sign_in_after_verification = self.config.auto_sign_in_after_verification;
            ctx.email_verification_policy.before_email_verification = self.config.before_email_verification.clone();
            ctx.email_verification_policy.after_email_verification = self.config.after_email_verification.clone();
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Route handlers (delegate to core functions)
// ---------------------------------------------------------------------------

impl EmailVerificationPlugin {
    pub(crate) fn from_context(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Option<Self> {
        ctx.extensions
            .get::<EmailVerificationConfig>()
            .map(|config| Self::with_config(config.clone()))
    }

    pub(crate) async fn send_verification_on_sign_up<S: better_auth_core::AuthSchema>(
        &self,
        user: &impl AuthUser,
        required: bool,
        callback_url: Option<&str>,
        endpoint: &crate::plugins::endpoint_context::EndpointContext<'_, S>,
    ) -> AuthResult<()> {
        if self.config.send_on_sign_up.unwrap_or(required)
            && let Some(email) = user.email()
        {
            self.send_verification_email_at(user, email, callback_url, endpoint)
                .await?;
        }
        Ok(())
    }

    async fn handle_send_verification_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match req.validated_body::<SendVerificationEmailRequest>() {
            Some(body) => body.clone(),
            None => super::json_body::email_input(req, "email", "callbackURL")?.0,
        };
        let current_session = ctx.require_session(req).await.ok();
        let mut config = self.config.clone();
        if config.send_verification_email.is_none() {
            config.send_verification_email = ctx.email_verification_policy.override_sender.clone();
        }
        let response =
            send_verification_email_core(&body, current_session.as_ref(), Some(req), &config, ctx)
                .await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_verify_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let token = req
            .query_string("token")?
            .ok_or_else(|| AuthError::bad_request("Verification token is required"))?;
        let callback_url = req
            .query_string("callbackURL")?
            .filter(|url| !url.is_empty())
            .map(str::to_owned);

        // Validate callbackURL against trusted origins, matching the TS
        // `originCheck` middleware applied to the verify-email endpoint.
        if let Some(ref url) = callback_url
            && !ctx.config.advanced.disable_origin_check
            && !ctx.is_redirect_target_trusted(url)
        {
            return Ok(AuthError::forbidden("Invalid callbackURL").to_auth_response());
        }

        let query = VerifyEmailQuery {
            token: token.to_owned(),
            callback_url,
        };

        let ip_address = ctx.config.advanced.ip_address.resolve(req);
        let user_agent = req.headers.get("user-agent").cloned();
        let current_session = ctx.require_session(req).await.ok();
        let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::Null,
            ctx,
        );
        endpoint.session = current_session.clone();

        match verify_email_core(
            &query,
            current_session,
            &self.config,
            req,
            ip_address,
            user_agent,
            &endpoint,
        )
        .await?
        {
            VerifyEmailResult::Redirect { url } => {
                let mut headers = better_auth_core::Headers::new();
                _ = headers.insert("Location".to_string(), url);
                _ = headers.insert("content-type".to_string(), "application/json".to_string());
                let mut response = AuthResponse::new(302);
                response.headers = headers;
                Ok(response)
            }
            VerifyEmailResult::Json { body } => Ok(AuthResponse::json(200, &body)?),
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
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        let body = request
            .filter(|request| request.body.is_some())
            .map(|request| request.body_as_json())
            .transpose()?
            .unwrap_or(serde_json::Value::Null);
        let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
            request,
            better_auth_core::FieldValue::from_json(body)?,
            ctx,
        );
        self.send_verification_email_at(user, email, callback_url, &endpoint)
            .await
    }

    async fn send_verification_email_at<S: better_auth_core::AuthSchema>(
        &self,
        user: &impl AuthUser,
        email: &str,
        callback_url: Option<&str>,
        endpoint: &crate::plugins::endpoint_context::EndpointContext<'_, S>,
    ) -> AuthResult<()> {
        let ctx = endpoint.auth;
        let verification_token = token::create_email_verification_token(
            ctx.config.signing_secret(),
            email,
            None,
            self.config.verification_token_expiry(),
            None,
        )?;
        let callback_url = callback_url.unwrap_or("/");
        let verification_url = format!(
            "{}/verify-email?token={}&callbackURL={}",
            ctx.base_url(),
            verification_token,
            urlencoding::encode(callback_url),
        );

        if ctx
            .extensions
            .get::<Arc<EmailVerificationCallbacks<S>>>()
            .is_none()
            && self.config.send_verification_email.is_none()
            && crate::plugins::email_otp::callbacks::overrides_verification(ctx)
        {
            let retained = endpoint.to_owned();
            let email = email.to_owned();
            better_auth_core::background::run_or_await(
                Some(Box::pin(async move {
                    let endpoint = retained.as_endpoint();
                    crate::plugins::email_otp::callbacks::send_verification_override(
                        &email, &endpoint,
                    )
                    .await
                })),
                ctx.config.advanced.background_tasks.as_ref(),
                &ctx.config.logger,
            )
            .await;
            return Ok(());
        }
        let message = VerificationEmail {
            user: ctx.internal_user_view(user).await?,
            url: verification_url,
            token: verification_token,
        };
        let task = delivery::delivery(Some(&self.config), message, endpoint)?;
        better_auth_core::background::run_or_await(
            task,
            ctx.config.advanced.background_tasks.as_ref(),
            &ctx.config.logger,
        )
        .await;

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
        self.send_verification_on_sign_in_with_request(user, callback_url, None, ctx)
            .await
    }

    pub(crate) async fn send_verification_on_sign_in_with_request(
        &self,
        user: &impl AuthUser,
        callback_url: Option<&str>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        if !self.config.send_on_sign_in {
            return Ok(());
        }

        if user.email_verified() {
            return Ok(());
        }

        if let Some(email) = user.email() {
            self.send_verification_email_for_user(user, email, callback_url, request, ctx)
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn send_verification_on_oauth_sign_in(
        &self,
        user: Option<&impl AuthUser>,
        is_register: bool,
        require_verification: bool,
        callback_url: &str,
        request: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) {
        let should_send = if is_register {
            self.config.send_on_sign_up.unwrap_or(require_verification)
        } else {
            require_verification && self.config.send_on_sign_in
        };
        if !should_send
            || user.is_some_and(AuthUser::email_verified)
            || !delivery::available(Some(&self.config), ctx)
        {
            return;
        }
        let result = async {
            let (user, email) = user
                .and_then(|user| user.email().map(|email| (user, email)))
                .ok_or_else(|| {
                    AuthError::internal(
                        "Cannot create an OAuth verification token without a user email",
                    )
                })?;
            self.send_verification_email_for_user(
                user,
                email,
                Some(callback_url),
                Some(request),
                ctx,
            )
            .await
        }
        .await;
        if let Err(error) = result {
            // Upstream logs verification delivery failures without changing the OAuth verification decision.
            better_auth_core::observability::logger::current().error(
                "Failed to send OAuth verification email",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
        }
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
