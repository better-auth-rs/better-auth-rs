use async_trait::async_trait;
use std::sync::Arc;

use better_auth_core::AuthSession;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

use better_auth_core::RequestMeta;
use better_auth_core::utils::password::PasswordHasher;

use super::StatusResponse;

mod callbacks;
pub use callbacks::{PasswordManagementCallbacks, PasswordResetEmail};
pub(super) mod handlers;
mod request;
pub(super) mod types;

#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

/// Type alias for the async password-reset callback to keep Clippy happy.
pub use better_auth_core::utils::password::{OnPasswordResetCallback, PasswordResetEvent};

/// Trait for sending password reset emails.
///
/// This callback powers `POST /request-password-reset` and is required to
/// enable that route. The user is provided as a serialized `serde_json::Value`
/// since `AuthUser` is not object-safe.
#[async_trait]
pub trait SendResetPassword: Send + Sync {
    /// Send a password reset notification.
    ///
    /// * `user` - The user as a serialized JSON value (from `serde_json::to_value`)
    /// * `url` - The full reset URL including the token
    /// * `token` - The raw reset token
    async fn send(&self, user: &serde_json::Value, url: &str, token: &str) -> AuthResult<()>;

    async fn send_with_request(
        &self,
        user: &serde_json::Value,
        url: &str,
        token: &str,
        _request: Option<&AuthRequest>,
    ) -> AuthResult<()> {
        self.send(user, url, token).await
    }
}

/// Password management plugin for password reset and change functionality
pub struct PasswordManagementPlugin {
    config: PasswordManagementConfig,
}

#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "PasswordManagementPlugin")]
pub struct PasswordManagementConfig {
    /// Reset token lifetime in seconds, including fractions. Zero and NaN select one hour.
    #[config(default = None)]
    pub reset_password_token_expires_in: Option<f64>,
    #[config(default = true)]
    pub require_current_password: bool,
    #[config(default = true)]
    pub send_email_notifications: bool,
    /// When true, all existing sessions are revoked on password reset (default: false).
    #[config(default = false)]
    pub revoke_sessions_on_password_reset: bool,
    /// Password reset email sender for `POST /request-password-reset`.
    /// This route is disabled when no sender is configured.
    #[config(default = None)]
    pub send_reset_password: Option<Arc<dyn SendResetPassword>>,
    /// Callback invoked after a password is successfully reset.
    /// Errors propagate after the password write and before session revocation.
    #[config(default = None)]
    pub on_password_reset: Option<Arc<OnPasswordResetCallback>>,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    #[config(default = None)]
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
}

impl PasswordManagementConfig {
    /// Read the reset-token lifetime in seconds. Omission, zero and NaN use one hour.
    pub fn reset_password_token_expires_in(&self) -> f64 {
        match self.reset_password_token_expires_in {
            Some(seconds) if seconds != 0.0 && !seconds.is_nan() => seconds,
            _ => 3600.0,
        }
    }

    fn reset_token_expires_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<chrono::DateTime<chrono::Utc>> {
        better_auth_core::utils::date::from_milliseconds(
            now.timestamp_millis() as f64 + self.reset_password_token_expires_in() * 1000.0,
        )
        .ok_or_else(|| AuthError::config("Reset token expiry is out of range"))
    }
}

impl std::fmt::Debug for PasswordManagementConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordManagementConfig")
            .field(
                "reset_password_token_expires_in",
                &self.reset_password_token_expires_in,
            )
            .field("require_current_password", &self.require_current_password)
            .field("send_email_notifications", &self.send_email_notifications)
            .field(
                "revoke_sessions_on_password_reset",
                &self.revoke_sessions_on_password_reset,
            )
            .field(
                "send_reset_password",
                &self.send_reset_password.as_ref().map(|_| "custom"),
            )
            .field(
                "on_password_reset",
                &self.on_password_reset.as_ref().map(|_| "custom"),
            )
            .field(
                "password_hasher",
                &self.password_hasher.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for PasswordManagementPlugin {
    fn telemetry(&self, options: &mut better_auth_core::observability::telemetry::PluginTelemetry) {
        let options = &mut options.email_and_password;
        options.reset_password_token_expires_in = self.config.reset_password_token_expires_in;
        options.send_reset_password = self.config.send_reset_password.is_some();
        options.on_password_reset = self.config.on_password_reset.is_some();
        options.revoke_sessions_on_password_reset = self.config.revoke_sessions_on_password_reset;
        options.password.hash |= self.config.password_hasher.is_some();
        options.password.verify |= self.config.password_hasher.is_some();
    }

    fn password_hasher(&self) -> Option<Arc<dyn PasswordHasher>> {
        self.config.password_hasher.clone()
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.password_policy.on_password_reset = self.config.on_password_reset.clone();
        ctx.password_policy.revoke_sessions_on_password_reset =
            self.config.revoke_sessions_on_password_reset;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "password-management"
    }

    fn telemetry_plugin_id(&self) -> Option<&'static str> {
        None
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/request-password-reset", "requestPasswordReset")
                .body_validator(request::request_reset_body),
            AuthRoute::post("/reset-password", "resetPassword")
                .body_validator(request::reset_body)
                .query_validator(crate::plugins::query_input::reset_password),
            AuthRoute::get("/reset-password/{token}", "resetPasswordCallback")
                .query_validator(crate::plugins::query_input::reset_password_token),
            AuthRoute::post("/change-password", "changePassword")
                .body_validator(request::change_body),
            AuthRoute::post("/verify-password", "verifyPassword")
                .body_validator(request::verify_body),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/request-password-reset") => {
                Ok(Some(self.handle_request_password_reset(req, ctx).await?))
            }
            (HttpMethod::Post, "/reset-password") => {
                Ok(Some(self.handle_reset_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/change-password") => {
                Ok(Some(self.handle_change_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/verify-password") => {
                Ok(Some(self.handle_verify_password(req, ctx).await?))
            }
            (HttpMethod::Get, path) if path.starts_with("/reset-password/") => {
                let token = path.get(16..).unwrap_or(""); // Remove "/reset-password/" prefix
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
    async fn handle_request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = request::request_reset(req)?;
        let response = request_password_reset_core(&body, &self.config, req, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut body = request::reset(req)?;
        if body.token.as_deref().is_none_or(str::is_empty) {
            body.token = req.query_string("token")?.map(str::to_owned);
        }
        let response = reset_password_core(&body, req, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_change_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = request::change(req)?;

        // Get current user from session
        let user = self
            .get_current_user(req, ctx)
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);

        let response = change_password_core(&body, &user, &self.config, req, &meta, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_verify_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = request::verify(req)?;

        let user = self.get_current_user(req, ctx).await?;
        let Some(user) = user else {
            // better-call's default body for a session-gated endpoint hit
            // without a session, which upstream returns verbatim.
            return Ok(
                AuthError::AuthenticationFailed("Unauthorized".to_string()).to_auth_response()
            );
        };
        let response = verify_password_core(&body, &user, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password_token(
        &self,
        token: &str,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let query = ResetPasswordTokenQuery {
            callback_url: req.query_string("callbackURL")?.map(str::to_owned),
        };
        match reset_password_token_core(token, &query, ctx).await? {
            ResetPasswordTokenResult::Redirect(url) => {
                let mut headers = better_auth_core::Headers::new();
                let _ = headers.insert("Location".to_string(), url);
                let _ = headers.insert("content-type".to_string(), "application/json".to_string());
                let mut response = AuthResponse::new(302);
                response.headers = headers;
                Ok(response)
            }
        }
    }

    async fn get_current_user<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let session_manager = ctx.session_manager();

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
        {
            return ctx
                .database
                .get_user_by_id(session.user_id().typed()?)
                .await;
        }

        Ok(None)
    }
}

#[cfg(test)]
impl PasswordManagementPlugin {
    fn validate_password(
        &self,
        password: &str,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        better_auth_core::utils::password::validate_password(
            password,
            ctx.config.password.min_length,
            ctx.config.password.max_length,
            ctx,
        )
    }

    async fn hash_password(&self, password: &str) -> AuthResult<String> {
        better_auth_core::utils::password::hash_password(
            self.config.password_hasher.as_ref(),
            password,
        )
        .await
    }

    async fn verify_password(&self, password: &str, hash: &str) -> AuthResult<()> {
        better_auth_core::utils::password::verify_password(
            self.config.password_hasher.as_ref(),
            password,
            hash,
        )
        .await
    }
}
