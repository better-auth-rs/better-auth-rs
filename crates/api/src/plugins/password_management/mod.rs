use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};
use better_auth_core::{AuthSession, DatabaseAdapter};

use better_auth_core::utils::password::PasswordHasher;

use super::StatusResponse;

pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

/// Type alias for the async password-reset callback to keep Clippy happy.
pub type OnPasswordResetCallback =
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = AuthResult<()>> + Send>> + Send + Sync;

/// Trait for sending password reset emails.
///
/// When set in `PasswordManagementConfig`, this overrides the default
/// `EmailProvider`-based reset email sending. The user is provided as a
/// serialized `serde_json::Value` since `AuthUser` is not object-safe.
#[async_trait]
pub trait SendResetPassword: Send + Sync {
    /// Send a password reset notification.
    ///
    /// * `user` - The user as a serialized JSON value (from `serde_json::to_value`)
    /// * `url` - The full reset URL including the token
    /// * `token` - The raw reset token
    async fn send(&self, user: &serde_json::Value, url: &str, token: &str) -> AuthResult<()>;
}

/// Password management plugin for password reset and change functionality
pub struct PasswordManagementPlugin {
    config: PasswordManagementConfig,
}

#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "PasswordManagementPlugin")]
pub struct PasswordManagementConfig {
    #[config(default = 24)]
    pub reset_token_expiry_hours: i64,
    #[config(default = true)]
    pub require_current_password: bool,
    #[config(default = true)]
    pub send_email_notifications: bool,
    /// When true, all existing sessions are revoked on password reset (default: true).
    #[config(default = true)]
    pub revoke_sessions_on_password_reset: bool,
    /// Custom password reset email sender. When set, overrides the default `EmailProvider`.
    #[config(default = None)]
    pub send_reset_password: Option<Arc<dyn SendResetPassword>>,
    /// Callback invoked after a password is successfully reset.
    /// The user is provided as a serialized `serde_json::Value`.
    #[config(default = None)]
    pub on_password_reset: Option<Arc<OnPasswordResetCallback>>,
    /// Custom password hasher. When `None`, the default Argon2 hasher is used.
    #[config(default = None)]
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
}

impl std::fmt::Debug for PasswordManagementConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordManagementConfig")
            .field("reset_token_expiry_hours", &self.reset_token_expiry_hours)
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
        let body: ForgetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = forget_password_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let body: ResetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = reset_password_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_change_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let body: ChangePasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Get current user from session
        let user = self
            .get_current_user(req, ctx)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        let (response, new_token) = change_password_core(&body, &user, &self.config, ctx).await?;

        let auth_response = AuthResponse::json(200, &response)?;

        // Set session cookie if a new session was created
        if let Some(token) = new_token {
            let cookie_header =
                better_auth_core::utils::cookie_utils::create_session_cookie(&token, &ctx.config);
            Ok(auth_response.with_header("Set-Cookie", cookie_header))
        } else {
            Ok(auth_response)
        }
    }

    async fn handle_set_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let body: SetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Authenticate user
        let user = self
            .get_current_user(req, ctx)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        let response = set_password_core(&body, &user, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password_token<DB: DatabaseAdapter>(
        &self,
        token: &str,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let query = ResetPasswordTokenQuery {
            callback_url: req.query.get("callbackURL").cloned(),
        };
        match reset_password_token_core(token, &query, ctx).await? {
            ResetPasswordTokenResult::Redirect(url) => {
                let mut headers = std::collections::HashMap::new();
                headers.insert("Location".to_string(), url);
                Ok(AuthResponse {
                    status: 302,
                    headers,
                    body: Vec::new(),
                })
            }
            ResetPasswordTokenResult::Json(data) => Ok(AuthResponse::json(200, &data)?),
        }
    }

    async fn get_current_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<DB::User>> {
        let session_manager = ctx.session_manager();

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
        {
            return ctx.database.get_user_by_id(session.user_id()).await;
        }

        Ok(None)
    }
}

#[cfg(test)]
impl PasswordManagementPlugin {
    fn validate_password<DB: DatabaseAdapter>(
        &self,
        password: &str,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        better_auth_core::utils::password::validate_password(
            password,
            ctx.config.password.min_length,
            usize::MAX,
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

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::extract::{Extension, Path, Query, State};
    use axum::response::IntoResponse;
    use axum::{Json, http::header};
    use better_auth_core::{AuthState, CurrentSession, ValidatedJson};

    #[derive(Clone)]
    struct PluginState {
        config: PasswordManagementConfig,
    }

    async fn handle_forget_password<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        ValidatedJson(body): ValidatedJson<ForgetPasswordRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let response = forget_password_core(&body, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_reset_password<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        ValidatedJson(body): ValidatedJson<ResetPasswordRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let response = reset_password_core(&body, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_reset_password_token<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Path(token): Path<String>,
        Query(query): Query<ResetPasswordTokenQuery>,
    ) -> Result<axum::response::Response, AuthError> {
        let ctx = state.to_context();
        match reset_password_token_core(&token, &query, &ctx).await? {
            ResetPasswordTokenResult::Redirect(url) => {
                Ok(axum::response::Redirect::to(&url).into_response())
            }
            ResetPasswordTokenResult::Json(data) => Ok(Json(data).into_response()),
        }
    }

    async fn handle_change_password<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<ChangePasswordRequest>,
    ) -> Result<axum::response::Response, AuthError> {
        let ctx = state.to_context();
        let (response, new_token) = change_password_core(&body, &user, &ps.config, &ctx).await?;

        if let Some(ref token) = new_token {
            let cookie = state.session_cookie(token);
            Ok(([(header::SET_COOKIE, cookie)], Json(response)).into_response())
        } else {
            Ok(Json(response).into_response())
        }
    }

    async fn handle_set_password<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<SetPasswordRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let response = set_password_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for PasswordManagementPlugin {
        fn name(&self) -> &'static str {
            "password-management"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });

            axum::Router::new()
                .route("/forget-password", post(handle_forget_password::<DB>))
                .route("/reset-password", post(handle_reset_password::<DB>))
                .route(
                    "/reset-password/:token",
                    get(handle_reset_password_token::<DB>),
                )
                .route("/change-password", post(handle_change_password::<DB>))
                .route("/set-password", post(handle_set_password::<DB>))
                .layer(Extension(plugin_state))
        }
    }
}
