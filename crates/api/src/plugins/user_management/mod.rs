use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

use better_auth_core::entity::AuthUser;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

// ---------------------------------------------------------------------------
// User info snapshot (dyn-compatible alternative to &dyn AuthUser)
// ---------------------------------------------------------------------------

/// A plain-data snapshot of the core user fields, passed to callback hooks.
///
/// `AuthUser` is **not** dyn-compatible (it requires `Serialize`), so we
/// extract the fields the callbacks are most likely to need into this struct.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

impl UserInfo {
    /// Build a [`UserInfo`] from any type that implements [`AuthUser`].
    fn from_auth_user(user: &impl AuthUser) -> Self {
        Self {
            id: user.id().to_string(),
            email: user.email().map(|s| s.to_string()),
            name: user.name().map(|s| s.to_string()),
            email_verified: user.email_verified(),
        }
    }
}

// ---------------------------------------------------------------------------
// Callback traits
// ---------------------------------------------------------------------------

/// Custom callback for sending change-email confirmation emails.
///
/// If set on [`ChangeEmailConfig`], this callback is invoked instead of the
/// default [`EmailProvider`](better_auth_core::EmailProvider). This allows callers to customise the email
/// subject, template, and delivery mechanism.
#[async_trait]
pub trait SendChangeEmailConfirmation: Send + Sync {
    async fn send(
        &self,
        user: &UserInfo,
        new_email: &str,
        url: &str,
        token: &str,
    ) -> AuthResult<()>;
}

/// Hook invoked **before** a user is deleted.
///
/// Return `Err(...)` from [`before_delete`](BeforeDeleteUser::before_delete) to
/// abort the deletion.
#[async_trait]
pub trait BeforeDeleteUser: Send + Sync {
    async fn before_delete(&self, user: &UserInfo) -> AuthResult<()>;
}

/// Hook invoked **after** a user has been deleted.
#[async_trait]
pub trait AfterDeleteUser: Send + Sync {
    async fn after_delete(&self, user: &UserInfo) -> AuthResult<()>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the change-email feature.
#[derive(Clone, Default)]
pub struct ChangeEmailConfig {
    /// Whether the change-email endpoints are enabled. Default: `false`.
    pub enabled: bool,
    /// If `true`, the new email is updated immediately without sending a
    /// verification email. Default: `false`.
    pub update_without_verification: bool,
    /// Optional custom callback for sending the confirmation email.
    pub send_change_email_confirmation: Option<Arc<dyn SendChangeEmailConfirmation>>,
}

impl std::fmt::Debug for ChangeEmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeEmailConfig")
            .field("enabled", &self.enabled)
            .field(
                "update_without_verification",
                &self.update_without_verification,
            )
            .field(
                "send_change_email_confirmation",
                &self.send_change_email_confirmation.is_some(),
            )
            .finish()
    }
}

/// Configuration for the delete-user feature.
#[derive(Clone)]
pub struct DeleteUserConfig {
    /// Whether the delete-user endpoints are enabled. Default: `false`.
    pub enabled: bool,
    /// How long a delete-confirmation token remains valid. Default: 1 day.
    pub delete_token_expires_in: Duration,
    /// If `true`, a verification email must be confirmed before the account is
    /// deleted. Default: `true`.
    pub require_verification: bool,
    /// Hook called before the user record is removed.
    pub before_delete: Option<Arc<dyn BeforeDeleteUser>>,
    /// Hook called after the user record has been removed.
    pub after_delete: Option<Arc<dyn AfterDeleteUser>>,
}

impl std::fmt::Debug for DeleteUserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeleteUserConfig")
            .field("enabled", &self.enabled)
            .field("delete_token_expires_in", &self.delete_token_expires_in)
            .field("require_verification", &self.require_verification)
            .field("before_delete", &self.before_delete.is_some())
            .field("after_delete", &self.after_delete.is_some())
            .finish()
    }
}

impl Default for DeleteUserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            delete_token_expires_in: Duration::hours(24),
            require_verification: true,
            before_delete: None,
            after_delete: None,
        }
    }
}

/// Combined configuration for the [`UserManagementPlugin`].
#[derive(Debug, Clone, Default)]
pub struct UserManagementConfig {
    pub change_email: ChangeEmailConfig,
    pub delete_user: DeleteUserConfig,
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/// User self-service management plugin (change email & delete account).
pub struct UserManagementPlugin {
    config: UserManagementConfig,
}

impl UserManagementPlugin {
    pub fn new() -> Self {
        Self {
            config: UserManagementConfig::default(),
        }
    }

    pub fn with_config(config: UserManagementConfig) -> Self {
        Self { config }
    }

    // -- builder helpers --

    pub fn change_email_enabled(mut self, enabled: bool) -> Self {
        self.config.change_email.enabled = enabled;
        self
    }

    pub fn update_without_verification(mut self, flag: bool) -> Self {
        self.config.change_email.update_without_verification = flag;
        self
    }

    pub fn send_change_email_confirmation(
        mut self,
        cb: Arc<dyn SendChangeEmailConfirmation>,
    ) -> Self {
        self.config.change_email.send_change_email_confirmation = Some(cb);
        self
    }

    pub fn delete_user_enabled(mut self, enabled: bool) -> Self {
        self.config.delete_user.enabled = enabled;
        self
    }

    pub fn delete_token_expires_in(mut self, duration: Duration) -> Self {
        self.config.delete_user.delete_token_expires_in = duration;
        self
    }

    pub fn require_delete_verification(mut self, require: bool) -> Self {
        self.config.delete_user.require_verification = require;
        self
    }

    pub fn before_delete(mut self, hook: Arc<dyn BeforeDeleteUser>) -> Self {
        self.config.delete_user.before_delete = Some(hook);
        self
    }

    pub fn after_delete(mut self, hook: Arc<dyn AfterDeleteUser>) -> Self {
        self.config.delete_user.after_delete = Some(hook);
        self
    }
}

impl Default for UserManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

fn append_clear_session_cookies(
    response: &mut AuthResponse,
    config: &better_auth_core::AuthConfig,
) {
    response.headers.append(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_clear_session_cookie(config),
    );
    response.headers.append(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "session_data"),
            config,
        ),
    );
    response.headers.append(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "dont_remember"),
            config,
        ),
    );
    if config.account.store_account_cookie {
        response.headers.append(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_clear_cookie(
                &related_cookie_name(config, "account_data"),
                config,
            ),
        );
    }
}

fn related_cookie_name(config: &better_auth_core::AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map(|prefix| format!("{prefix}{suffix}"))
        .unwrap_or_else(|| format!("better-auth.{suffix}"))
}

// ---------------------------------------------------------------------------
// Route handlers (delegate to core functions)
// ---------------------------------------------------------------------------

impl UserManagementPlugin {
    /// `POST /change-email`
    async fn handle_change_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: ChangeEmailRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = change_email_core(&body, &user, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    /// `POST /delete-user`
    async fn handle_delete_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx.require_session(req).await?;
        let body: DeleteUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = delete_user_core(&body, &user, &session, &self.config, ctx).await?;
        let mut response = AuthResponse::json(200, &response)?;
        append_clear_session_cookies(&mut response, &ctx.config);
        Ok(response)
    }

    /// `GET /delete-user/callback`
    async fn handle_delete_user_callback(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx
            .require_session(req)
            .await
            .map_err(|_| AuthError::not_found("Failed to get user info"))?;
        let query: TokenQuery = serde_json::from_value(serde_json::json!({
            "token": req.query.get("token").cloned(),
            "callbackURL": req.query.get("callbackURL").cloned(),
        }))
        .map_err(|_| AuthError::bad_request("Verification token is required"))?;
        let response = delete_user_callback_core(&query.token, &user, &self.config, ctx).await?;
        if let Some(callback_url) = query.callback_url {
            let mut headers = better_auth_core::Headers::new();
            _ = headers.insert("Location".to_string(), callback_url);
            let mut response = AuthResponse {
                status: 302,
                headers,
                body: Vec::new(),
            };
            append_clear_session_cookies(&mut response, &ctx.config);
            return Ok(response);
        }

        let mut response = AuthResponse::json(200, &response)?;
        append_clear_session_cookies(&mut response, &ctx.config);
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// AuthPlugin implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl AuthPlugin for UserManagementPlugin {
    fn name(&self) -> &'static str {
        "user-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = Vec::new();
        if self.config.change_email.enabled {
            routes.push(AuthRoute::post("/change-email", "change_email"));
        }
        if self.config.delete_user.enabled {
            routes.push(AuthRoute::post("/delete-user", "delete_user"));
            routes.push(AuthRoute::get(
                "/delete-user/callback",
                "delete_user_callback",
            ));
        }
        routes
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            // -- change email --
            (HttpMethod::Post, "/change-email") if self.config.change_email.enabled => {
                Ok(Some(self.handle_change_email(req, ctx).await?))
            }
            // -- delete user --
            (HttpMethod::Post, "/delete-user") if self.config.delete_user.enabled => {
                Ok(Some(self.handle_delete_user(req, ctx).await?))
            }
            (HttpMethod::Get, "/delete-user/callback") if self.config.delete_user.enabled => {
                Ok(Some(self.handle_delete_user_callback(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Axum plugin
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, Query, State};
    use axum::http::{HeaderValue, header};
    use axum::response::IntoResponse;
    use better_auth_core::{AuthError, AuthState, CurrentSession, ValidatedJson};

    #[derive(Clone)]
    struct PluginState {
        config: UserManagementConfig,
    }

    async fn handle_change_email(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession,
        ValidatedJson(body): ValidatedJson<ChangeEmailRequest>,
    ) -> Result<Json<better_auth_core::StatusResponse>, AuthError> {
        if !ps.config.change_email.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = change_email_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_delete_user(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session }: CurrentSession,
        ValidatedJson(body): ValidatedJson<DeleteUserRequest>,
    ) -> Result<axum::response::Response, AuthError> {
        if !ps.config.delete_user.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = delete_user_core(&body, &user, &session, &ps.config, &ctx).await?;
        let mut response = Json(response).into_response();
        for cookie in [
            state.clear_session_cookie(),
            better_auth_core::utils::cookie_utils::create_clear_cookie(
                &related_cookie_name(&state.config, "session_data"),
                &state.config,
            ),
            better_auth_core::utils::cookie_utils::create_clear_cookie(
                &related_cookie_name(&state.config, "dont_remember"),
                &state.config,
            ),
        ] {
            _ = response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie)
                    .map_err(|_| AuthError::internal("Invalid cookie header"))?,
            );
        }
        if state.config.account.store_account_cookie {
            _ = response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&better_auth_core::utils::cookie_utils::create_clear_cookie(
                    &related_cookie_name(&state.config, "account_data"),
                    &state.config,
                ))
                .map_err(|_| AuthError::internal("Invalid cookie header"))?,
            );
        }
        Ok(response)
    }

    async fn handle_delete_user_callback(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession,
        Query(query): Query<TokenQuery>,
    ) -> Result<axum::response::Response, AuthError> {
        if !ps.config.delete_user.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = delete_user_callback_core(&query.token, &user, &ps.config, &ctx).await?;

        if let Some(callback_url) = query.callback_url {
            let mut response = axum::response::Redirect::to(&callback_url).into_response();
            for cookie in [
                state.clear_session_cookie(),
                better_auth_core::utils::cookie_utils::create_clear_cookie(
                    &related_cookie_name(&state.config, "session_data"),
                    &state.config,
                ),
                better_auth_core::utils::cookie_utils::create_clear_cookie(
                    &related_cookie_name(&state.config, "dont_remember"),
                    &state.config,
                ),
            ] {
                _ = response.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&cookie)
                        .map_err(|_| AuthError::internal("Invalid cookie header"))?,
                );
            }
            if state.config.account.store_account_cookie {
                _ = response.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_str(
                        &better_auth_core::utils::cookie_utils::create_clear_cookie(
                            &related_cookie_name(&state.config, "account_data"),
                            &state.config,
                        ),
                    )
                    .map_err(|_| AuthError::internal("Invalid cookie header"))?,
                );
            }
            return Ok(response);
        }

        let mut response = Json(response).into_response();
        for cookie in [
            state.clear_session_cookie(),
            better_auth_core::utils::cookie_utils::create_clear_cookie(
                &related_cookie_name(&state.config, "session_data"),
                &state.config,
            ),
            better_auth_core::utils::cookie_utils::create_clear_cookie(
                &related_cookie_name(&state.config, "dont_remember"),
                &state.config,
            ),
        ] {
            _ = response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie)
                    .map_err(|_| AuthError::internal("Invalid cookie header"))?,
            );
        }
        if state.config.account.store_account_cookie {
            _ = response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&better_auth_core::utils::cookie_utils::create_clear_cookie(
                    &related_cookie_name(&state.config, "account_data"),
                    &state.config,
                ))
                .map_err(|_| AuthError::internal("Invalid cookie header"))?,
            );
        }
        Ok(response)
    }

    impl better_auth_core::AxumPlugin for UserManagementPlugin {
        fn name(&self) -> &'static str {
            "user-management"
        }

        fn router(&self) -> axum::Router<AuthState> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });

            axum::Router::new()
                .route("/change-email", post(handle_change_email))
                .route("/delete-user", post(handle_delete_user))
                .route("/delete-user/callback", get(handle_delete_user_callback))
                .layer(Extension(plugin_state))
        }
    }
}
