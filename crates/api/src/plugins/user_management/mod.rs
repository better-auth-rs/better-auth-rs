use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

use better_auth_core::adapters::DatabaseAdapter;
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
/// default [`EmailProvider`]. This allows callers to customise the email
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

// ---------------------------------------------------------------------------
// Route handlers (delegate to core functions)
// ---------------------------------------------------------------------------

impl UserManagementPlugin {
    /// `POST /change-email`
    async fn handle_change_email<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: ChangeEmailRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = change_email_core(&body, &user, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    /// `GET /change-email/verify`
    async fn handle_change_email_verify<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let token = req
            .query
            .get("token")
            .ok_or_else(|| AuthError::bad_request("Verification token is required"))?;
        let response = change_email_verify_core(token, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    /// `POST /delete-user`
    async fn handle_delete_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let response = delete_user_core(&user, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    /// `GET /delete-user/verify`
    async fn handle_delete_user_verify<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let token = req
            .query
            .get("token")
            .ok_or_else(|| AuthError::bad_request("Verification token is required"))?;
        let response = delete_user_verify_core(token, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

// ---------------------------------------------------------------------------
// AuthPlugin implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for UserManagementPlugin {
    fn name(&self) -> &'static str {
        "user-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = Vec::new();
        if self.config.change_email.enabled {
            routes.push(AuthRoute::post("/change-email", "change_email"));
            routes.push(AuthRoute::get(
                "/change-email/verify",
                "change_email_verify",
            ));
        }
        if self.config.delete_user.enabled {
            routes.push(AuthRoute::post("/delete-user", "delete_user"));
            routes.push(AuthRoute::get("/delete-user/verify", "delete_user_verify"));
        }
        routes
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            // -- change email --
            (HttpMethod::Post, "/change-email") if self.config.change_email.enabled => {
                Ok(Some(self.handle_change_email(req, ctx).await?))
            }
            (HttpMethod::Get, "/change-email/verify") if self.config.change_email.enabled => {
                Ok(Some(self.handle_change_email_verify(req, ctx).await?))
            }
            // -- delete user --
            (HttpMethod::Post, "/delete-user") if self.config.delete_user.enabled => {
                Ok(Some(self.handle_delete_user(req, ctx).await?))
            }
            (HttpMethod::Get, "/delete-user/verify") if self.config.delete_user.enabled => {
                Ok(Some(self.handle_delete_user_verify(req, ctx).await?))
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
    use better_auth_core::{AuthError, AuthState, CurrentSession, ValidatedJson};

    #[derive(Clone)]
    struct PluginState {
        config: UserManagementConfig,
    }

    async fn handle_change_email<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<ChangeEmailRequest>,
    ) -> Result<Json<StatusMessageResponse>, AuthError> {
        if !ps.config.change_email.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = change_email_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_change_email_verify<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        Query(query): Query<TokenQuery>,
    ) -> Result<Json<StatusMessageResponse>, AuthError> {
        if !ps.config.change_email.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = change_email_verify_core(&query.token, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_delete_user<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<StatusMessageResponse>, AuthError> {
        if !ps.config.delete_user.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = delete_user_core(&user, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_delete_user_verify<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        Query(query): Query<TokenQuery>,
    ) -> Result<Json<StatusMessageResponse>, AuthError> {
        if !ps.config.delete_user.enabled {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = delete_user_verify_core(&query.token, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for UserManagementPlugin {
        fn name(&self) -> &'static str {
            "user-management"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });

            axum::Router::new()
                .route("/change-email", post(handle_change_email::<DB>))
                .route(
                    "/change-email/verify",
                    get(handle_change_email_verify::<DB>),
                )
                .route("/delete-user", post(handle_delete_user::<DB>))
                .route("/delete-user/verify", get(handle_delete_user_verify::<DB>))
                .layer(Extension(plugin_state))
        }
    }
}
