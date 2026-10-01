use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

use better_auth_core::entity::AuthUser;
use better_auth_core::wire::UserView;
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
    async fn before_delete(&self, user: &UserView, request: Option<&AuthRequest>)
    -> AuthResult<()>;
}

/// Hook invoked **after** a user has been deleted.
#[async_trait]
pub trait AfterDeleteUser: Send + Sync {
    async fn after_delete(&self, user: &UserView, request: Option<&AuthRequest>) -> AuthResult<()>;
}

/// Configuring this sender requires email confirmation before account deletion.
#[async_trait]
pub trait SendDeleteAccountVerification: Send + Sync {
    async fn send(
        &self,
        user: &UserView,
        url: &str,
        token: &str,
        request: Option<&AuthRequest>,
    ) -> AuthResult<()>;
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
    /// Send confirmation instead of immediately deleting the account.
    pub send_delete_account_verification: Option<Arc<dyn SendDeleteAccountVerification>>,
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
            .field(
                "send_delete_account_verification",
                &self.send_delete_account_verification.is_some(),
            )
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
            send_delete_account_verification: None,
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

    pub fn send_delete_account_verification(
        mut self,
        sender: Arc<dyn SendDeleteAccountVerification>,
    ) -> Self {
        self.config.delete_user.send_delete_account_verification = Some(sender);
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

impl UserManagementPlugin {
    /// `POST /change-email`
    async fn handle_change_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let user = ctx.user_view(&user)?;
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
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx.require_session(req).await?;
        let user = ctx.user_view(&user)?;
        let body: DeleteUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = delete_user_core(&body, &user, &session, req, &self.config, ctx).await?;
        let mut response = AuthResponse::json(200, &response)?;
        for (name, value) in req.take_response_headers()? {
            response.headers.append(name, value);
        }
        Ok(response)
    }

    /// `GET /delete-user/callback`
    async fn handle_delete_user_callback(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(|error| {
                if error.status_code() == 401 {
                    AuthError::not_found("Failed to get user info")
                } else {
                    error
                }
            })?;
        let user = ctx.user_view(&user)?;
        let query: TokenQuery = serde_json::from_value(serde_json::json!({
            "token": req.query.get("token").cloned(),
            "callbackURL": req.query.get("callbackURL").cloned(),
        }))
        .map_err(|_| AuthError::bad_request("Verification token is required"))?;
        let response =
            delete_user_callback_core(&query.token, &user, req, &self.config, ctx).await?;
        if let Some(callback_url) = query.callback_url {
            let mut headers = better_auth_core::Headers::new();
            _ = headers.insert("Location".to_string(), callback_url);
            let mut response = AuthResponse {
                status: 302,
                headers,
                body: Vec::new(),
            };
            for (name, value) in req.take_response_headers()? {
                response.headers.append(name, value);
            }
            return Ok(response);
        }

        let mut response = AuthResponse::json(200, &response)?;
        for (name, value) in req.take_response_headers()? {
            response.headers.append(name, value);
        }
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// AuthPlugin implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for UserManagementPlugin {
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
        ctx: &AuthContext<S>,
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
