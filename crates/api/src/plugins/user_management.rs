use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthSession, AuthUser, AuthVerification};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute, SessionManager};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateVerification, HttpMethod, UpdateUser};

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
/// Return `Err(…)` from [`before_delete`](BeforeDeleteUser::before_delete) to
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
#[derive(Clone)]
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
            .field("update_without_verification", &self.update_without_verification)
            .field(
                "send_change_email_confirmation",
                &self.send_change_email_confirmation.is_some(),
            )
            .finish()
    }
}

impl Default for ChangeEmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            update_without_verification: false,
            send_change_email_confirmation: None,
        }
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
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    #[validate(email(message = "Invalid email address"))]
    new_email: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusMessageResponse {
    status: bool,
    message: String,
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
            routes.push(AuthRoute::get("/change-email/verify", "change_email_verify"));
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
// Route handlers
// ---------------------------------------------------------------------------

impl UserManagementPlugin {
    // ── helpers ────────────────────────────────────────────────────────

    /// Require an authenticated session and return `(user, session)`.
    async fn require_session<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<(DB::User, DB::Session)> {
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
            && let Some(user) = ctx.database.get_user_by_id(session.user_id()).await?
        {
            return Ok((user, session));
        }

        Err(AuthError::Unauthenticated)
    }

    // ── change email ──────────────────────────────────────────────────

    /// `POST /change-email`
    async fn handle_change_email<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;

        let change_req: ChangeEmailRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Prevent changing to the same email
        if user.email().map(|e| e == change_req.new_email).unwrap_or(false) {
            return Err(AuthError::bad_request(
                "New email must be different from the current email",
            ));
        }

        // Check if the new email is already in use
        if ctx
            .database
            .get_user_by_email(&change_req.new_email)
            .await?
            .is_some()
        {
            return Err(AuthError::bad_request(
                "Email is already in use by another account",
            ));
        }

        // Generate verification token
        let verification_token = format!("ce_{}", Uuid::new_v4());
        let identifier = format!("change_email:{}:{}", user.id(), change_req.new_email);
        let expires_at = Utc::now() + Duration::hours(24);

        let create_verification = CreateVerification {
            identifier: identifier.clone(),
            value: verification_token.clone(),
            expires_at,
        };

        ctx.database
            .create_verification(create_verification)
            .await?;

        // Build the verification URL
        let verification_url = if let Some(callback_url) = &change_req.callback_url {
            format!("{}?token={}", callback_url, verification_token)
        } else {
            format!(
                "{}/change-email/verify?token={}",
                ctx.config.base_url, verification_token
            )
        };

        // Send confirmation email via custom callback or default provider
        if let Some(ref cb) = self.config.change_email.send_change_email_confirmation {
            let user_info = UserInfo::from_auth_user(&user);
            cb.send(
                &user_info,
                &change_req.new_email,
                &verification_url,
                &verification_token,
            )
            .await?;
        } else if let Ok(provider) = ctx.email_provider() {
            let subject = "Confirm your email change";
            let html = format!(
                "<p>Click the link below to confirm your new email address:</p>\
                 <p><a href=\"{url}\">Confirm Email Change</a></p>",
                url = verification_url
            );
            let text = format!("Confirm your email change: {}", verification_url);

            if let Err(e) = provider
                .send(&change_req.new_email, subject, &html, &text)
                .await
            {
                eprintln!(
                    "[user-management] Failed to send change-email confirmation to {}: {}",
                    change_req.new_email, e
                );
            }
        } else {
            eprintln!(
                "[user-management] No email provider or callback configured, skipping change-email confirmation for {}",
                change_req.new_email
            );
        }

        let response = StatusMessageResponse {
            status: true,
            message: "Verification email sent to your new email address".to_string(),
        };
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

        // Locate and validate the verification token
        let verification = ctx
            .database
            .get_verification_by_value(token)
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid or expired verification token"))?;

        // Check expiry
        if verification.expires_at() < Utc::now() {
            // Clean up the expired token
            ctx.database.delete_verification(verification.id()).await?;
            return Err(AuthError::bad_request("Verification token has expired"));
        }

        // Parse the identifier: change_email:{user_id}:{new_email}
        let identifier = verification.identifier();
        let parts: Vec<&str> = identifier.splitn(3, ':').collect();
        if parts.len() != 3 || parts[0] != "change_email" {
            return Err(AuthError::bad_request("Invalid verification token"));
        }

        let user_id = parts[1];
        let new_email = parts[2];

        // Fetch the user
        let user = ctx
            .database
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Check if the new email is still available
        if ctx
            .database
            .get_user_by_email(new_email)
            .await?
            .is_some()
        {
            ctx.database.delete_verification(verification.id()).await?;
            return Err(AuthError::bad_request(
                "Email is already in use by another account",
            ));
        }

        // Determine new email_verified status:
        // If old email was verified, mark new email as unverified
        // (unless update_without_verification is set).
        let new_verified = if user.email_verified() {
            self.config.change_email.update_without_verification
        } else {
            false
        };

        let update_user = UpdateUser {
            email: Some(new_email.to_string()),
            email_verified: Some(new_verified),
            ..Default::default()
        };

        ctx.database.update_user(user.id(), update_user).await?;

        // Consume the verification token
        ctx.database.delete_verification(verification.id()).await?;

        let response = StatusMessageResponse {
            status: true,
            message: "Email updated successfully".to_string(),
        };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── delete user ───────────────────────────────────────────────────

    /// `POST /delete-user`
    async fn handle_delete_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;

        if self.config.delete_user.require_verification {
            // Send a verification email; actual deletion happens on GET /delete-user/verify.
            let delete_token = format!("del_{}", Uuid::new_v4());
            let identifier = format!("delete_user:{}", user.id());
            let expires_at = Utc::now() + self.config.delete_user.delete_token_expires_in;

            let create_verification = CreateVerification {
                identifier,
                value: delete_token.clone(),
                expires_at,
            };

            ctx.database
                .create_verification(create_verification)
                .await?;

            // Send confirmation email
            let verification_url = format!(
                "{}/delete-user/verify?token={}",
                ctx.config.base_url, delete_token
            );

            if let Ok(provider) = ctx.email_provider() {
                let email = user.email().unwrap_or_default();
                let subject = "Confirm account deletion";
                let html = format!(
                    "<p>Click the link below to confirm the deletion of your account:</p>\
                     <p><a href=\"{url}\">Confirm Account Deletion</a></p>\
                     <p>If you did not request this, please ignore this email.</p>",
                    url = verification_url
                );
                let text = format!("Confirm account deletion: {}", verification_url);

                if let Err(e) = provider.send(email, subject, &html, &text).await {
                    eprintln!(
                        "[user-management] Failed to send delete-user confirmation to {}: {}",
                        email, e
                    );
                }
            } else {
                eprintln!(
                    "[user-management] No email provider configured, skipping delete-user confirmation for user {}",
                    user.id()
                );
            }

            let response = StatusMessageResponse {
                status: true,
                message: "Verification email sent. Please confirm to delete your account."
                    .to_string(),
            };
            Ok(AuthResponse::json(200, &response)?)
        } else {
            // Immediate deletion (no verification required)
            self.perform_user_deletion(&user, ctx).await?;

            let response = StatusMessageResponse {
                status: true,
                message: "Account deleted successfully".to_string(),
            };
            Ok(AuthResponse::json(200, &response)?)
        }
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

        // Locate and validate the verification token
        let verification = ctx
            .database
            .get_verification_by_value(token)
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid or expired verification token"))?;

        // Check expiry
        if verification.expires_at() < Utc::now() {
            ctx.database.delete_verification(verification.id()).await?;
            return Err(AuthError::bad_request("Verification token has expired"));
        }

        // Parse the identifier: delete_user:{user_id}
        let identifier = verification.identifier();
        let parts: Vec<&str> = identifier.splitn(2, ':').collect();
        if parts.len() != 2 || parts[0] != "delete_user" {
            return Err(AuthError::bad_request("Invalid verification token"));
        }

        let user_id = parts[1];

        // Fetch the user
        let user = ctx
            .database
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Consume the verification token first
        ctx.database.delete_verification(verification.id()).await?;

        // Perform the actual deletion
        self.perform_user_deletion(&user, ctx).await?;

        let response = StatusMessageResponse {
            status: true,
            message: "Account deleted successfully".to_string(),
        };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── shared deletion logic ─────────────────────────────────────────

    /// Delete a user together with all their sessions and accounts.
    ///
    /// Calls the configured `before_delete` / `after_delete` hooks when
    /// present.
    async fn perform_user_deletion<DB: DatabaseAdapter>(
        &self,
        user: &DB::User,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        let user_info = UserInfo::from_auth_user(user);

        // before_delete hook
        if let Some(ref hook) = self.config.delete_user.before_delete {
            hook.before_delete(&user_info).await?;
        }

        // Delete all sessions
        ctx.database.delete_user_sessions(user.id()).await?;

        // Delete all linked accounts
        let accounts = ctx.database.get_user_accounts(user.id()).await?;
        for account in &accounts {
            use better_auth_core::entity::AuthAccount;
            ctx.database.delete_account(account.id()).await?;
        }

        // Delete the user record
        ctx.database.delete_user(user.id()).await?;

        // after_delete hook
        if let Some(ref hook) = self.config.delete_user.after_delete {
            hook.after_delete(&user_info).await?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps, VerificationOps};
    use better_auth_core::config::AuthConfig;
    use better_auth_core::{CreateSession, CreateUser, Session, User};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn create_test_context_with_user() -> (AuthContext<MemoryDatabaseAdapter>, User, Session)
    {
        let config = Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long"));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config.clone(), database.clone());

        let create_user = CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true);
        let user = database.create_user(create_user).await.unwrap();

        let create_session = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session = database.create_session(create_session).await.unwrap();

        (ctx, user, session)
    }

    fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }

        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body,
            query,
        }
    }

    // ── change email tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_change_email_success() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = plugin.handle_change_email(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_change_email_same_email() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({ "newEmail": "test@example.com" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let err = plugin.handle_change_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn test_change_email_unauthenticated() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-email",
            None,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let err = plugin.handle_change_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn test_change_email_verify_success() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, user, session) = create_test_context_with_user().await;

        // 1. Initiate the change
        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        plugin.handle_change_email(&req, &ctx).await.unwrap();

        // 2. Find the verification token created
        let identifier = format!("change_email:{}:new@example.com", user.id);
        let verification = ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .expect("verification should exist");

        // 3. Verify the token
        let mut query = HashMap::new();
        query.insert("token".to_string(), verification.value.clone());
        let req = create_auth_request(
            HttpMethod::Get,
            "/change-email/verify",
            None,
            None,
            query,
        );
        let response = plugin
            .handle_change_email_verify(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        // 4. Confirm the email was updated
        let updated_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_user.email.as_deref(), Some("new@example.com"));
        // Old email was verified → new email should be unverified
        assert!(!updated_user.email_verified);
    }

    #[tokio::test]
    async fn test_change_email_verify_keeps_verified_when_configured() {
        let plugin = UserManagementPlugin::new()
            .change_email_enabled(true)
            .update_without_verification(true);
        let (ctx, user, session) = create_test_context_with_user().await;

        // Initiate change
        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        plugin.handle_change_email(&req, &ctx).await.unwrap();

        // Find token
        let identifier = format!("change_email:{}:new@example.com", user.id);
        let verification = ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .expect("verification should exist");

        // Verify
        let mut query = HashMap::new();
        query.insert("token".to_string(), verification.value.clone());
        let req = create_auth_request(
            HttpMethod::Get,
            "/change-email/verify",
            None,
            None,
            query,
        );
        plugin
            .handle_change_email_verify(&req, &ctx)
            .await
            .unwrap();

        let updated_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_user.email.as_deref(), Some("new@example.com"));
        // update_without_verification = true → should remain verified
        assert!(updated_user.email_verified);
    }

    #[tokio::test]
    async fn test_change_email_verify_invalid_token() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let mut query = HashMap::new();
        query.insert("token".to_string(), "invalid-token".to_string());
        let req = create_auth_request(
            HttpMethod::Get,
            "/change-email/verify",
            None,
            None,
            query,
        );

        let err = plugin
            .handle_change_email_verify(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // ── delete user tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_user_immediate() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false);
        let (ctx, user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // User should be gone
        let deleted_user = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(deleted_user.is_none());
    }

    #[tokio::test]
    async fn test_delete_user_with_verification() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(true);
        let (ctx, user, session) = create_test_context_with_user().await;

        // 1. Request deletion — should return pending status
        let req = create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // User should still exist
        let still_exists = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(still_exists.is_some());

        // 2. Find the verification token
        let identifier = format!("delete_user:{}", user.id);
        let verification = ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .expect("verification should exist");

        // 3. Confirm deletion
        let mut query = HashMap::new();
        query.insert("token".to_string(), verification.value.clone());
        let req = create_auth_request(
            HttpMethod::Get,
            "/delete-user/verify",
            None,
            None,
            query,
        );
        let response = plugin
            .handle_delete_user_verify(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        // User should now be gone
        let deleted = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_delete_user_unauthenticated() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false);
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            None,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let err = plugin.handle_delete_user(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn test_delete_user_verify_invalid_token() {
        let plugin = UserManagementPlugin::new().delete_user_enabled(true);
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let mut query = HashMap::new();
        query.insert("token".to_string(), "invalid-token".to_string());
        let req = create_auth_request(
            HttpMethod::Get,
            "/delete-user/verify",
            None,
            None,
            query,
        );

        let err = plugin
            .handle_delete_user_verify(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn test_delete_user_before_hook_abort() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct AbortHook;
        #[async_trait]
        impl BeforeDeleteUser for AbortHook {
            async fn before_delete(&self, _user: &UserInfo) -> AuthResult<()> {
                Err(AuthError::forbidden("Deletion blocked by policy"))
            }
        }

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        struct AfterHook(Arc<AtomicBool>);
        #[async_trait]
        impl AfterDeleteUser for AfterHook {
            async fn after_delete(&self, _user: &UserInfo) -> AuthResult<()> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false)
            .before_delete(Arc::new(AbortHook))
            .after_delete(Arc::new(AfterHook(called_clone)));
        let (ctx, user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let err = plugin.handle_delete_user(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 403);

        // User should still exist
        let still_exists = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(still_exists.is_some());

        // after_delete should NOT have been called
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_plugin_routes_conditional() {
        // All disabled
        let plugin = UserManagementPlugin::new();
        assert!(plugin.routes().is_empty());

        // Only change-email enabled
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let routes = plugin.routes();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|r| r.path == "/change-email"));
        assert!(routes.iter().any(|r| r.path == "/change-email/verify"));

        // Only delete-user enabled
        let plugin = UserManagementPlugin::new().delete_user_enabled(true);
        let routes = plugin.routes();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|r| r.path == "/delete-user"));
        assert!(routes.iter().any(|r| r.path == "/delete-user/verify"));

        // Both enabled
        let plugin = UserManagementPlugin::new()
            .change_email_enabled(true)
            .delete_user_enabled(true);
        assert_eq!(plugin.routes().len(), 4);
    }

    #[tokio::test]
    async fn test_on_request_disabled_routes_passthrough() {
        let plugin = UserManagementPlugin::new(); // both disabled
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({ "newEmail": "x@y.com" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let result = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(result.is_none(), "disabled routes should return None");
    }
}
