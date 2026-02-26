use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute, ListUsersParams, SessionManager};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser, HttpMethod, UpdateUser,
};

use better_auth_core::utils::cookie_utils::create_session_cookie;

// ---------------------------------------------------------------------------
// Plugin & config
// ---------------------------------------------------------------------------

/// Admin plugin for user management operations.
///
/// Provides endpoints for creating users, listing users, banning/unbanning,
/// role management, session management, password management, user impersonation,
/// and permission checks.
///
/// All endpoints require an authenticated session with the `admin` role.
pub struct AdminPlugin {
    config: AdminConfig,
}

/// Configuration for the admin plugin.
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// The role required to access admin endpoints (default: `"admin"`).
    pub admin_role: String,
    /// Default role assigned to newly created users (default: `"user"`).
    pub default_user_role: String,
    /// Whether to allow banning other admins (default: `false`).
    pub allow_ban_admin: bool,
    /// Default number of users returned in list-users (default: 100).
    pub default_page_limit: usize,
    /// Maximum number of users returned in list-users (default: 500).
    pub max_page_limit: usize,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            admin_role: "admin".to_string(),
            default_user_role: "user".to_string(),
            allow_ban_admin: false,
            default_page_limit: 100,
            max_page_limit: 500,
        }
    }
}

impl AdminPlugin {
    pub fn new() -> Self {
        Self {
            config: AdminConfig::default(),
        }
    }

    pub fn with_config(config: AdminConfig) -> Self {
        Self { config }
    }

    pub fn admin_role(mut self, role: impl Into<String>) -> Self {
        self.config.admin_role = role.into();
        self
    }

    pub fn default_user_role(mut self, role: impl Into<String>) -> Self {
        self.config.default_user_role = role.into();
        self
    }

    pub fn allow_ban_admin(mut self, allow: bool) -> Self {
        self.config.allow_ban_admin = allow;
        self
    }

    pub fn default_page_limit(mut self, limit: usize) -> Self {
        self.config.default_page_limit = limit;
        self
    }

    pub fn max_page_limit(mut self, limit: usize) -> Self {
        self.config.max_page_limit = limit;
        self
    }
}

impl Default for AdminPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
struct SetRoleRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    user_id: String,
    #[validate(length(min = 1, message = "role is required"))]
    role: String,
}

#[derive(Debug, Deserialize, Validate)]
struct CreateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[validate(length(min = 1, message = "Name is required"))]
    name: String,
    role: Option<String>,
    data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
struct UserIdRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    user_id: String,
}

#[derive(Debug, Deserialize, Validate)]
struct BanUserRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    user_id: String,
    #[serde(rename = "banReason")]
    ban_reason: Option<String>,
    /// Number of seconds until the ban expires.
    #[serde(rename = "banExpiresIn")]
    ban_expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
struct RevokeSessionRequest {
    #[serde(rename = "sessionToken")]
    #[validate(length(min = 1, message = "sessionToken is required"))]
    session_token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct SetUserPasswordRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    user_id: String,
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "newPassword is required"))]
    new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
struct HasPermissionRequest {
    permission: Option<serde_json::Value>,
    permissions: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct UserResponse<U: Serialize> {
    user: U,
}

#[derive(Debug, Serialize)]
struct SessionUserResponse<S: Serialize, U: Serialize> {
    session: S,
    user: U,
}

#[derive(Debug, Serialize)]
struct ListUsersResponse<U: Serialize> {
    users: Vec<U>,
    total: usize,
    limit: usize,
    offset: usize,
}

#[derive(Debug, Serialize)]
struct ListSessionsResponse<S: Serialize> {
    sessions: Vec<S>,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

#[derive(Debug, Serialize)]
struct PermissionResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Plugin trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for AdminPlugin {
    fn name(&self) -> &'static str {
        "admin"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/admin/set-role", "admin_set_role"),
            AuthRoute::post("/admin/create-user", "admin_create_user"),
            AuthRoute::get("/admin/list-users", "admin_list_users"),
            AuthRoute::post("/admin/list-user-sessions", "admin_list_user_sessions"),
            AuthRoute::post("/admin/ban-user", "admin_ban_user"),
            AuthRoute::post("/admin/unban-user", "admin_unban_user"),
            AuthRoute::post("/admin/impersonate-user", "admin_impersonate_user"),
            AuthRoute::post("/admin/stop-impersonating", "admin_stop_impersonating"),
            AuthRoute::post("/admin/revoke-user-session", "admin_revoke_user_session"),
            AuthRoute::post("/admin/revoke-user-sessions", "admin_revoke_user_sessions"),
            AuthRoute::post("/admin/remove-user", "admin_remove_user"),
            AuthRoute::post("/admin/set-user-password", "admin_set_user_password"),
            AuthRoute::post("/admin/has-permission", "admin_has_permission"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/admin/set-role") => {
                Ok(Some(self.handle_set_role(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/create-user") => {
                Ok(Some(self.handle_create_user(req, ctx).await?))
            }
            (HttpMethod::Get, "/admin/list-users") => {
                Ok(Some(self.handle_list_users(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/list-user-sessions") => {
                Ok(Some(self.handle_list_user_sessions(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/ban-user") => {
                Ok(Some(self.handle_ban_user(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/unban-user") => {
                Ok(Some(self.handle_unban_user(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/impersonate-user") => {
                Ok(Some(self.handle_impersonate_user(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/stop-impersonating") => {
                Ok(Some(self.handle_stop_impersonating(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/revoke-user-session") => {
                Ok(Some(self.handle_revoke_user_session(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/revoke-user-sessions") => {
                Ok(Some(self.handle_revoke_user_sessions(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/remove-user") => {
                Ok(Some(self.handle_remove_user(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/set-user-password") => {
                Ok(Some(self.handle_set_user_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/has-permission") => {
                Ok(Some(self.handle_has_permission(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Handler implementations
// ---------------------------------------------------------------------------

impl AdminPlugin {
    // -- Auth helpers --------------------------------------------------------

    /// Authenticate the caller and verify they have the admin role.
    async fn require_admin<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<(DB::User, DB::Session)> {
        let (user, session) = ctx.require_session(req).await?;

        // Check admin role
        let user_role = user.role().unwrap_or("user");
        if user_role != self.config.admin_role {
            return Err(AuthError::forbidden(
                "You do not have permission to access this resource",
            ));
        }

        Ok((user, session))
    }

    // -- Handlers -----------------------------------------------------------

    /// POST /admin/set-role — Set the role of a user.
    async fn handle_set_role<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: SetRoleRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Find target user
        let _target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        let update = UpdateUser {
            role: Some(body.role),
            ..Default::default()
        };

        let updated_user = ctx.database.update_user(&body.user_id, update).await?;

        let response = UserResponse { user: updated_user };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/create-user — Create a new user (admin only).
    async fn handle_create_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: CreateUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Check if user with email already exists
        if ctx.database.get_user_by_email(&body.email).await?.is_some() {
            return Err(AuthError::conflict("A user with this email already exists"));
        }

        // Validate password length
        if body.password.len() < ctx.config.password.min_length {
            return Err(AuthError::bad_request(format!(
                "Password must be at least {} characters long",
                ctx.config.password.min_length
            )));
        }

        // Hash the password
        let password_hash = better_auth_core::hash_password(None, &body.password).await?;

        let role = body
            .role
            .unwrap_or_else(|| self.config.default_user_role.clone());

        // Normalize metadata to always be a JSON object and include the password_hash
        let metadata_value = body.data.unwrap_or(serde_json::json!({}));
        let metadata = if let serde_json::Value::Object(mut obj) = metadata_value {
            obj.insert(
                "password_hash".to_string(),
                serde_json::json!(password_hash),
            );
            serde_json::Value::Object(obj)
        } else {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "password_hash".to_string(),
                serde_json::json!(password_hash),
            );
            serde_json::Value::Object(obj)
        };

        let create_user = CreateUser::new()
            .with_email(&body.email)
            .with_name(&body.name)
            .with_role(role)
            .with_email_verified(true)
            .with_metadata(metadata);

        let user = ctx.database.create_user(create_user).await?;

        // Create a credential account for the user
        ctx.database
            .create_account(CreateAccount {
                user_id: user.id().to_string(),
                account_id: user.id().to_string(),
                provider_id: "credential".to_string(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some(password_hash),
            })
            .await?;

        let response = UserResponse { user };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// GET /admin/list-users — List users with optional search, filter, sort, and pagination.
    async fn handle_list_users<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let limit = req
            .query
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(self.config.default_page_limit)
            .min(self.config.max_page_limit);

        let offset = req
            .query
            .get("offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        let params = ListUsersParams {
            limit: Some(limit),
            offset: Some(offset),
            search_field: req.query.get("searchField").cloned(),
            search_value: req.query.get("searchValue").cloned(),
            search_operator: req.query.get("searchOperator").cloned(),
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
            filter_field: req.query.get("filterField").cloned(),
            filter_value: req.query.get("filterValue").cloned(),
            filter_operator: req.query.get("filterOperator").cloned(),
        };

        let (users, total) = ctx.database.list_users(params).await?;

        let response = ListUsersResponse {
            users,
            total,
            limit,
            offset,
        };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/list-user-sessions — List all active sessions for a user.
    async fn handle_list_user_sessions<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Verify the target user exists
        let _target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let sessions = session_manager.list_user_sessions(&body.user_id).await?;

        let response = ListSessionsResponse { sessions };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/ban-user — Ban a user.
    async fn handle_ban_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: BanUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Prevent banning yourself
        if body.user_id == admin_user.id() {
            return Err(AuthError::bad_request("You cannot ban yourself"));
        }

        let target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Prevent banning other admins unless explicitly allowed
        if !self.config.allow_ban_admin && target.role().unwrap_or("user") == self.config.admin_role
        {
            return Err(AuthError::forbidden("Cannot ban an admin user"));
        }

        let ban_expires = body
            .ban_expires_in
            .and_then(Duration::try_seconds)
            .map(|d| Utc::now() + d);

        let update = UpdateUser {
            banned: Some(true),
            ban_reason: body.ban_reason,
            ban_expires,
            ..Default::default()
        };

        let updated_user = ctx.database.update_user(&body.user_id, update).await?;

        // Revoke all sessions for the banned user
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        session_manager
            .revoke_all_user_sessions(&body.user_id)
            .await?;

        let response = UserResponse { user: updated_user };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/unban-user — Unban a user.
    async fn handle_unban_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let _target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        let update = UpdateUser {
            banned: Some(false),
            ban_reason: None,
            ban_expires: None,
            ..Default::default()
        };

        // The adapter's apply_update clears ban_reason and ban_expires
        // when banned is explicitly set to false.
        let updated_user = ctx.database.update_user(&body.user_id, update).await?;

        let response = UserResponse { user: updated_user };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/impersonate-user — Create an impersonation session.
    async fn handle_impersonate_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Cannot impersonate yourself
        if body.user_id == admin_user.id() {
            return Err(AuthError::bad_request("Cannot impersonate yourself"));
        }

        let target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Create an impersonation session
        let expires_at = Utc::now() + ctx.config.session.expires_in;
        let create_session = CreateSession {
            user_id: target.id().to_string(),
            expires_at,
            ip_address: req.headers.get("x-forwarded-for").cloned(),
            user_agent: req.headers.get("user-agent").cloned(),
            impersonated_by: Some(admin_user.id().to_string()),
            active_organization_id: None,
        };

        let session = ctx.database.create_session(create_session).await?;

        let cookie_header = create_session_cookie(session.token(), ctx);
        let response = SessionUserResponse {
            session,
            user: target,
        };

        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /admin/stop-impersonating — Stop the current impersonation session.
    async fn handle_stop_impersonating<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());

        let token = session_manager
            .extract_session_token(req)
            .ok_or(AuthError::Unauthenticated)?;

        let session = session_manager
            .get_session(&token)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        // Must be an impersonation session
        let admin_id = session
            .impersonated_by()
            .ok_or_else(|| {
                AuthError::bad_request("Current session is not an impersonation session")
            })?
            .to_string();

        // Delete the impersonation session
        session_manager.delete_session(&token).await?;

        // Look up the original admin user
        let admin_user = ctx
            .database
            .get_user_by_id(&admin_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Create a new session for the admin user so the client
        // transitions back to a valid admin session.
        let expires_at = Utc::now() + ctx.config.session.expires_in;
        let create_session = CreateSession {
            user_id: admin_id,
            expires_at,
            ip_address: req.headers.get("x-forwarded-for").cloned(),
            user_agent: req.headers.get("user-agent").cloned(),
            impersonated_by: None,
            active_organization_id: None,
        };

        let admin_session = ctx.database.create_session(create_session).await?;

        let cookie_header = create_session_cookie(admin_session.token(), ctx);
        let response = SessionUserResponse {
            session: admin_session,
            user: admin_user,
        };

        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /admin/revoke-user-session — Revoke a specific session by token.
    async fn handle_revoke_user_session<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: RevokeSessionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        session_manager.delete_session(&body.session_token).await?;

        let response = SuccessResponse { success: true };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/revoke-user-sessions — Revoke all sessions for a user.
    async fn handle_revoke_user_sessions<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Verify the target user exists
        let _target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        session_manager
            .revoke_all_user_sessions(&body.user_id)
            .await?;

        let response = SuccessResponse { success: true };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/remove-user — Delete a user and all their data.
    ///
    /// **Note:** This endpoint deletes sessions, accounts, and the user record.
    /// Data owned by other plugins (passkeys, two-factor settings, API keys,
    /// organization memberships) is **not** cleaned up here.  Those records
    /// should be removed through the respective plugin APIs or via database
    /// cascade rules.
    async fn handle_remove_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Prevent self-deletion
        if body.user_id == admin_user.id() {
            return Err(AuthError::bad_request("You cannot remove yourself"));
        }

        // Verify user exists
        let _target = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Revoke all sessions first
        ctx.database.delete_user_sessions(&body.user_id).await?;

        // Delete all accounts linked to this user
        let accounts = ctx.database.get_user_accounts(&body.user_id).await?;
        for account in &accounts {
            ctx.database.delete_account(account.id()).await?;
        }

        // Delete the user
        ctx.database.delete_user(&body.user_id).await?;

        let response = SuccessResponse { success: true };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/set-user-password — Set a user's password.
    async fn handle_set_user_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;

        let body: SetUserPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validate password length
        if body.new_password.len() < ctx.config.password.min_length {
            return Err(AuthError::bad_request(format!(
                "Password must be at least {} characters long",
                ctx.config.password.min_length
            )));
        }

        // Verify user exists
        let user = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        let password_hash = better_auth_core::hash_password(None, &body.new_password).await?;

        // Update password in user metadata
        let mut metadata = user.metadata().clone();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "password_hash".to_string(),
                serde_json::json!(password_hash),
            );
        } else {
            return Err(AuthError::bad_request(
                "User metadata must be a JSON object to store password hash",
            ));
        }

        let update = UpdateUser {
            metadata: Some(metadata),
            ..Default::default()
        };
        ctx.database.update_user(&body.user_id, update).await?;

        // Update the credential account's password field (or create one if missing)
        let accounts = ctx.database.get_user_accounts(&body.user_id).await?;
        let has_credential = accounts.iter().any(|a| a.provider_id() == "credential");

        if has_credential {
            for account in &accounts {
                if account.provider_id() == "credential" {
                    let account_update = better_auth_core::UpdateAccount {
                        password: Some(password_hash.clone()),
                        ..Default::default()
                    };
                    ctx.database
                        .update_account(account.id(), account_update)
                        .await?;
                    break;
                }
            }
        } else {
            // User has no credential account (e.g. OAuth-only user).
            // Create one so the password is usable for email/password sign-in.
            ctx.database
                .create_account(CreateAccount {
                    user_id: body.user_id.clone(),
                    account_id: body.user_id.clone(),
                    provider_id: "credential".to_string(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash.clone()),
                })
                .await?;
        }

        let response = StatusResponse { status: true };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/has-permission — Check if the calling user has a given permission.
    async fn handle_has_permission<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;

        let body: HasPermissionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Use the `permissions` field, falling back to deprecated `permission`.
        let _permissions = body.permissions.or(body.permission);

        let is_admin = user.role().unwrap_or("user") == self.config.admin_role;

        // If the user is an admin they have all permissions.
        // Otherwise check if the requested permission matches a simple
        // role-based scheme. The `permissions` object from the spec is
        // free-form; we treat it as a map of resource -> action arrays
        // and grant access if the user's role matches the admin role.
        let (success, error) = if is_admin {
            (true, None)
        } else {
            (
                false,
                Some("User does not have the required permissions".to_string()),
            )
        };

        let response = PermissionResponse { success, error };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapters::{AccountOps, MemoryDatabaseAdapter, SessionOps, UserOps};
    use better_auth_core::entity::AuthAccount;
    use better_auth_core::{CreateSession, Session, User};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn create_admin_context() -> (
        AuthContext<MemoryDatabaseAdapter>,
        User,
        Session,
        User,
        Session,
    ) {
        let config = Arc::new(better_auth_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config, database.clone());

        // Create admin user
        let admin = database
            .create_user(
                CreateUser::new()
                    .with_email("admin@example.com")
                    .with_name("Admin")
                    .with_role("admin"),
            )
            .await
            .unwrap();

        let admin_session = database
            .create_session(CreateSession {
                user_id: admin.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        // Create regular user
        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("user@example.com")
                    .with_name("Regular User")
                    .with_role("user"),
            )
            .await
            .unwrap();

        let user_session = database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        (ctx, admin, admin_session, user, user_session)
    }

    fn make_request(
        method: HttpMethod,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body: body.map(|b| serde_json::to_vec(&b).unwrap()),
            query: HashMap::new(),
        }
    }

    fn make_request_with_query(
        method: HttpMethod,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body: body.map(|b| serde_json::to_vec(&b).unwrap()),
            query,
        }
    }

    fn json_body(resp: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&resp.body).unwrap()
    }

    // -----------------------------------------------------------------------
    // Basic auth / access control
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_set_role() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-role",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "role": "moderator"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["role"], "moderator");
    }

    #[tokio::test]
    async fn test_non_admin_rejected() {
        let (ctx, _admin, _admin_session, _user, user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-role",
            &user_session.token,
            Some(serde_json::json!({
                "userId": "someone",
                "role": "admin"
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unauthenticated_rejected() {
        let (ctx, _admin, _admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-role",
            "invalid-token",
            Some(serde_json::json!({
                "userId": user.id,
                "role": "admin"
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_custom_admin_role() {
        let config = Arc::new(better_auth_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config, database.clone());

        // Create superadmin user with custom role
        let admin = database
            .create_user(
                CreateUser::new()
                    .with_email("superadmin@example.com")
                    .with_name("Super Admin")
                    .with_role("superadmin"),
            )
            .await
            .unwrap();

        let admin_session = database
            .create_session(CreateSession {
                user_id: admin.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("user@example.com")
                    .with_name("User")
                    .with_role("user"),
            )
            .await
            .unwrap();

        let plugin = AdminPlugin::new().admin_role("superadmin");

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-role",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "role": "moderator"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["role"], "moderator");
    }

    #[tokio::test]
    async fn test_non_admin_path_returns_none() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/api/not-admin",
            &admin_session.token,
            None,
        );

        // Routes not matching /admin/* should return None (not handled by plugin)
        let result = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Create user
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_user() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "new@example.com",
                "password": "securepassword123",
                "name": "New User"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["email"], "new@example.com");
        assert_eq!(body["user"]["name"], "New User");
        assert_eq!(body["user"]["role"], "user");
    }

    #[tokio::test]
    async fn test_create_user_with_custom_role() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "mod@example.com",
                "password": "securepassword123",
                "name": "Moderator",
                "role": "moderator"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["role"], "moderator");
    }

    #[tokio::test]
    async fn test_create_user_creates_credential_account() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "new@example.com",
                "password": "securepassword123",
                "name": "New User"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        let user_id = body["user"]["id"].as_str().unwrap();

        // Verify a credential account was created
        let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].provider_id(), "credential");
        assert!(accounts[0].password().is_some());
    }

    #[tokio::test]
    async fn test_create_user_duplicate_email_rejected() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // user@example.com already exists in the context
        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "user@example.com",
                "password": "securepassword123",
                "name": "Duplicate"
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_user_default_role_config() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new().default_user_role("member");

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "newmember@example.com",
                "password": "securepassword123",
                "name": "New Member"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["role"], "member");
    }

    // -----------------------------------------------------------------------
    // List users
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_users() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Get,
            "/admin/list-users",
            &admin_session.token,
            None,
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["total"], 2); // admin + regular user
        assert_eq!(body["users"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_users_pagination() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let mut query = HashMap::new();
        query.insert("limit".to_string(), "1".to_string());
        query.insert("offset".to_string(), "0".to_string());

        let req = make_request_with_query(
            HttpMethod::Get,
            "/admin/list-users",
            &admin_session.token,
            None,
            query,
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["total"], 2); // total is still 2
        assert_eq!(body["users"].as_array().unwrap().len(), 1); // but only 1 returned
        assert_eq!(body["limit"], 1);
        assert_eq!(body["offset"], 0);
    }

    #[tokio::test]
    async fn test_list_users_respects_max_page_limit() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new().max_page_limit(1);

        // Request limit=100 but max is 1
        let mut query = HashMap::new();
        query.insert("limit".to_string(), "100".to_string());

        let req = make_request_with_query(
            HttpMethod::Get,
            "/admin/list-users",
            &admin_session.token,
            None,
            query,
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        // Should be clamped to max_page_limit=1
        assert_eq!(body["users"].as_array().unwrap().len(), 1);
        assert_eq!(body["limit"], 1);
    }

    // -----------------------------------------------------------------------
    // List user sessions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_user_sessions() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/list-user-sessions",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        let sessions = body["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_list_user_sessions_nonexistent_user() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/list-user-sessions",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "nonexistent-id",
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Ban / Unban
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ban_unban_user() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Ban user
        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "banReason": "spam"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["banned"], true);

        // Unban user
        let req = make_request(
            HttpMethod::Post,
            "/admin/unban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["banned"], false);
    }

    #[tokio::test]
    async fn test_cannot_ban_self() {
        let (ctx, admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": admin.id,
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    /// Verifies the bug fix: unbanning clears ban_reason and ban_expires in the adapter.
    #[tokio::test]
    async fn test_unban_clears_ban_reason_and_expires() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Ban with reason and expiry
        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "banReason": "spam",
                "banExpiresIn": 3600
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["banned"], true);
        assert_eq!(body["user"]["banReason"], "spam");
        assert!(!body["user"]["banExpires"].is_null());

        // Unban
        let req = make_request(
            HttpMethod::Post,
            "/admin/unban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["banned"], false);

        // Verify ban_reason and ban_expires are cleared by checking the DB directly
        let updated_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!updated_user.banned);
        assert!(updated_user.ban_reason.is_none());
        assert!(updated_user.ban_expires.is_none());
    }

    #[tokio::test]
    async fn test_ban_with_expiry() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "banExpiresIn": 7200 // 2 hours
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["banned"], true);
        assert!(!body["user"]["banExpires"].is_null());
    }

    #[tokio::test]
    async fn test_ban_revokes_user_sessions() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Confirm user has sessions
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(!sessions.is_empty());

        // Ban user
        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "banReason": "bad behavior"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);

        // After ban, sessions should be revoked
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_cannot_ban_admin_by_default() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Create second admin
        let admin2 = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("admin2@example.com")
                    .with_name("Admin 2")
                    .with_role("admin"),
            )
            .await
            .unwrap();

        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": admin2.id,
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_allow_ban_admin_config() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new().allow_ban_admin(true);

        // Create second admin
        let admin2 = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("admin2@example.com")
                    .with_name("Admin 2")
                    .with_role("admin"),
            )
            .await
            .unwrap();

        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": admin2.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["banned"], true);
    }

    // -----------------------------------------------------------------------
    // Impersonation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_impersonate_and_stop() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Impersonate
        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["user"]["email"], "user@example.com");
        assert!(body["session"]["token"].is_string());
    }

    /// Verifies the impersonation session has the impersonated_by field set.
    #[tokio::test]
    async fn test_impersonate_session_has_impersonated_by() {
        let (ctx, admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        let imp_token = body["session"]["token"].as_str().unwrap();

        // Look up the impersonation session and check impersonated_by
        let imp_session = ctx.database.get_session(imp_token).await.unwrap().unwrap();
        assert_eq!(
            imp_session.impersonated_by().unwrap(),
            admin.id,
            "impersonated_by should be the admin's user id"
        );
    }

    /// Verifies the bug fix: stop-impersonating creates a new admin session.
    #[tokio::test]
    async fn test_stop_impersonating_creates_admin_session() {
        let (ctx, admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Impersonate
        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let body = json_body(&resp);
        let imp_token = body["session"]["token"].as_str().unwrap().to_string();

        // Stop impersonating using the impersonation session token
        let req = make_request(
            HttpMethod::Post,
            "/admin/stop-impersonating",
            &imp_token,
            None,
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);

        // Should return admin user and a new session
        assert_eq!(body["user"]["email"], "admin@example.com");
        assert!(body["session"]["token"].is_string());

        // The new session token should be for the admin
        let new_token = body["session"]["token"].as_str().unwrap();
        let new_session = ctx.database.get_session(new_token).await.unwrap().unwrap();
        assert_eq!(new_session.user_id, admin.id);
        assert!(
            new_session.impersonated_by.is_none(),
            "new admin session should not be an impersonation session"
        );

        // The response should include a Set-Cookie header
        assert!(resp.headers.contains_key("Set-Cookie"));

        // The old impersonation session should be deleted
        let old_session = ctx.database.get_session(&imp_token).await.unwrap();
        assert!(old_session.is_none());
    }

    #[tokio::test]
    async fn test_stop_impersonating_non_impersonation_session_rejected() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // Try to stop impersonating with a normal admin session (not impersonation)
        let req = make_request(
            HttpMethod::Post,
            "/admin/stop-impersonating",
            &admin_session.token,
            None,
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cannot_impersonate_self() {
        let (ctx, admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": admin.id,
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_impersonate_nonexistent_user_rejected() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "nonexistent-user-id",
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_impersonate_response_has_set_cookie() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert!(
            resp.headers.contains_key("Set-Cookie"),
            "impersonate response should set a session cookie"
        );
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_revoke_user_sessions() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/revoke-user-sessions",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["success"], true);

        // Verify sessions are actually deleted
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_specific_session() {
        let (ctx, _admin, admin_session, _user, user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/revoke-user-session",
            &admin_session.token,
            Some(serde_json::json!({
                "sessionToken": user_session.token,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["success"], true);

        // Verify specific session is deleted
        let session = ctx.database.get_session(&user_session.token).await.unwrap();
        assert!(session.is_none());
    }

    // -----------------------------------------------------------------------
    // Remove user
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_remove_user() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/remove-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["success"], true);

        // Verify user is deleted
        let deleted = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_cannot_remove_self() {
        let (ctx, admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/remove-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": admin.id,
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_user_cleans_up_sessions_and_accounts() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // First create a user with an account
        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "tobedeleted@example.com",
                "password": "securepassword123",
                "name": "To Be Deleted"
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let body = json_body(&resp);
        let user_id = body["user"]["id"].as_str().unwrap().to_string();

        // Verify user has an account
        let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);

        // Remove the user
        let req = make_request(
            HttpMethod::Post,
            "/admin/remove-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user_id,
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);

        // Verify user is deleted
        let deleted = ctx.database.get_user_by_id(&user_id).await.unwrap();
        assert!(deleted.is_none());

        // Verify accounts are cleaned up
        let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
        assert!(accounts.is_empty());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_user() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/remove-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "nonexistent-user-id",
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Set user password
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_set_user_password() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // First create a user with a credential account
        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "pwuser@example.com",
                "password": "oldpassword123",
                "name": "PW User"
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let body = json_body(&resp);
        let user_id = body["user"]["id"].as_str().unwrap().to_string();

        // Set new password
        let req = make_request(
            HttpMethod::Post,
            "/admin/set-user-password",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user_id,
                "newPassword": "newpassword456"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["status"], true);
    }

    /// Verifies the bug fix: set-user-password also updates the credential account password.
    #[tokio::test]
    async fn test_set_user_password_updates_account() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        // First create a user with a credential account
        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "pwuser@example.com",
                "password": "oldpassword123",
                "name": "PW User"
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let body = json_body(&resp);
        let user_id = body["user"]["id"].as_str().unwrap().to_string();

        // Get the old password hash from the credential account
        let accounts_before = ctx.database.get_user_accounts(&user_id).await.unwrap();
        let old_password = accounts_before[0].password().unwrap().to_string();

        // Set new password
        let req = make_request(
            HttpMethod::Post,
            "/admin/set-user-password",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user_id,
                "newPassword": "newpassword456"
            })),
        );
        plugin.on_request(&req, &ctx).await.unwrap().unwrap();

        // Verify the credential account password was updated
        let accounts_after = ctx.database.get_user_accounts(&user_id).await.unwrap();
        let new_password = accounts_after[0].password().unwrap().to_string();
        assert_ne!(
            old_password, new_password,
            "credential account password should be updated"
        );
    }

    #[tokio::test]
    async fn test_set_user_password_too_short() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-user-password",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "newPassword": "ab" // too short
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_password_nonexistent_user() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-user-password",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "nonexistent-user-id",
                "newPassword": "newpassword456"
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Permissions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_has_permission_admin() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/has-permission",
            &admin_session.token,
            Some(serde_json::json!({
                "permissions": { "users": ["read", "write"] }
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["success"], true);
    }

    #[tokio::test]
    async fn test_has_permission_non_admin() {
        let (ctx, _admin, _admin_session, _user, user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/has-permission",
            &user_session.token,
            Some(serde_json::json!({
                "permissions": { "users": ["read", "write"] }
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["success"], false);
        assert!(body["error"].is_string());
    }

    // -----------------------------------------------------------------------
    // Set role edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_set_role_nonexistent_user() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-role",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "nonexistent-user-id",
                "role": "admin"
            })),
        );

        let result = plugin.on_request(&req, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_role_persists_in_database() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/set-role",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "role": "editor"
            })),
        );

        plugin.on_request(&req, &ctx).await.unwrap().unwrap();

        // Verify role is persisted in the database
        let updated = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.role.as_deref(), Some("editor"));
    }

    // -----------------------------------------------------------------------
    // Plugin name / routes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_plugin_name() {
        let plugin = AdminPlugin::new();
        assert_eq!(
            <AdminPlugin as AuthPlugin<MemoryDatabaseAdapter>>::name(&plugin),
            "admin"
        );
    }

    #[tokio::test]
    async fn test_plugin_routes_count() {
        let plugin = AdminPlugin::new();
        let routes = <AdminPlugin as AuthPlugin<MemoryDatabaseAdapter>>::routes(&plugin);
        assert_eq!(routes.len(), 13, "admin plugin should register 13 routes");
    }
}
