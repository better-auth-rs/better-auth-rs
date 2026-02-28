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

use super::StatusResponse;

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
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

pub(crate) async fn set_role_core<DB: DatabaseAdapter>(
    body: &SetRoleRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<UserResponse<DB::User>> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let update = UpdateUser {
        role: Some(body.role.clone()),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(UserResponse { user: updated_user })
}

pub(crate) async fn create_user_core<DB: DatabaseAdapter>(
    body: &CreateUserRequest,
    config: &AdminConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<UserResponse<DB::User>> {
    if ctx.database.get_user_by_email(&body.email).await?.is_some() {
        return Err(AuthError::conflict("A user with this email already exists"));
    }

    if body.password.len() < ctx.config.password.min_length {
        return Err(AuthError::bad_request(format!(
            "Password must be at least {} characters long",
            ctx.config.password.min_length
        )));
    }

    let password_hash = better_auth_core::hash_password(None, &body.password).await?;

    let role = body
        .role
        .clone()
        .unwrap_or_else(|| config.default_user_role.clone());

    let metadata_value = body.data.clone().unwrap_or(serde_json::json!({}));
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

    Ok(UserResponse { user })
}

/// Query parameters for `list_users`.
#[derive(Debug, Deserialize)]
pub(crate) struct ListUsersQueryParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(rename = "searchField")]
    pub search_field: Option<String>,
    #[serde(rename = "searchValue")]
    pub search_value: Option<String>,
    #[serde(rename = "searchOperator")]
    pub search_operator: Option<String>,
    #[serde(rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    pub sort_direction: Option<String>,
    #[serde(rename = "filterField")]
    pub filter_field: Option<String>,
    #[serde(rename = "filterValue")]
    pub filter_value: Option<String>,
    #[serde(rename = "filterOperator")]
    pub filter_operator: Option<String>,
}

pub(crate) async fn list_users_core<DB: DatabaseAdapter>(
    query: &ListUsersQueryParams,
    config: &AdminConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<ListUsersResponse<DB::User>> {
    let limit = query
        .limit
        .unwrap_or(config.default_page_limit)
        .min(config.max_page_limit);
    let offset = query.offset.unwrap_or(0);

    let params = ListUsersParams {
        limit: Some(limit),
        offset: Some(offset),
        search_field: query.search_field.clone(),
        search_value: query.search_value.clone(),
        search_operator: query.search_operator.clone(),
        sort_by: query.sort_by.clone(),
        sort_direction: query.sort_direction.clone(),
        filter_field: query.filter_field.clone(),
        filter_value: query.filter_value.clone(),
        filter_operator: query.filter_operator.clone(),
    };

    let (users, total) = ctx.database.list_users(params).await?;
    Ok(ListUsersResponse {
        users,
        total,
        limit,
        offset,
    })
}

pub(crate) async fn list_user_sessions_core<DB: DatabaseAdapter>(
    body: &UserIdRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<ListSessionsResponse<DB::Session>> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let sessions = session_manager.list_user_sessions(&body.user_id).await?;
    Ok(ListSessionsResponse { sessions })
}

pub(crate) async fn ban_user_core<DB: DatabaseAdapter>(
    body: &BanUserRequest,
    admin_user_id: &str,
    config: &AdminConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<UserResponse<DB::User>> {
    if body.user_id == admin_user_id {
        return Err(AuthError::bad_request("You cannot ban yourself"));
    }

    let target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    if !config.allow_ban_admin && target.role().unwrap_or("user") == config.admin_role {
        return Err(AuthError::forbidden("Cannot ban an admin user"));
    }

    let ban_expires = body
        .ban_expires_in
        .and_then(Duration::try_seconds)
        .map(|d| Utc::now() + d);

    let update = UpdateUser {
        banned: Some(true),
        ban_reason: body.ban_reason.clone(),
        ban_expires,
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;

    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    session_manager
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(UserResponse { user: updated_user })
}

pub(crate) async fn unban_user_core<DB: DatabaseAdapter>(
    body: &UserIdRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<UserResponse<DB::User>> {
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

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(UserResponse { user: updated_user })
}

pub(crate) async fn impersonate_user_core<DB: DatabaseAdapter>(
    body: &UserIdRequest,
    admin_user_id: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    ctx: &AuthContext<DB>,
) -> AuthResult<(SessionUserResponse<DB::Session, DB::User>, String)> {
    if body.user_id == admin_user_id {
        return Err(AuthError::bad_request("Cannot impersonate yourself"));
    }

    let target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let expires_at = Utc::now() + ctx.config.session.expires_in;
    let create_session = CreateSession {
        user_id: target.id().to_string(),
        expires_at,
        ip_address: ip_address.map(|s| s.to_string()),
        user_agent: user_agent.map(|s| s.to_string()),
        impersonated_by: Some(admin_user_id.to_string()),
        active_organization_id: None,
    };

    let session = ctx.database.create_session(create_session).await?;
    let token = session.token().to_string();
    let response = SessionUserResponse {
        session,
        user: target,
    };

    Ok((response, token))
}

pub(crate) async fn stop_impersonating_core<DB: DatabaseAdapter>(
    session: &DB::Session,
    session_token: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    ctx: &AuthContext<DB>,
) -> AuthResult<(SessionUserResponse<DB::Session, DB::User>, String)> {
    let admin_id = session
        .impersonated_by()
        .ok_or_else(|| AuthError::bad_request("Current session is not an impersonation session"))?
        .to_string();

    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    session_manager.delete_session(session_token).await?;

    let admin_user = ctx
        .database
        .get_user_by_id(&admin_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let expires_at = Utc::now() + ctx.config.session.expires_in;
    let create_session = CreateSession {
        user_id: admin_id,
        expires_at,
        ip_address: ip_address.map(|s| s.to_string()),
        user_agent: user_agent.map(|s| s.to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };

    let admin_session = ctx.database.create_session(create_session).await?;
    let token = admin_session.token().to_string();
    let response = SessionUserResponse {
        session: admin_session,
        user: admin_user,
    };

    Ok((response, token))
}

pub(crate) async fn revoke_user_session_core<DB: DatabaseAdapter>(
    body: &RevokeSessionRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    session_manager.delete_session(&body.session_token).await?;
    Ok(SuccessResponse { success: true })
}

pub(crate) async fn revoke_user_sessions_core<DB: DatabaseAdapter>(
    body: &UserIdRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    session_manager
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(SuccessResponse { success: true })
}

pub(crate) async fn remove_user_core<DB: DatabaseAdapter>(
    body: &UserIdRequest,
    admin_user_id: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    if body.user_id == admin_user_id {
        return Err(AuthError::bad_request("You cannot remove yourself"));
    }

    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    ctx.database.delete_user_sessions(&body.user_id).await?;

    let accounts = ctx.database.get_user_accounts(&body.user_id).await?;
    for account in &accounts {
        ctx.database.delete_account(account.id()).await?;
    }

    ctx.database.delete_user(&body.user_id).await?;
    Ok(SuccessResponse { success: true })
}

pub(crate) async fn set_user_password_core<DB: DatabaseAdapter>(
    body: &SetUserPasswordRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    if body.new_password.len() < ctx.config.password.min_length {
        return Err(AuthError::bad_request(format!(
            "Password must be at least {} characters long",
            ctx.config.password.min_length
        )));
    }

    let user = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let password_hash = better_auth_core::hash_password(None, &body.new_password).await?;

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

    Ok(StatusResponse { status: true })
}

pub(crate) async fn has_permission_core<DB: DatabaseAdapter>(
    body: &HasPermissionRequest,
    user: &DB::User,
    config: &AdminConfig,
) -> AuthResult<PermissionResponse> {
    let _permissions = body.permissions.clone().or(body.permission.clone());

    let is_admin = user.role().unwrap_or("user") == config.admin_role;

    let (success, error) = if is_admin {
        (true, None)
    } else {
        (
            false,
            Some("User does not have the required permissions".to_string()),
        )
    };

    Ok(PermissionResponse { success, error })
}

// ---------------------------------------------------------------------------
// Handler implementations (old — delegate to core)
// ---------------------------------------------------------------------------

impl AdminPlugin {
    /// Authenticate the caller and verify they have the admin role.
    async fn require_admin<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<(DB::User, DB::Session)> {
        let (user, session) = ctx.require_session(req).await?;

        let user_role = user.role().unwrap_or("user");
        if user_role != self.config.admin_role {
            return Err(AuthError::forbidden(
                "You do not have permission to access this resource",
            ));
        }

        Ok((user, session))
    }

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
        let response = set_role_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = create_user_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_users<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let query = ListUsersQueryParams {
            limit: req.query.get("limit").and_then(|v| v.parse().ok()),
            offset: req.query.get("offset").and_then(|v| v.parse().ok()),
            search_field: req.query.get("searchField").cloned(),
            search_value: req.query.get("searchValue").cloned(),
            search_operator: req.query.get("searchOperator").cloned(),
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
            filter_field: req.query.get("filterField").cloned(),
            filter_value: req.query.get("filterValue").cloned(),
            filter_operator: req.query.get("filterOperator").cloned(),
        };
        let response = list_users_core(&query, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = list_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = ban_user_core(&body, admin_user.id(), &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = unban_user_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let (response, token) = impersonate_user_core(
            &body,
            admin_user.id(),
            req.headers.get("x-forwarded-for").map(|s| s.as_str()),
            req.headers.get("user-agent").map(|s| s.as_str()),
            ctx,
        )
        .await?;
        let cookie_header = create_session_cookie(&token, &ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

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
        let (response, new_token) = stop_impersonating_core(
            &session,
            &token,
            req.headers.get("x-forwarded-for").map(|s| s.as_str()),
            req.headers.get("user-agent").map(|s| s.as_str()),
            ctx,
        )
        .await?;
        let cookie_header = create_session_cookie(&new_token, &ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

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
        let response = revoke_user_session_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = revoke_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = remove_user_core(&body, admin_user.id(), ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = set_user_password_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

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
        let response = has_permission_core::<DB>(&body, &user, &self.config).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}

// ---------------------------------------------------------------------------
// Axum integration
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, Query, State};
    use axum::http::header;
    use better_auth_core::{AdminRole, AdminSession, AuthState, CurrentSession, ValidatedJson};

    #[derive(Clone)]
    struct PluginState {
        config: AdminConfig,
    }

    async fn handle_set_role<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<SetRoleRequest>,
    ) -> Result<Json<UserResponse<DB::User>>, AuthError> {
        let ctx = state.to_context();
        let response = set_role_core(&body, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_create_user<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<CreateUserRequest>,
    ) -> Result<Json<UserResponse<DB::User>>, AuthError> {
        let ctx = state.to_context();
        let response = create_user_core(&body, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_list_users<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        AdminSession { .. }: AdminSession<DB>,
        Query(query): Query<ListUsersQueryParams>,
    ) -> Result<Json<ListUsersResponse<DB::User>>, AuthError> {
        let ctx = state.to_context();
        let response = list_users_core(&query, &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_list_user_sessions<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<UserIdRequest>,
    ) -> Result<Json<ListSessionsResponse<DB::Session>>, AuthError> {
        let ctx = state.to_context();
        let response = list_user_sessions_core(&body, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_ban_user<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        AdminSession { user, .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<BanUserRequest>,
    ) -> Result<Json<UserResponse<DB::User>>, AuthError> {
        let ctx = state.to_context();
        let response = ban_user_core(&body, user.id(), &ps.config, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_unban_user<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<UserIdRequest>,
    ) -> Result<Json<UserResponse<DB::User>>, AuthError> {
        let ctx = state.to_context();
        let response = unban_user_core(&body, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_impersonate_user<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { user, .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<UserIdRequest>,
    ) -> Result<
        (
            [(header::HeaderName, String); 1],
            Json<SessionUserResponse<DB::Session, DB::User>>,
        ),
        AuthError,
    > {
        let ctx = state.to_context();
        let (response, token) = impersonate_user_core(&body, user.id(), None, None, &ctx).await?;
        let cookie = state.session_cookie(&token);
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    async fn handle_stop_impersonating<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { session, .. }: CurrentSession<DB>,
    ) -> Result<
        (
            [(header::HeaderName, String); 1],
            Json<SessionUserResponse<DB::Session, DB::User>>,
        ),
        AuthError,
    > {
        let ctx = state.to_context();
        let token = session.token().to_string();
        let (response, new_token) =
            stop_impersonating_core(&session, &token, None, None, &ctx).await?;
        let cookie = state.session_cookie(&new_token);
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    async fn handle_revoke_user_session<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<RevokeSessionRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let response = revoke_user_session_core(&body, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_revoke_user_sessions<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<UserIdRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let response = revoke_user_sessions_core(&body, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_remove_user<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { user, .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<UserIdRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let response = remove_user_core(&body, user.id(), &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_set_user_password<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        AdminSession { .. }: AdminSession<DB>,
        ValidatedJson(body): ValidatedJson<SetUserPasswordRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let response = set_user_password_core(&body, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_has_permission<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<HasPermissionRequest>,
    ) -> Result<Json<PermissionResponse>, AuthError> {
        let response = has_permission_core::<DB>(&body, &user, &ps.config).await?;
        Ok(Json(response))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for AdminPlugin {
        fn name(&self) -> &'static str {
            "admin"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });
            axum::Router::new()
                .route("/admin/set-role", post(handle_set_role::<DB>))
                .route("/admin/create-user", post(handle_create_user::<DB>))
                .route("/admin/list-users", get(handle_list_users::<DB>))
                .route(
                    "/admin/list-user-sessions",
                    post(handle_list_user_sessions::<DB>),
                )
                .route("/admin/ban-user", post(handle_ban_user::<DB>))
                .route("/admin/unban-user", post(handle_unban_user::<DB>))
                .route(
                    "/admin/impersonate-user",
                    post(handle_impersonate_user::<DB>),
                )
                .route(
                    "/admin/stop-impersonating",
                    post(handle_stop_impersonating::<DB>),
                )
                .route(
                    "/admin/revoke-user-session",
                    post(handle_revoke_user_session::<DB>),
                )
                .route(
                    "/admin/revoke-user-sessions",
                    post(handle_revoke_user_sessions::<DB>),
                )
                .route("/admin/remove-user", post(handle_remove_user::<DB>))
                .route(
                    "/admin/set-user-password",
                    post(handle_set_user_password::<DB>),
                )
                .route("/admin/has-permission", post(handle_has_permission::<DB>))
                .layer(Extension(plugin_state))
                .layer(Extension(AdminRole(self.config.admin_role.clone())))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
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
        let ctx = test_helpers::create_test_context();

        // Create admin user
        let admin = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("admin@example.com")
                .with_name("Admin")
                .with_role("admin"),
        )
        .await;
        let admin_session =
            test_helpers::create_session(&ctx, admin.id.clone(), Duration::hours(24)).await;

        // Create regular user
        let user = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("user@example.com")
                .with_name("Regular User")
                .with_role("user"),
        )
        .await;
        let user_session =
            test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(24)).await;

        (ctx, admin, admin_session, user, user_session)
    }

    fn make_request(
        method: HttpMethod,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        test_helpers::create_auth_json_request_no_query(method, path, Some(token), body)
    }

    fn make_request_with_query(
        method: HttpMethod,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        test_helpers::create_auth_json_request(method, path, Some(token), body, query)
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
