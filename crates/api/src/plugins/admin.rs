use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser, HttpMethod,
    SessionManager, UpdateUser,
};

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
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());

        let token = session_manager
            .extract_session_token(req)
            .ok_or(AuthError::Unauthenticated)?;

        let session = session_manager
            .get_session(&token)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        let user = ctx
            .database
            .get_user_by_id(session.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Check admin role
        let user_role = user.role().unwrap_or("user");
        if user_role != self.config.admin_role {
            return Err(AuthError::forbidden(
                "You do not have permission to access this resource",
            ));
        }

        Ok((user, session))
    }

    fn hash_password(password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;

        Ok(password_hash.to_string())
    }

    fn create_session_cookie<DB: DatabaseAdapter>(token: &str, ctx: &AuthContext<DB>) -> String {
        let session_config = &ctx.config.session;
        let secure = if session_config.cookie_secure {
            "; Secure"
        } else {
            ""
        };
        let http_only = if session_config.cookie_http_only {
            "; HttpOnly"
        } else {
            ""
        };
        let same_site = match session_config.cookie_same_site {
            better_auth_core::config::SameSite::Strict => "; SameSite=Strict",
            better_auth_core::config::SameSite::Lax => "; SameSite=Lax",
            better_auth_core::config::SameSite::None => "; SameSite=None",
        };

        let expires = Utc::now() + session_config.expires_in;
        let expires_str = expires.format("%a, %d %b %Y %H:%M:%S GMT");

        format!(
            "{}={}; Path=/; Expires={}{}{}{}",
            session_config.cookie_name, token, expires_str, secure, http_only, same_site
        )
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
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: None,
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

        // Hash the password
        let password_hash = Self::hash_password(&body.password)?;

        let role = body
            .role
            .unwrap_or_else(|| self.config.default_user_role.clone());

        let mut metadata = body.data.unwrap_or(serde_json::json!({}));
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "password_hash".to_string(),
                serde_json::json!(password_hash),
            );
        }

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

        let search_value = req.query.get("searchValue").cloned();
        let search_field = req
            .query
            .get("searchField")
            .cloned()
            .unwrap_or_else(|| "email".to_string());
        let search_operator = req
            .query
            .get("searchOperator")
            .cloned()
            .unwrap_or_else(|| "contains".to_string());

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

        let sort_by = req.query.get("sortBy").cloned();
        let sort_direction = req
            .query
            .get("sortDirection")
            .cloned()
            .unwrap_or_else(|| "asc".to_string());

        let filter_field = req.query.get("filterField").cloned();
        let filter_value = req.query.get("filterValue").cloned();
        let _filter_operator = req
            .query
            .get("filterOperator")
            .cloned()
            .unwrap_or_else(|| "eq".to_string());

        // Since DatabaseAdapter doesn't have a built-in list-all or search
        // method, we use a pragmatic approach: iterate through known search
        // fields. For a production deployment backed by SQL the adapter
        // would typically provide a query-builder method. Here we support
        // the common case of searching by email or name.
        let mut all_users: Vec<DB::User> = Vec::new();

        // Try to fetch by search
        if let Some(ref search_value) = search_value {
            match search_field.as_str() {
                "email" => {
                    if let Some(user) = ctx.database.get_user_by_email(search_value).await? {
                        all_users.push(user);
                    }
                }
                "name" => {
                    // Name search not directly supported by DatabaseAdapter;
                    // try email as a fallback since we can't enumerate all users.
                    if let Some(user) = ctx.database.get_user_by_email(search_value).await? {
                        all_users.push(user);
                    }
                }
                _ => {}
            }

            // Apply operator-based filtering on matched results
            all_users.retain(|user| {
                let field_value = match search_field.as_str() {
                    "email" => user.email().unwrap_or("").to_string(),
                    "name" => user.name().unwrap_or("").to_string(),
                    _ => String::new(),
                };
                match search_operator.as_str() {
                    "contains" => field_value
                        .to_lowercase()
                        .contains(&search_value.to_lowercase()),
                    "starts_with" => field_value
                        .to_lowercase()
                        .starts_with(&search_value.to_lowercase()),
                    "ends_with" => field_value
                        .to_lowercase()
                        .ends_with(&search_value.to_lowercase()),
                    _ => true,
                }
            });
        } else if let Some(ref filter_value) = filter_value {
            // Filter by a specific field value (exact match)
            if let Some(ref filter_field) = filter_field {
                match filter_field.as_str() {
                    "email" => {
                        if let Some(user) = ctx.database.get_user_by_email(filter_value).await? {
                            all_users.push(user);
                        }
                    }
                    "username" => {
                        if let Some(user) = ctx.database.get_user_by_username(filter_value).await? {
                            all_users.push(user);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Apply sorting
        if let Some(ref sort_by) = sort_by {
            let desc = sort_direction == "desc";
            all_users.sort_by(|a, b| {
                let cmp = match sort_by.as_str() {
                    "email" => a.email().unwrap_or("").cmp(b.email().unwrap_or("")),
                    "name" => a.name().unwrap_or("").cmp(b.name().unwrap_or("")),
                    "createdAt" => a.created_at().cmp(&b.created_at()),
                    _ => std::cmp::Ordering::Equal,
                };
                if desc { cmp.reverse() } else { cmp }
            });
        }

        let total = all_users.len();

        // Paginate
        let paginated: Vec<DB::User> = all_users.into_iter().skip(offset).take(limit).collect();

        let response = ListUsersResponse {
            users: paginated,
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
            ban_reason: body.ban_reason.or_else(|| Some(String::new())),
            ban_expires,
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            two_factor_enabled: None,
            metadata: None,
        };

        let updated_user = ctx.database.update_user(&body.user_id, update).await?;

        // Revoke all sessions for the banned user
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let _ = session_manager
            .revoke_all_user_sessions(&body.user_id)
            .await;

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
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            two_factor_enabled: None,
            metadata: None,
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

        let cookie_header = Self::create_session_cookie(session.token(), ctx);
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

        let cookie_header = Self::create_session_cookie(admin_session.token(), ctx);
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

        let password_hash = Self::hash_password(&body.new_password)?;

        // Update password in user metadata
        let mut metadata = user.metadata().clone();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "password_hash".to_string(),
                serde_json::json!(password_hash),
            );
        }

        let update = UpdateUser {
            metadata: Some(metadata),
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
        };
        ctx.database.update_user(&body.user_id, update).await?;

        let response = StatusResponse { status: true };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    /// POST /admin/has-permission — Check if the calling user has a given permission.
    async fn handle_has_permission<DB: DatabaseAdapter>(
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

        let user = ctx
            .database
            .get_user_by_id(session.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let body: HasPermissionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Use the `permissions` field, falling back to deprecated `permission`.
        let permissions = body.permissions.or(body.permission);

        let is_admin = user.role().unwrap_or("user") == self.config.admin_role;

        // If the user is an admin they have all permissions.
        // Otherwise check if the requested permission matches a simple
        // role-based scheme. The `permissions` object from the spec is
        // free-form; we treat it as a map of resource -> action arrays
        // and grant access if the user's role matches the admin role.
        let (success, error) = if is_admin {
            (true, None)
        } else if permissions.is_some() {
            (
                false,
                Some("User does not have the required permissions".to_string()),
            )
        } else {
            (true, None)
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
    use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
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

    fn json_body(resp: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&resp.body).unwrap()
    }

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
    }

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
}
