use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute, ListUsersParams, SessionManager};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateUser, HttpMethod, UpdateUser};

// ── Config ──────────────────────────────────────────────────────────────────

/// Admin plugin for user management operations.
pub struct AdminPlugin {
    config: AdminConfig,
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// The role string that identifies an admin user.
    pub admin_role: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            admin_role: "admin".to_string(),
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
}

impl Default for AdminPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
#[allow(dead_code)]
struct CreateUserRequest {
    #[validate(email)]
    email: String,
    #[validate(length(min = 1))]
    password: String,
    #[validate(length(min = 1))]
    name: String,
    role: Option<String>,
    data: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct RemoveUserRequest {
    #[validate(length(min = 1))]
    #[serde(rename = "userId")]
    user_id: String,
}

#[derive(Debug, Deserialize, Validate)]
struct SetUserPasswordRequest {
    #[validate(length(min = 1))]
    #[serde(rename = "userId")]
    user_id: String,
    #[validate(length(min = 1))]
    #[serde(rename = "newPassword")]
    new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
struct SetRoleRequest {
    #[validate(length(min = 1))]
    #[serde(rename = "userId")]
    user_id: String,
    #[validate(length(min = 1))]
    role: String,
}

#[derive(Debug, Deserialize)]
struct HasPermissionRequest {
    permissions: serde_json::Value,
    #[serde(default)]
    permission: Option<serde_json::Value>,
}

// Response types (typed structs, not json!)

#[derive(Debug, Serialize)]
struct ListUsersResponse<U: Serialize> {
    users: Vec<U>,
    total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<usize>,
}

#[derive(Debug, Serialize)]
struct UserResponse<U: Serialize> {
    user: U,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Debug, Serialize)]
struct StatusBoolResponse {
    status: bool,
}

#[derive(Debug, Serialize)]
struct HasPermissionResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ── Plugin trait impl ───────────────────────────────────────────────────────

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for AdminPlugin {
    fn name(&self) -> &'static str {
        "admin"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/admin/list-users", "admin_list_users"),
            AuthRoute::post("/admin/create-user", "admin_create_user"),
            AuthRoute::post("/admin/remove-user", "admin_remove_user"),
            AuthRoute::post("/admin/set-user-password", "admin_set_user_password"),
            AuthRoute::post("/admin/set-role", "admin_set_role"),
            AuthRoute::post("/admin/has-permission", "admin_has_permission"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        let path = req.path().split('?').next().unwrap_or(req.path());
        match (req.method(), path) {
            (HttpMethod::Get, "/admin/list-users") => {
                Ok(Some(self.handle_list_users(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/create-user") => {
                Ok(Some(self.handle_create_user(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/remove-user") => {
                Ok(Some(self.handle_remove_user(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/set-user-password") => {
                Ok(Some(self.handle_set_user_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/set-role") => {
                Ok(Some(self.handle_set_role(req, ctx).await?))
            }
            (HttpMethod::Post, "/admin/has-permission") => {
                Ok(Some(self.handle_has_permission(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

// ── Handler implementations ─────────────────────────────────────────────────

impl AdminPlugin {
    /// Authenticate the request and verify the caller has the admin role.
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
            .ok_or(AuthError::Unauthenticated)?;

        // Check admin role
        let role = user.role().unwrap_or("");
        if role != self.config.admin_role {
            return Err(AuthError::forbidden(
                "You are not allowed to access this resource",
            ));
        }

        Ok((user, session))
    }

    // ── GET /admin/list-users ───────────────────────────────────────────

    async fn handle_list_users<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.require_admin(req, ctx).await?;

        // Parse query parameters from the URL (GET request uses query params)
        let params = ListUsersParams {
            limit: self.extract_query_param(req, "limit"),
            offset: self.extract_query_param(req, "offset"),
            search_field: self.extract_query_param_str(req, "searchField"),
            search_value: self.extract_query_param_str(req, "searchValue"),
            search_operator: self.extract_query_param_str(req, "searchOperator"),
            sort_by: self.extract_query_param_str(req, "sortBy"),
            sort_direction: self.extract_query_param_str(req, "sortDirection"),
            filter_field: self.extract_query_param_str(req, "filterField"),
            filter_value: self.extract_query_param_str(req, "filterValue"),
            filter_operator: self.extract_query_param_str(req, "filterOperator"),
        };

        let limit = params.limit;
        let offset = params.offset;
        let (users, total) = ctx.database.list_users(params).await?;

        let response = ListUsersResponse {
            users,
            total,
            limit,
            offset,
        };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── POST /admin/create-user ─────────────────────────────────────────

    async fn handle_create_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.require_admin(req, ctx).await?;

        let body: CreateUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Check if user already exists
        if ctx.database.get_user_by_email(&body.email).await?.is_some() {
            return Err(AuthError::conflict("A user with this email already exists"));
        }

        // Hash password
        let password_hash = self.hash_password(&body.password)?;
        let metadata = serde_json::json!({
            "password_hash": password_hash,
        });

        let mut create_user = CreateUser::new()
            .with_email(&body.email)
            .with_name(&body.name);

        if let Some(role) = &body.role {
            create_user = create_user.with_role(role);
        }
        create_user.metadata = Some(metadata);

        let user = ctx.database.create_user(create_user).await?;

        let response = UserResponse { user };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── POST /admin/remove-user ─────────────────────────────────────────

    async fn handle_remove_user<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.require_admin(req, ctx).await?;

        let body: RemoveUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Verify the user exists
        ctx.database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Delete user sessions first, then the user
        ctx.database.delete_user_sessions(&body.user_id).await?;
        ctx.database.delete_user(&body.user_id).await?;

        let response = SuccessResponse { success: true };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── POST /admin/set-user-password ───────────────────────────────────

    async fn handle_set_user_password<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.require_admin(req, ctx).await?;

        let body: SetUserPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Verify the user exists
        let user = ctx
            .database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Hash new password
        let password_hash = self.hash_password(&body.new_password)?;

        // Merge into existing metadata
        let mut metadata = user.metadata().clone();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "password_hash".to_string(),
                serde_json::Value::String(password_hash),
            );
        } else {
            metadata = serde_json::json!({ "password_hash": password_hash });
        }

        let update = UpdateUser {
            metadata: Some(metadata),
            ..Default::default()
        };
        ctx.database.update_user(&body.user_id, update).await?;

        let response = StatusBoolResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── POST /admin/set-role ────────────────────────────────────────────

    async fn handle_set_role<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.require_admin(req, ctx).await?;

        let body: SetRoleRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Verify the user exists
        ctx.database
            .get_user_by_id(&body.user_id)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        let update = UpdateUser {
            role: Some(body.role),
            ..Default::default()
        };
        let user = ctx.database.update_user(&body.user_id, update).await?;

        let response = UserResponse { user };
        Ok(AuthResponse::json(200, &response)?)
    }

    // ── POST /admin/has-permission ──────────────────────────────────────

    async fn handle_has_permission<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_admin(req, ctx).await?;

        let body: HasPermissionRequest = req
            .body_as_json()
            .map_err(|_| AuthError::bad_request("Invalid request body"))?;

        // Use `permissions` (preferred) or fall back to deprecated `permission`
        let permissions = if body.permissions.is_null() {
            body.permission.unwrap_or(serde_json::Value::Null)
        } else {
            body.permissions
        };

        // Simple permission check: admin role has all permissions
        let role = user.role().unwrap_or("");
        let has_permission = role == self.config.admin_role;

        if has_permission {
            let response = HasPermissionResponse {
                success: true,
                error: None,
            };
            Ok(AuthResponse::json(200, &response)?)
        } else {
            let response = HasPermissionResponse {
                success: false,
                error: Some(format!(
                    "User does not have the required permissions: {:?}",
                    permissions
                )),
            };
            Ok(AuthResponse::json(200, &response)?)
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;

        Ok(password_hash.to_string())
    }

    /// Extract a query parameter from the request path (e.g. `?limit=10`).
    fn extract_query_param(&self, req: &AuthRequest, key: &str) -> Option<usize> {
        self.extract_query_param_str(req, key)
            .and_then(|s| s.parse().ok())
    }

    /// Extract a string query parameter from the request path.
    fn extract_query_param_str(&self, req: &AuthRequest, key: &str) -> Option<String> {
        let path = req.path();
        let query_start = path.find('?')?;
        let query = &path[query_start + 1..];
        for pair in query.split('&') {
            let mut kv = pair.splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next())
                && k == key
            {
                return Some(v.to_string());
            }
        }
        None
    }
}
