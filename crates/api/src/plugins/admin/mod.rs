use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::AuthUser;
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use better_auth_core::utils::cookie_utils::create_session_cookie;

#[cfg(feature = "axum")]
use super::StatusResponse;

pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

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
#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "AdminPlugin")]
pub struct AdminConfig {
    /// The role required to access admin endpoints (default: `"admin"`).
    #[config(default = "admin".to_string())]
    pub admin_role: String,
    /// Default role assigned to newly created users (default: `"user"`).
    #[config(default = "user".to_string())]
    pub default_user_role: String,
    /// Whether to allow banning other admins (default: `false`).
    #[config(default = false)]
    pub allow_ban_admin: bool,
    /// Default number of users returned in list-users (default: 100).
    #[config(default = 100)]
    pub default_page_limit: usize,
    /// Maximum number of users returned in list-users (default: 500).
    #[config(default = 500)]
    pub max_page_limit: usize,
}

// ---------------------------------------------------------------------------
// Plugin trait implementation
// ---------------------------------------------------------------------------

better_auth_core::impl_auth_plugin! {
    AdminPlugin, "admin";
    routes {
        post "/admin/set-role" => handle_set_role, "admin_set_role";
        post "/admin/create-user" => handle_create_user, "admin_create_user";
        get  "/admin/list-users" => handle_list_users, "admin_list_users";
        post "/admin/list-user-sessions" => handle_list_user_sessions, "admin_list_user_sessions";
        post "/admin/ban-user" => handle_ban_user, "admin_ban_user";
        post "/admin/unban-user" => handle_unban_user, "admin_unban_user";
        post "/admin/impersonate-user" => handle_impersonate_user, "admin_impersonate_user";
        post "/admin/stop-impersonating" => handle_stop_impersonating, "admin_stop_impersonating";
        post "/admin/revoke-user-session" => handle_revoke_user_session, "admin_revoke_user_session";
        post "/admin/revoke-user-sessions" => handle_revoke_user_sessions, "admin_revoke_user_sessions";
        post "/admin/remove-user" => handle_remove_user, "admin_remove_user";
        post "/admin/set-user-password" => handle_set_user_password, "admin_set_user_password";
        post "/admin/has-permission" => handle_has_permission, "admin_has_permission";
    }
}

// ---------------------------------------------------------------------------
// Handler implementations (old -- delegate to core)
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
        let session_manager = ctx.session_manager();
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
    use better_auth_core::entity::AuthSession;
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
