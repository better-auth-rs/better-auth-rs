use better_auth_core::entity::AuthUser;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use better_auth_core::utils::cookie_utils::create_session_cookie;

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
    async fn require_admin(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<(UserView, SessionView)> {
        let (user, session) = ctx.require_session(req).await?;

        let user_role = user.role().unwrap_or("user");
        if user_role != self.config.admin_role {
            return Err(AuthError::forbidden(
                "You do not have permission to access this resource",
            ));
        }

        Ok((UserView::from(&user), SessionView::from(&session)))
    }

    async fn handle_set_role(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: SetRoleRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = set_role_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_create_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: CreateUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = create_user_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_users(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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

    async fn handle_list_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = list_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_ban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: BanUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = ban_user_core(&body, admin_user.id(), &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_unban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = unban_user_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_impersonate_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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

    async fn handle_stop_impersonating(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session_manager = ctx.session_manager();
        let token = session_manager
            .extract_session_token(req)
            .ok_or(AuthError::Unauthenticated)?;
        let session = session_manager
            .get_session(&token)
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        let session = SessionView::from(&session);
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

    async fn handle_revoke_user_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: RevokeSessionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = revoke_user_session_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_revoke_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = revoke_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_remove_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = remove_user_core(&body, admin_user.id(), ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_set_user_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (_admin_user, _admin_session) = self.require_admin(req, ctx).await?;
        let body: SetUserPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = set_user_password_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_has_permission(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let user = UserView::from(&user);
        let body: HasPermissionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = has_permission_core(&body, &user, &self.config)?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}
