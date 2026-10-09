use std::collections::HashMap;

use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_like_cookie, related_cookie_name,
};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult};

pub mod access;
mod banned_message;
mod native;
mod request;
pub use banned_message::{BannedUserMessage, BannedUserMessageFuture};
pub use native::AdminApi;
pub use types::{
    CreateUserRequest as CreateAdminUser, RoleInput as AdminRole, UserResponse as AdminUserResponse,
};
pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use crate::plugins::helpers::{delete_session_cookies, get_cookie};
use access::{has_permission, is_admin_role, is_admin_user_id};
use handlers::*;
use types::*;

const MESSAGE_CHANGE_ROLE: &str = "You are not allowed to change users role";
const MESSAGE_CREATE_USERS: &str = "You are not allowed to create users";
const MESSAGE_LIST_USERS: &str = "You are not allowed to list users";
const MESSAGE_LIST_USER_SESSIONS: &str = "You are not allowed to list users sessions";
const MESSAGE_BAN_USERS: &str = "You are not allowed to ban users";
const MESSAGE_IMPERSONATE_USERS: &str = "You are not allowed to impersonate users";
const MESSAGE_REVOKE_USER_SESSIONS: &str = "You are not allowed to revoke users sessions";
const MESSAGE_DELETE_USERS: &str = "You are not allowed to delete users";
const MESSAGE_SET_USER_PASSWORD: &str = "You are not allowed to set users password";
const MESSAGE_GET_USER: &str = "You are not allowed to get user";
const MESSAGE_UPDATE_USERS: &str = "You are not allowed to update users";

/// Admin plugin for user management operations.
pub struct AdminPlugin {
    config: AdminConfig,
}

/// Configuration for the admin plugin.
#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "AdminPlugin")]
pub struct AdminConfig {
    /// Default role assigned to new users and role-less permission checks.
    #[config(default = "user".to_string())]
    pub default_role: String,
    /// Roles treated as "admin" for target-admin checks such as impersonation.
    #[config(default = None)]
    pub admin_roles: Option<Vec<String>>,
    /// Users that always bypass admin permission checks.
    #[config(default = None)]
    pub admin_user_ids: Option<Vec<String>>,
    /// Custom role definitions. When provided, these replace the built-in
    /// `admin` and `user` role permissions.
    #[config(default = None)]
    pub roles: Option<HashMap<String, access::RolePermissions>>,
    /// Default reason applied when banning a user without an explicit reason.
    #[config(default = None)]
    pub default_ban_reason: Option<String>,
    /// Default ban duration in fractional seconds when the request has no nonzero duration.
    #[config(default = None)]
    pub default_ban_expires_in: Option<f64>,
    /// Custom impersonation session duration in fractional seconds; zero uses one hour.
    #[config(default = None)]
    pub impersonation_session_duration: Option<f64>,
    /// Message surfaced to banned users.
    #[config(default = BannedUserMessage::default(), skip)]
    pub banned_user_message: BannedUserMessage,
    /// Whether other admin users may be impersonated.
    #[config(default = false)]
    pub allow_impersonating_admins: bool,
}

better_auth_core::impl_auth_plugin! {
    AdminPlugin, "admin";
    routes {
        post "/admin/set-role" => handle_set_role, "setUserRole", body = request::validate, require_headers = true;
        get  "/admin/get-user" => handle_get_user, "getUser", query = crate::plugins::query_input::get_user;
        post "/admin/create-user" => handle_create_user, "createUser", body = request::validate;
        post "/admin/update-user" => handle_update_user, "adminUpdateUser", body = request::validate;
        get  "/admin/list-users" => handle_list_users, "listUsers", query = crate::plugins::query_input::list_users;
        post "/admin/list-user-sessions" => handle_list_user_sessions, "adminListUserSessions", body = request::validate;
        post "/admin/ban-user" => handle_ban_user, "banUser", body = request::validate;
        post "/admin/unban-user" => handle_unban_user, "unbanUser", body = request::validate;
        post "/admin/impersonate-user" => handle_impersonate_user, "impersonateUser", body = request::validate;
        post "/admin/stop-impersonating" => handle_stop_impersonating, "stopImpersonating", require_headers = true;
        post "/admin/revoke-user-session" => handle_revoke_user_session, "revokeUserSession", body = request::validate;
        post "/admin/revoke-user-sessions" => handle_revoke_user_sessions, "revokeUserSessions", body = request::validate;
        post "/admin/remove-user" => handle_remove_user, "removeUser", body = request::validate;
        post "/admin/set-user-password" => handle_set_user_password, "setUserPassword", body = request::validate;
        post "/admin/has-permission" => handle_has_permission, "userHasPermission", body = request::validate;
    }
    extra {
        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> better_auth_core::AuthResult<()> {
            self.config.validate()?;
            S::User::require_plugin_fields("admin", &["role", "banned", "ban_reason", "ban_expires"])?;
            S::Session::require_plugin_fields("admin", &["impersonated_by"])?;
            ctx.register_native_user_fields("admin.enabled");
            ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));
            ctx.set_metadata(
                "admin.default_role",
                serde_json::Value::String(self.config.default_role.clone()),
            );
            ctx.extensions.insert(self.config.banned_user_message.clone());
            ctx.extensions.insert(self.config.clone());
            Ok(())
        }
    }
}

impl AdminPlugin {
    /// Set a fixed or asynchronous message for rejected session creation.
    pub fn banned_user_message(mut self, message: impl Into<BannedUserMessage>) -> Self {
        self.config.banned_user_message = message.into();
        self
    }

    async fn require_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<(UserView, SessionView)> {
        ctx.require_authoritative_session(req)
            .await
            .map_err(|error| match error {
                AuthError::Unauthenticated => AuthResponse::new(401).into(),
                error => error,
            })
    }

    async fn optional_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<(UserView, SessionView)>> {
        let data = ctx
            .session_manager()
            .resolve(req, better_auth_core::session::SessionRead::Authoritative)
            .await?
            .data;
        if data.is_none() && (req.endpoint_headers().is_some() || req.original_request().is_some())
        {
            return Err(AuthResponse::new(401).into());
        }
        Ok(data.map(|data| (data.user, data.session)))
    }

    fn authorize(
        &self,
        user: &UserView,
        resource: &str,
        action: &str,
        message: &str,
    ) -> AuthResult<()> {
        let permissions = HashMap::from([(resource.to_string(), vec![action.to_string()])]);
        if has_permission(
            user.id.as_str(),
            &user.role.field_value(),
            &self.config,
            &permissions,
        )? {
            Ok(())
        } else {
            Err(AuthError::forbidden(message))
        }
    }

    async fn handle_set_role(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "set-role", MESSAGE_CHANGE_ROLE)?;
        let body: SetRoleRequest = request::read(req)?;
        let response = set_role_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_get_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "get", MESSAGE_GET_USER)?;
        let query = GetUserQuery {
            id: req
                .query_string("id")?
                .map(str::to_owned)
                .unwrap_or_default(),
        };
        let response = get_user_core(&query, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_create_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: CreateUserRequest = request::read(req)?;
        let session = self.optional_session(req, ctx).await?;
        if let Some((user, _)) = &session {
            self.authorize(user, "user", "create", MESSAGE_CREATE_USERS)?;
        }
        let response = create_user_core(&body, Some(req), session, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "update", MESSAGE_UPDATE_USERS)?;
        let body: AdminUpdateUserRequest = request::read(req)?;
        let response = update_user_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_users(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "list", MESSAGE_LIST_USERS)?;
        let query: ListUsersQueryParams = crate::plugins::query_input::parse(&req.query)?;
        // The upstream admin endpoint catches list/count/projection failures.
        let response = list_users_core(&query, ctx)
            .await
            .unwrap_or_else(|_| ListUsersResponse {
                users: Vec::new(),
                total: 0,
                limit: None,
                offset: None,
            });
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "session", "list", MESSAGE_LIST_USER_SESSIONS)?;
        let body: UserIdRequest = request::read(req)?;
        let response = list_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_ban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "ban", MESSAGE_BAN_USERS)?;
        let body: BanUserRequest = request::read(req)?;
        let response = ban_user_core(&body, user.id.typed()?.as_str(), &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_unban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "ban", MESSAGE_BAN_USERS)?;
        let body: UserIdRequest = request::read(req)?;
        let response = unban_user_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_impersonate_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "impersonate", MESSAGE_IMPERSONATE_USERS)?;
        let body: UserIdRequest = request::read(req)?;
        let (response, data) = impersonate_user_core(
            &body,
            &user,
            ctx.config.advanced.ip_address.resolve(req).as_deref(),
            req.headers.get("user-agent").map(|value| value.as_str()),
            &self.config,
            ctx,
        )
        .await?;
        let dont_remember = ctx.session_manager().dont_remember(req);
        let admin_cookie = create_admin_session_cookie_value(
            ctx.config.signing_secret(),
            &AdminSessionCookiePayload {
                session_token: session.token.display_string()?,
                dont_remember,
            },
            ctx.config.session.expires_in(),
        )?;
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");

        delete_session_cookies(req, &ctx.config, false, None)?;
        req.append_response_header(
            "Set-Cookie",
            create_session_like_cookie(
                &admin_cookie_name,
                &admin_cookie,
                Some(ctx.config.session.expires_in().as_seconds_f64()),
                &ctx.config,
            )?,
        )?;
        ctx.session_manager()
            .set_session_cookie(req, data, Some(true))
            .await?;
        let auth_response = AuthResponse::json(200, &response)?;
        Ok(auth_response)
    }

    async fn handle_stop_impersonating(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session_manager = ctx.session_manager();
        let session = session_manager
            .resolve(req, better_auth_core::session::SessionRead::Authoritative)
            .await?
            .data
            .ok_or_else(|| AuthError::from(AuthResponse::new(401)))?
            .session;
        if !session.impersonated_by.field_value().is_truthy() {
            return Err(AuthError::bad_request("You are not impersonating anyone"));
        }

        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        let admin_cookie_value = get_cookie(req, &admin_cookie_name)
            .ok_or_else(|| AuthError::internal("Failed to find admin session"))?;
        let admin_cookie =
            decode_admin_session_cookie_value(ctx.config.signing_secret(), &admin_cookie_value)
                .map_err(|_| AuthError::internal("Failed to find admin session"))?;

        let (response, data) = stop_impersonating_core(&session, &admin_cookie, ctx).await?;

        ctx.session_manager()
            .set_session_cookie(req, data, Some(admin_cookie.dont_remember))
            .await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
        better_auth_core::utils::cookie_utils::remove_set_cookie_entries(
            req,
            Some(&mut auth_response.headers),
            &admin_cookie_name,
        )?;
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_clear_cookie(&admin_cookie_name, &ctx.config)?,
        );
        Ok(auth_response)
    }

    async fn handle_revoke_user_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "session", "revoke", MESSAGE_REVOKE_USER_SESSIONS)?;
        let body: RevokeSessionRequest = request::read(req)?;
        let response = revoke_user_session_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_revoke_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "session", "revoke", MESSAGE_REVOKE_USER_SESSIONS)?;
        let body: UserIdRequest = request::read(req)?;
        let response = revoke_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_remove_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "delete", MESSAGE_DELETE_USERS)?;
        let body: UserIdRequest = request::read(req)?;
        let response = remove_user_core(&body, user.id.typed()?.as_str(), ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_set_user_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "set-password", MESSAGE_SET_USER_PASSWORD)?;
        let body: SetUserPasswordRequest = request::read(req)?;
        let response = set_user_password_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_has_permission(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: HasPermissionRequest = request::read(req)?;
        let requested = body.requested_permissions().ok_or_else(|| {
            AuthError::bad_request("invalid permission check. no permission(s) were passed.")
        })?;
        let session = self.optional_session(req, ctx).await?;
        let user_id = body.user_id.as_deref().filter(|value| !value.is_empty());
        let role = body.role.as_deref().filter(|value| !value.is_empty());
        if session.is_none() && user_id.is_none() && role.is_none() {
            return Err(AuthError::bad_request("user id or role is required"));
        }
        let user = match session {
            Some((user, _)) => Some(user),
            None if role.is_some() => None,
            None => Some(
                ctx.database
                    .get_user_by_id(
                        user_id.ok_or_else(|| AuthError::bad_request("user not found"))?,
                    )
                    .await?
                    .ok_or_else(|| AuthError::bad_request("user not found"))?,
            ),
        };
        let response = match user {
            Some(user) => has_permission_core(&body, &user, &self.config)?,
            None => PermissionResponse {
                error: None,
                success: has_permission(
                    user_id,
                    &role.map_or(better_auth_core::FieldValue::Undefined, Into::into),
                    &self.config,
                    requested,
                )?,
            },
        };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}

pub(super) fn target_is_admin(
    user_id: Option<&str>,
    role: &better_auth_core::FieldValue,
    config: &AdminConfig,
) -> AuthResult<bool> {
    Ok(is_admin_user_id(user_id, config) || is_admin_role(role, config)?)
}

pub use access::RolePermissions;
