use std::collections::HashMap;

use better_auth_core::entity::AuthUser;
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name,
};
use better_auth_core::utils::username::{UsernameValidationError, validate_username};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, ErrorCodeMessageResponse,
};
use validator::Validate;

pub mod access;
pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use crate::plugins::helpers::{delete_session_cookie_headers, get_cookie};
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
const MESSAGE_USERNAME_IS_ALREADY_TAKEN: &str = "Username is already taken. Please try another.";
const MESSAGE_USERNAME_TOO_SHORT: &str = "Username is too short";
const MESSAGE_USERNAME_TOO_LONG: &str = "Username is too long";
const MESSAGE_INVALID_USERNAME: &str = "Username is invalid";

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: code.to_string(),
            message: message.to_string(),
        },
    )
    .map_err(AuthError::from)
}

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
    #[config(default = vec!["admin".to_string()])]
    pub admin_roles: Vec<String>,
    /// Users that always bypass admin permission checks.
    #[config(default = None)]
    pub admin_user_ids: Option<Vec<String>>,
    /// Custom role definitions. When provided, these replace the built-in
    /// `admin` and `user` role permissions.
    #[config(default = HashMap::new())]
    pub roles: HashMap<String, access::RolePermissions>,
    /// Default reason applied when banning a user without an explicit reason.
    #[config(default = None)]
    pub default_ban_reason: Option<String>,
    /// Default ban duration in seconds when banning a user without an explicit duration.
    #[config(default = None)]
    pub default_ban_expires_in: Option<i64>,
    /// Custom impersonation session duration in seconds.
    #[config(default = None)]
    pub impersonation_session_duration: Option<i64>,
    /// Message surfaced to banned users.
    #[config(default = "You have been banned from this application. Please contact support if you believe this is an error.".to_string())]
    pub banned_user_message: String,
    /// Whether other admin users may be impersonated.
    #[config(default = false)]
    pub allow_impersonating_admins: bool,
}

better_auth_core::impl_auth_plugin! {
    AdminPlugin, "admin";
    routes {
        post "/admin/set-role" => handle_set_role, "admin_set_role";
        get  "/admin/get-user" => handle_get_user, "admin_get_user";
        post "/admin/create-user" => handle_create_user, "admin_create_user";
        post "/admin/update-user" => handle_update_user, "admin_update_user";
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
    extra {
        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> better_auth_core::AuthResult<()> {
            ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));
            ctx.set_metadata(
                "admin.default_role",
                serde_json::Value::String(self.config.default_role.clone()),
            );
            ctx.set_metadata(
                "admin.banned_user_message",
                serde_json::Value::String(self.config.banned_user_message.clone()),
            );
            Ok(())
        }
    }
}

impl AdminPlugin {
    async fn require_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<(UserView, SessionView)> {
        let (user, session) = ctx.require_session(req).await?;
        Ok((UserView::from(&user), SessionView::from(&session)))
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
            Some(user.id.as_str()),
            user.role.as_deref(),
            &self.config,
            &permissions,
        ) {
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
        let body: SetRoleRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
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
            id: req.query.get("id").cloned().unwrap_or_default(),
        };
        query
            .validate()
            .map_err(|error| AuthError::validation(error.to_string()))?;
        let response = get_user_core(&query, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_create_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "create", MESSAGE_CREATE_USERS)?;
        let body: CreateUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = create_user_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "update", MESSAGE_UPDATE_USERS)?;
        let mut body: AdminUpdateUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let username = body
            .data
            .remove("username")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .map(|value| value.to_lowercase());
        let display_username = body
            .data
            .remove("displayUsername")
            .and_then(|value| value.as_str().map(ToOwned::to_owned));

        if let Some(username) = username.as_deref() {
            match validate_username(username) {
                Ok(()) => {}
                Err(UsernameValidationError::TooShort) => {
                    return username_error_response(
                        400,
                        "USERNAME_TOO_SHORT",
                        MESSAGE_USERNAME_TOO_SHORT,
                    );
                }
                Err(UsernameValidationError::TooLong) => {
                    return username_error_response(
                        400,
                        "USERNAME_IS_TOO_LONG",
                        MESSAGE_USERNAME_TOO_LONG,
                    );
                }
                Err(UsernameValidationError::Invalid) => {
                    return username_error_response(
                        400,
                        "USERNAME_IS_INVALID",
                        MESSAGE_INVALID_USERNAME,
                    );
                }
            }

            if let Some(existing_user) = ctx.database.get_user_by_username(username).await?
                && AuthUser::id(&existing_user).as_ref() != body.user_id
            {
                return username_error_response(
                    400,
                    "USERNAME_IS_ALREADY_TAKEN",
                    MESSAGE_USERNAME_IS_ALREADY_TAKEN,
                );
            }
        }

        if let Some(username) = username {
            _ = body
                .data
                .insert("username".to_string(), serde_json::Value::String(username));
        }
        if let Some(display_username) = display_username {
            _ = body.data.insert(
                "displayUsername".to_string(),
                serde_json::Value::String(display_username),
            );
        }

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
        let query = ListUsersQueryParams {
            limit: req.query.get("limit").and_then(|value| value.parse().ok()),
            offset: req.query.get("offset").and_then(|value| value.parse().ok()),
            search_field: req.query.get("searchField").cloned(),
            search_value: req.query.get("searchValue").cloned(),
            search_operator: req.query.get("searchOperator").cloned(),
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
            filter_field: req.query.get("filterField").cloned(),
            filter_value: req.query.get("filterValue").cloned(),
            filter_operator: req.query.get("filterOperator").cloned(),
        };
        let response = list_users_core(&query, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "session", "list", MESSAGE_LIST_USER_SESSIONS)?;
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
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "ban", MESSAGE_BAN_USERS)?;
        let body: BanUserRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = ban_user_core(&body, user.id.as_str(), &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_unban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "ban", MESSAGE_BAN_USERS)?;
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
        let (user, session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "impersonate", MESSAGE_IMPERSONATE_USERS)?;
        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let (response, token) = impersonate_user_core(
            &body,
            user.id.as_str(),
            req.headers
                .get("x-forwarded-for")
                .map(|value| value.as_str()),
            req.headers.get("user-agent").map(|value| value.as_str()),
            &self.config,
            ctx,
        )
        .await?;
        let dont_remember =
            get_cookie(req, &related_cookie_name(&ctx.config, "dont_remember")).is_some();
        let admin_cookie = create_admin_session_cookie_value(
            &ctx.config.secret,
            &AdminSessionCookiePayload {
                session_token: session.token.clone(),
                dont_remember,
            },
            ctx.config.session.expires_in,
        )?;
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");

        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in delete_session_cookie_headers(&ctx.config) {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &admin_cookie_name,
                &admin_cookie,
                Some(ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            ),
        );
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(Some(&token), None, &ctx.config),
        );
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(&ctx.config, "dont_remember"),
                "true",
                None,
                &ctx.config,
            ),
        );
        Ok(auth_response)
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
        if session.impersonated_by.is_none() {
            return Err(AuthError::bad_request("You are not impersonating anyone"));
        }

        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        let admin_cookie_value = get_cookie(req, &admin_cookie_name)
            .ok_or_else(|| AuthError::internal("Failed to find admin session"))?;
        let admin_cookie =
            decode_admin_session_cookie_value(&ctx.config.secret, &admin_cookie_value)
                .map_err(|_| AuthError::internal("Failed to find admin session"))?;

        let (response, new_token) = stop_impersonating_core(&session, &admin_cookie, ctx).await?;

        let mut auth_response = AuthResponse::json(200, &response)?;
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(&new_token),
                if admin_cookie.dont_remember {
                    None
                } else {
                    Some(ctx.config.session.expires_in.num_seconds())
                },
                &ctx.config,
            ),
        );
        if admin_cookie.dont_remember {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                create_session_like_cookie(
                    &related_cookie_name(&ctx.config, "dont_remember"),
                    "true",
                    None,
                    &ctx.config,
                ),
            );
        }
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_clear_cookie(&admin_cookie_name, &ctx.config),
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
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "session", "revoke", MESSAGE_REVOKE_USER_SESSIONS)?;
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
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "delete", MESSAGE_DELETE_USERS)?;
        let body: UserIdRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = remove_user_core(&body, user.id.as_str(), ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_set_user_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;
        self.authorize(&user, "user", "set-password", MESSAGE_SET_USER_PASSWORD)?;
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
        let (user, _session) = self.require_session(req, ctx).await?;
        let body: HasPermissionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = has_permission_core(&body, &user, &self.config)?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}

pub(super) fn target_is_admin(
    user_id: Option<&str>,
    role: Option<&str>,
    config: &AdminConfig,
) -> bool {
    is_admin_user_id(user_id, config) || is_admin_role(role, config)
}

pub use access::RolePermissions;
