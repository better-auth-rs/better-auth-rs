use std::collections::HashMap;

use better_auth_core::session::NativeSessionData;
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, encode_cookie_value, get_cookie, related_cookie_name, render_cookie,
    sign_cookie_value_native_raw, verify_cookie_value,
};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult};
use better_auth_core::{AuthSession, AuthUser};

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
mod impersonation_tests;
#[cfg(test)]
mod native_session_tests;
#[cfg(test)]
mod tests;

use crate::plugins::helpers::delete_session_cookies;
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
        fn schema(&self, fields: &mut better_auth_core::plugin_runtime::ModelFields) -> better_auth_core::AuthResult<()> {
            fields.register_native_user_fields("admin.enabled");
            fields.register_native_session_fields("admin.enabled")?;
            Ok(())
        }

        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> better_auth_core::AuthResult<()> {
            self.config.validate()?;
            S::User::require_plugin_fields("admin", &["role", "banned", "ban_reason", "ban_expires"])?;
            S::Session::require_plugin_fields("admin", &["impersonated_by"])?;
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
    ) -> AuthResult<NativeSessionData> {
        ctx.require_authoritative_native_session(req)
            .await
            .map_err(|error| match error.original() {
                AuthError::Unauthenticated => {
                    AuthError::from_status("UNAUTHORIZED", better_auth_core::FieldValue::Undefined)
                }
                _ => error,
            })
    }

    async fn optional_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        class: better_auth_core::ApiErrorClass,
    ) -> AuthResult<Option<NativeSessionData>> {
        let data = ctx
            .native_session(req, better_auth_core::session::SessionRead::Authoritative)
            .await?;
        if data.is_none() && (req.endpoint_headers().is_some() || req.original_request().is_some())
        {
            return Err(AuthError::try_api_error(better_auth_core::ApiErrorInit {
                status: "UNAUTHORIZED".into(),
                class,
                ..Default::default()
            })?);
        }
        Ok(data)
    }

    fn authorize(
        &self,
        session: &NativeSessionData,
        resource: &str,
        action: &str,
        code: &str,
        message: &str,
    ) -> AuthResult<()> {
        let permissions = HashMap::from([(resource.to_string(), vec![action.to_string()])]);
        if has_permission(
            &session.user_property("id")?,
            &session.user_property("role")?,
            &self.config,
            &permissions,
        )? {
            Ok(())
        } else {
            Err(AuthError::from_code("FORBIDDEN", code, message))
        }
    }

    async fn handle_set_role(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "set-role",
            "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
            MESSAGE_CHANGE_ROLE,
        )?;
        let body: SetRoleRequest = request::read(req)?;
        let response = set_role_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::native(None, response.into_field_value()))
    }

    async fn handle_get_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "get",
            "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
            MESSAGE_GET_USER,
        )?;
        let query = GetUserQuery {
            id: req.query_string("id")?.unwrap_or_default(),
        };
        let response = get_user_core(&query, ctx).await?;
        Ok(AuthResponse::native(
            None,
            better_auth_core::FieldMap::from(response).into(),
        ))
    }

    async fn handle_create_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: CreateUserRequest = request::read(req)?;
        let session = self
            .optional_session(req, ctx, better_auth_core::ApiErrorClass::BetterCall)
            .await?;
        if let Some(session) = &session {
            self.authorize(
                session,
                "user",
                "create",
                "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
                MESSAGE_CREATE_USERS,
            )?;
        }
        let response = create_user_core(&body, Some(req), session, &self.config, ctx).await?;
        Ok(AuthResponse::native(None, response.into_field_value()))
    }

    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "update",
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
            MESSAGE_UPDATE_USERS,
        )?;
        let body: AdminUpdateUserRequest = request::read(req)?;
        let response = update_user_core(&body, &session, &self.config, ctx).await?;
        Ok(AuthResponse::native(
            None,
            response
                .map(|user| better_auth_core::FieldMap::from(user).into())
                .unwrap_or(better_auth_core::FieldValue::Null),
        ))
    }

    async fn handle_list_users(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "list",
            "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
            MESSAGE_LIST_USERS,
        )?;
        let query: ListUsersQueryParams = crate::plugins::query_input::parse(req)?;
        // The upstream admin endpoint catches list/count/projection failures.
        let response = list_users_core(&query, ctx)
            .await
            .map(ListUsersResponse::into_field_value)
            .unwrap_or_else(|_| {
                better_auth_core::FieldMap::from([
                    (
                        "users".into(),
                        Vec::<better_auth_core::FieldValue>::new().into(),
                    ),
                    ("total".into(), 0.into()),
                ])
                .into()
            });
        Ok(AuthResponse::native(None, response))
    }

    async fn handle_list_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "session",
            "list",
            "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS",
            MESSAGE_LIST_USER_SESSIONS,
        )?;
        let body: UserIdRequest = request::read(req)?;
        let response = list_user_sessions_core(&body, ctx).await?;
        let sessions: Vec<better_auth_core::FieldValue> = response
            .sessions
            .into_iter()
            .map(|session| better_auth_core::FieldMap::from(session).into())
            .collect();
        Ok(AuthResponse::native(
            None,
            better_auth_core::FieldMap::from([("sessions".into(), sessions.into())]).into(),
        ))
    }

    async fn handle_ban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "ban",
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
            MESSAGE_BAN_USERS,
        )?;
        let body: BanUserRequest = request::read(req)?;
        let response =
            ban_user_core(&body, &session.user_property("id")?, &self.config, ctx).await?;
        Ok(AuthResponse::native(None, response.into_field_value()))
    }

    async fn handle_unban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "ban",
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
            MESSAGE_BAN_USERS,
        )?;
        let body: UserIdRequest = request::read(req)?;
        let response = unban_user_core(&body, ctx).await?;
        Ok(AuthResponse::native(None, response.into_field_value()))
    }

    async fn handle_impersonate_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "impersonate",
            "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
            MESSAGE_IMPERSONATE_USERS,
        )?;
        let body: UserIdRequest = request::read(req)?;
        let (response, data) = impersonate_user_core(
            &body,
            &session,
            ctx.config.advanced.ip_address.resolve(req).as_deref(),
            req.headers.get("user-agent").map(|value| value.as_str()),
            &self.config,
            ctx,
        )
        .await?;
        delete_session_cookies(req, &ctx.config, false, None)?;
        let dont_remember = get_cookie(req, &related_cookie_name(&ctx.config, "dont_remember"))
            .and_then(|value| verify_cookie_value(&value, ctx.config.signing_secret()))
            .unwrap_or_default();
        let mut payload = session
            .session_property("token")?
            .display_utf16()?
            .as_utf16()
            .to_vec();
        payload.push(u16::from(b':'));
        payload.extend(dont_remember.encode_utf16());
        let admin_cookie = encode_cookie_value(&sign_cookie_value_native_raw(
            &better_auth_core::Utf16String::from_units(payload).into(),
            ctx.config.signing_secret(),
        )?);
        let mut cookie = ctx.config.auth_cookie(
            "session_token",
            better_auth_core::CookieAttributes {
                max_age: Some(ctx.config.session.expires_in().as_seconds_f64()),
                ..Default::default()
            },
        );
        cookie.name = related_cookie_name(&ctx.config, "admin_session");
        req.append_response_header("Set-Cookie", render_cookie(&admin_cookie, &cookie)?)?;
        ctx.session_manager()
            .set_session_cookie(req, data, Some(true))
            .await?;
        let response = SessionUserResponse {
            session: ctx.session_view(&response.session).await?,
            user: ctx.user_view(&response.user).await?,
        };
        Ok(AuthResponse::native(
            None,
            better_auth_core::FieldMap::from([
                (
                    "session".into(),
                    better_auth_core::FieldMap::from(response.session).into(),
                ),
                (
                    "user".into(),
                    better_auth_core::FieldMap::from(response.user).into(),
                ),
            ])
            .into(),
        ))
    }

    async fn handle_stop_impersonating(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = ctx
            .native_session(req, better_auth_core::session::SessionRead::Cached)
            .await?
            .ok_or_else(|| {
                AuthError::from_status("UNAUTHORIZED", better_auth_core::FieldValue::Undefined)
            })?;
        let (data, dont_remember) = stop_impersonating_core(&session, req, ctx).await?;

        ctx.session_manager()
            .set_native_session_cookie(req, data.clone(), Some(dont_remember))
            .await?;
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        better_auth_core::utils::cookie_utils::remove_set_cookie_entries(
            req,
            None,
            &admin_cookie_name,
        )?;
        req.append_response_header(
            "Set-Cookie",
            create_clear_cookie(&admin_cookie_name, &ctx.config)?,
        )?;
        let response = better_auth_core::FieldMap::from([
            ("session".into(), data.public_session(&ctx.config.session)?),
            ("user".into(), data.public_user(&ctx.config.user)?),
        ])
        .into();
        Ok(AuthResponse::native(None, response))
    }

    async fn handle_revoke_user_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "session",
            "revoke",
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
            MESSAGE_REVOKE_USER_SESSIONS,
        )?;
        let body: RevokeSessionRequest = request::read(req)?;
        let response = revoke_user_session_core(&body, ctx).await?;
        AuthResponse::json(None, &response)
    }

    async fn handle_revoke_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "session",
            "revoke",
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
            MESSAGE_REVOKE_USER_SESSIONS,
        )?;
        let body: UserIdRequest = request::read(req)?;
        let response = revoke_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(None, &response)
    }

    async fn handle_remove_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "delete",
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
            MESSAGE_DELETE_USERS,
        )?;
        let body: UserIdRequest = request::read(req)?;
        let response = remove_user_core(&body, &session.user_property("id")?, ctx).await?;
        AuthResponse::json(None, &response)
    }

    async fn handle_set_user_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let session = self.require_session(req, ctx).await?;
        self.authorize(
            &session,
            "user",
            "set-password",
            "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
            MESSAGE_SET_USER_PASSWORD,
        )?;
        let body: SetUserPasswordRequest = request::read(req)?;
        let response = set_user_password_core(&body, ctx).await?;
        AuthResponse::json(None, &response)
    }

    async fn handle_has_permission(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: HasPermissionRequest = request::read(req)?;
        let requested = body.requested_permissions().ok_or_else(|| {
            AuthError::from_status(
                "BAD_REQUEST",
                better_auth_core::FieldMap::from([(
                    "message".into(),
                    "invalid permission check. no permission(s) were passed.".into(),
                )])
                .into(),
            )
        })?;
        let session = self
            .optional_session(req, ctx, better_auth_core::ApiErrorClass::BetterAuth)
            .await?;
        let user_id = body.user_id.as_deref().filter(|value| !value.is_empty());
        let role = body.role.as_deref().filter(|value| !value.is_empty());
        if session.is_none() && user_id.is_none() && role.is_none() {
            return Err(AuthError::from_status(
                "BAD_REQUEST",
                better_auth_core::FieldMap::from([(
                    "message".into(),
                    "user id or role is required".into(),
                )])
                .into(),
            ));
        }
        let session = match session {
            Some(data) if data.user_value()?.is_truthy() => Some(data),
            _ => None,
        };
        let (user_id, role) = if let Some(session) = session {
            (session.user_property("id")?, session.user_property("role")?)
        } else if let Some(role) = role {
            (user_id.unwrap_or_default().into(), role.into())
        } else {
            let user_id = user_id.ok_or_else(|| {
                AuthError::from_status(
                    "BAD_REQUEST",
                    better_auth_core::FieldMap::from([("message".into(), "user not found".into())])
                        .into(),
                )
            })?;
            let user = ctx
                .database
                .get_user_by_id_value(&user_id.into())
                .await?
                .ok_or_else(|| {
                    AuthError::from_status(
                        "BAD_REQUEST",
                        better_auth_core::FieldMap::from([(
                            "message".into(),
                            "user not found".into(),
                        )])
                        .into(),
                    )
                })?;
            (user.id.field_value(), user.role.field_value())
        };
        let response = PermissionResponse {
            error: None,
            success: has_permission(&user_id, &role, &self.config, requested)?,
        };
        AuthResponse::json(None, &response)
    }
}

pub(super) fn target_is_admin(
    user_id: &better_auth_core::FieldValue,
    role: &better_auth_core::FieldValue,
    config: &AdminConfig,
) -> AuthResult<bool> {
    Ok(is_admin_user_id(user_id, config) || is_admin_role(role, config)?)
}

pub use access::RolePermissions;
