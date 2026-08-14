use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, CreateAccount, CreateSession, UpdateUser,
};

use crate::plugins::StatusResponse;

use super::access::has_permission;
use super::types::*;
use super::{AdminConfig, target_is_admin};

const MESSAGE_USER_NOT_FOUND: &str = "User not found";
const MESSAGE_NON_EXISTENT_ROLE: &str = "You are not allowed to set a non-existent role value";
const MESSAGE_INVALID_ROLE_TYPE: &str = "Invalid role type";
const MESSAGE_NO_DATA_TO_UPDATE: &str = "No data to update";
const MESSAGE_CHANGE_ROLE: &str = "You are not allowed to change users role";
const MESSAGE_CANNOT_IMPERSONATE_ADMINS: &str = "You cannot impersonate admins";
const MESSAGE_NOT_IMPERSONATING: &str = "You are not impersonating anyone";
const MESSAGE_FAILED_TO_FIND_USER: &str = "Failed to find user";
const MESSAGE_FAILED_TO_FIND_ADMIN_SESSION: &str = "Failed to find admin session";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminSessionCookieClaims {
    #[serde(rename = "sessionToken")]
    session_token: String,
    #[serde(rename = "dontRemember")]
    dont_remember: bool,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AdminSessionCookiePayload {
    pub session_token: String,
    pub dont_remember: bool,
}

pub(crate) fn create_admin_session_cookie_value(
    secret: &str,
    payload: &AdminSessionCookiePayload,
    max_age: Duration,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = AdminSessionCookieClaims {
        session_token: payload.session_token.clone(),
        dont_remember: payload.dont_remember,
        exp: (now + max_age).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_admin_session_cookie_value(
    secret: &str,
    token: &str,
) -> AuthResult<AdminSessionCookiePayload> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let claims = decode::<AdminSessionCookieClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims;

    Ok(AdminSessionCookiePayload {
        session_token: claims.session_token,
        dont_remember: claims.dont_remember,
    })
}

fn joined_role(role: &RoleInput) -> String {
    role.joined()
}

fn validate_role_input(role: &RoleInput, config: &AdminConfig) -> AuthResult<()> {
    if role.is_empty() {
        return Err(AuthError::bad_request("role is required"));
    }

    if config.roles.is_empty() {
        return Ok(());
    }

    let unknown_roles: Vec<_> = role
        .roles()
        .into_iter()
        .filter(|item| !config.roles.contains_key(*item))
        .collect();

    if unknown_roles.is_empty() {
        Ok(())
    } else {
        Err(AuthError::bad_request(MESSAGE_NON_EXISTENT_ROLE))
    }
}

pub(crate) async fn set_role_core(
    body: &SetRoleRequest,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    validate_role_input(&body.role, config)?;

    let update = UpdateUser {
        role: Some(joined_role(&body.role)),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(UserResponse {
        user: AdminUserView::from(&updated_user),
    })
}

pub(crate) async fn get_user_core(
    query: &GetUserQuery,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AdminUserView> {
    let user = ctx
        .database
        .get_user_by_id(&query.id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;
    Ok(AdminUserView::from(&user))
}

pub(crate) async fn create_user_core(
    body: &CreateUserRequest,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    if ctx.database.get_user_by_email(&body.email).await?.is_some() {
        return Err(AuthError::bad_request(
            "User already exists. Use another email.",
        ));
    }

    let role = body
        .role
        .as_ref()
        .map(joined_role)
        .unwrap_or_else(|| config.default_role.clone());

    let metadata = body
        .data
        .clone()
        .map(serde_json::Value::Object)
        .unwrap_or_else(|| serde_json::json!({}));

    let create_user = better_auth_core::CreateUser::new()
        .with_email(&body.email)
        .with_name(&body.name)
        .with_role(role)
        .with_metadata(metadata);

    let user = ctx.database.create_user(create_user).await?;

    if let Some(password) = body
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        let password_hash = better_auth_core::hash_password(None, password).await?;
        let _ = ctx
            .database
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
    }

    Ok(UserResponse {
        user: AdminUserView::from(&user),
    })
}

pub(crate) async fn update_user_core(
    body: &AdminUpdateUserRequest,
    acting_user: &UserView,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AdminUserView> {
    if body.data.is_empty() {
        return Err(AuthError::bad_request(MESSAGE_NO_DATA_TO_UPDATE));
    }

    let mut update = UpdateUser::default();

    if let Some(value) = body.data.get("role") {
        let permissions =
            std::collections::HashMap::from([("user".to_string(), vec!["set-role".to_string()])]);
        if !has_permission(
            Some(acting_user.id.as_str()),
            acting_user.role.as_deref(),
            config,
            &permissions,
        ) {
            return Err(AuthError::forbidden(MESSAGE_CHANGE_ROLE));
        }

        let role = serde_json::from_value::<RoleInput>(value.clone())
            .map_err(|_| AuthError::bad_request(MESSAGE_INVALID_ROLE_TYPE))?;
        validate_role_input(&role, config)?;
        update.role = Some(joined_role(&role));
    }

    if let Some(value) = body.data.get("email").and_then(|value| value.as_str()) {
        update.email = Some(value.to_string());
    }
    if let Some(value) = body.data.get("name").and_then(|value| value.as_str()) {
        update.name = Some(value.to_string());
    }
    if let Some(value) = body.data.get("image").and_then(|value| value.as_str()) {
        update.image = Some(value.to_string());
    }
    if let Some(value) = body
        .data
        .get("emailVerified")
        .and_then(|value| value.as_bool())
    {
        update.email_verified = Some(value);
    }
    if let Some(value) = body.data.get("username").and_then(|value| value.as_str()) {
        update.username = Some(value.to_string());
    }
    if let Some(value) = body
        .data
        .get("displayUsername")
        .and_then(|value| value.as_str())
    {
        update.display_username = Some(value.to_string());
    }
    if let Some(value) = body.data.get("banned").and_then(|value| value.as_bool()) {
        update.banned = Some(value);
    }
    if let Some(value) = body.data.get("banReason").and_then(|value| value.as_str()) {
        update.ban_reason = Some(value.to_string());
    }
    if let Some(value) = body.data.get("banExpires").and_then(|value| value.as_str()) {
        let parsed = chrono::DateTime::parse_from_rfc3339(value)
            .map_err(|_| AuthError::bad_request("Invalid banExpires"))?
            .with_timezone(&Utc);
        update.ban_expires = Some(parsed);
    }
    if let Some(value) = body
        .data
        .get("twoFactorEnabled")
        .and_then(|value| value.as_bool())
    {
        update.two_factor_enabled = Some(value);
    }
    if let Some(value) = body
        .data
        .get("metadata")
        .and_then(|value| value.as_object())
    {
        update.metadata = Some(serde_json::Value::Object(value.clone()));
    }

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(AdminUserView::from(&updated_user))
}

pub(crate) async fn list_users_core(
    query: &ListUsersQueryParams,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListUsersResponse<AdminUserView>> {
    let params = better_auth_core::ListUsersParams {
        limit: query.limit,
        offset: query.offset,
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
        users: users.iter().map(AdminUserView::from).collect(),
        total,
        limit: query.limit.filter(|limit| *limit > 0),
        offset: query.offset.filter(|offset| *offset > 0),
    })
}

pub(crate) async fn list_user_sessions_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListSessionsResponse<SessionView>> {
    let session_manager = ctx.session_manager();
    let sessions = session_manager.list_user_sessions(&body.user_id).await?;
    Ok(ListSessionsResponse {
        sessions: sessions.iter().map(SessionView::from).collect(),
    })
}

pub(crate) async fn ban_user_core(
    body: &BanUserRequest,
    admin_user_id: impl AsRef<str>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    if body.user_id == admin_user_id.as_ref() {
        return Err(AuthError::bad_request("You cannot ban yourself"));
    }

    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    let ban_expires = body
        .ban_expires_in
        .or(config.default_ban_expires_in)
        .and_then(Duration::try_seconds)
        .map(|duration| Utc::now() + duration);

    let update = UpdateUser {
        banned: Some(true),
        ban_reason: Some(
            body.ban_reason
                .clone()
                .or_else(|| config.default_ban_reason.clone())
                .unwrap_or_else(|| "No reason".to_string()),
        ),
        ban_expires,
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    let _ = ctx
        .session_manager()
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(UserResponse {
        user: AdminUserView::from(&updated_user),
    })
}

pub(crate) async fn unban_user_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    let update = UpdateUser {
        banned: Some(false),
        ban_reason: None,
        ban_expires: None,
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(UserResponse {
        user: AdminUserView::from(&updated_user),
    })
}

pub(crate) async fn impersonate_user_core(
    body: &UserIdRequest,
    admin_user_id: impl AsRef<str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionUserResponse<SessionView, UserView>, String)> {
    if body.user_id == admin_user_id.as_ref() {
        return Err(AuthError::bad_request("Cannot impersonate yourself"));
    }

    let mut target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    if !config.allow_impersonating_admins
        && target_is_admin(Some(&body.user_id), target.role(), config)
    {
        return Err(AuthError::forbidden(MESSAGE_CANNOT_IMPERSONATE_ADMINS));
    }

    if target.banned() {
        if target
            .ban_expires()
            .is_some_and(|expires| expires <= Utc::now())
        {
            target = ctx
                .database
                .update_user(
                    &body.user_id,
                    UpdateUser {
                        banned: Some(false),
                        ban_reason: None,
                        ban_expires: None,
                        ..Default::default()
                    },
                )
                .await?;
        } else {
            return Err(AuthError::banned_user(config.banned_user_message.clone()));
        }
    }

    let expires_at = Utc::now()
        + Duration::try_seconds(config.impersonation_session_duration.unwrap_or(60 * 60))
            .unwrap_or(Duration::hours(1));
    let create_session = CreateSession {
        user_id: target.id().to_string(),
        expires_at,
        ip_address: ip_address.map(|value| value.to_string()),
        user_agent: user_agent.map(|value| value.to_string()),
        impersonated_by: Some(admin_user_id.as_ref().to_string()),
        active_organization_id: None,
    };

    let session = ctx.database.create_session(create_session).await?;
    let token = session.token().to_string();
    let response = SessionUserResponse {
        session: SessionView::from(&session),
        user: UserView::from(&target),
    };

    Ok((response, token))
}

pub(crate) async fn stop_impersonating_core(
    session: &impl AuthSession,
    admin_cookie: &AdminSessionCookiePayload,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionUserResponse<SessionView, UserView>, String)> {
    let admin_id = session
        .impersonated_by()
        .ok_or_else(|| AuthError::bad_request(MESSAGE_NOT_IMPERSONATING))?
        .to_string();

    let admin_user = ctx
        .database
        .get_user_by_id(&admin_id)
        .await?
        .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_USER))?;

    let admin_session = ctx
        .database
        .get_session(&admin_cookie.session_token)
        .await?
        .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION))?;

    if admin_session.user_id() != admin_user.id() {
        return Err(AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION));
    }

    ctx.session_manager()
        .delete_session(session.token())
        .await?;

    let token = admin_session.token().to_string();
    let response = SessionUserResponse {
        session: SessionView::from(&admin_session),
        user: UserView::from(&admin_user),
    };

    Ok((response, token))
}

pub(crate) async fn revoke_user_session_core(
    body: &RevokeSessionRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    ctx.session_manager()
        .delete_session(&body.session_token)
        .await?;
    Ok(SuccessResponse { success: true })
}

pub(crate) async fn revoke_user_sessions_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    let _ = ctx
        .session_manager()
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(SuccessResponse { success: true })
}

pub(crate) async fn remove_user_core(
    body: &UserIdRequest,
    admin_user_id: impl AsRef<str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    if body.user_id == admin_user_id.as_ref() {
        return Err(AuthError::bad_request("You cannot remove yourself"));
    }

    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    ctx.database.delete_user_sessions(&body.user_id).await?;

    let accounts = ctx.database.get_user_accounts(&body.user_id).await?;
    for account in &accounts {
        ctx.database.delete_account(&account.id()).await?;
    }

    ctx.database.delete_user(&body.user_id).await?;
    Ok(SuccessResponse { success: true })
}

pub(crate) async fn set_user_password_core(
    body: &SetUserPasswordRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if body.new_password.len() < ctx.config.password.min_length {
        return Err(AuthError::bad_request("Password too short"));
    }

    if body.new_password.len() > 128 {
        return Err(AuthError::bad_request("Password too long"));
    }

    let password_hash = better_auth_core::hash_password(None, &body.new_password).await?;

    let accounts = ctx.database.get_user_accounts(&body.user_id).await?;
    if let Some(account) = accounts
        .iter()
        .find(|account| account.provider_id() == "credential")
    {
        let account_update = better_auth_core::UpdateAccount {
            password: Some(password_hash),
            ..Default::default()
        };
        let _ = ctx
            .database
            .update_account(&account.id(), account_update)
            .await?;
    }

    Ok(StatusResponse { status: true })
}

pub(crate) fn has_permission_core(
    body: &HasPermissionRequest,
    user: &UserView,
    config: &AdminConfig,
) -> AuthResult<PermissionResponse> {
    let requested = body.requested_permissions().ok_or_else(|| {
        AuthError::bad_request("invalid permission check. no permission(s) were passed.")
    })?;

    Ok(PermissionResponse {
        error: None,
        success: has_permission(
            Some(user.id.as_str()),
            user.role.as_deref(),
            config,
            requested,
        ),
    })
}
