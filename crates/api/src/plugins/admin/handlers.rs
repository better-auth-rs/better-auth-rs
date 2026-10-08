use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use better_auth_core::entity::{AuthSession, AuthUser};
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
    if let Some(roles) = &config.roles
        && role.roles().iter().any(|role| !roles.contains_key(role))
    {
        return Err(AuthError::bad_request(MESSAGE_NON_EXISTENT_ROLE));
    }
    Ok(())
}

fn require_user_permission(
    user: &UserView,
    config: &AdminConfig,
    action: &str,
    message: &str,
) -> AuthResult<()> {
    let permission = std::collections::HashMap::from([("user".into(), vec![action.into()])]);
    if has_permission(
        Some(user.id.typed()?),
        user.role.as_deref(),
        config,
        &permission,
    ) {
        Ok(())
    } else {
        Err(AuthError::forbidden(message))
    }
}

fn has_ban_data(data: &serde_json::Map<String, serde_json::Value>) -> bool {
    ["banned", "banReason", "banExpires"]
        .iter()
        .any(|key| data.contains_key(*key))
}

fn ban_expiry(
    data: &serde_json::Map<String, serde_json::Value>,
) -> AuthResult<Option<chrono::DateTime<Utc>>> {
    data.get("banExpires")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|_| AuthError::bad_request("Invalid banExpires"))
        })
        .transpose()
}

pub(crate) async fn set_role_core(
    body: &SetRoleRequest,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    validate_role_input(&body.role, config)?;
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    let update = UpdateUser {
        role: Some(joined_role(&body.role)),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(UserResponse {
        user: ctx.user_view(&updated_user).await?,
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
    ctx.user_view(&user).await
}

pub(crate) async fn create_user_core(
    body: &CreateUserRequest,
    req: Option<&better_auth_core::AuthRequest>,
    session: Option<(
        better_auth_core::wire::UserView,
        better_auth_core::wire::SessionView,
    )>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    let mut data = body.data.clone().unwrap_or_default();
    let data_role = data.remove("role");
    if (body.role.is_some() || data_role.is_some())
        && let Some((user, _)) = &session
    {
        require_user_permission(user, config, "set-role", MESSAGE_CHANGE_ROLE)?;
    }
    let role = match &body.role {
        Some(role) => Some(role.clone()),
        None => data_role
            .map(serde_json::from_value::<RoleInput>)
            .transpose()
            .map_err(|_| AuthError::bad_request(MESSAGE_INVALID_ROLE_TYPE))?,
    };
    if let Some(role) = &role {
        validate_role_input(role, config)?;
    }
    if has_ban_data(&data)
        && let Some((user, _)) = &session
    {
        require_user_permission(user, config, "ban", "You are not allowed to ban users")?;
    }
    let email = body.email.to_lowercase();
    if !crate::plugins::json_body::valid_email(&email)? {
        return Err(AuthError::bad_request("Invalid email"));
    }
    if let Some(password) = body
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
        && password.encode_utf16().count() > ctx.password_policy.max_length
    {
        return Err(AuthError::bad_request("Password too long"));
    }
    if ctx.database.get_user_by_email(&email).await?.is_some() {
        return Err(AuthError::bad_request(
            "User already exists. Use another email.",
        ));
    }
    let mut create_user = better_auth_core::CreateUser::new()
        .with_email(email)
        .with_name(&body.name)
        .with_role(
            role.as_ref()
                .map(joined_role)
                .unwrap_or_else(|| config.default_role.clone()),
        );
    create_user.banned = data.get("banned").and_then(serde_json::Value::as_bool);
    create_user.ban_reason = data
        .get("banReason")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    create_user.ban_expires = ban_expiry(&data)?.map(Into::into);
    create_user.image = better_auth_core::SchemaValue::from_json(data.get("image").cloned())?;
    create_user.email_verified = data
        .get("emailVerified")
        .and_then(serde_json::Value::as_bool);
    create_user.additional_fields = better_auth_core::FieldMap::from_json(data)?;

    let mut input: serde_json::Map<String, serde_json::Value> = match req {
        Some(req) => req.body_as_json()?,
        None => serde_json::from_value(serde_json::to_value(body)?)?,
    };
    input.retain(|key, _| {
        matches!(
            key.as_str(),
            "email" | "name" | "password" | "role" | "data"
        )
    });
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        req,
        better_auth_core::FieldValue::from_json(input.into())?,
        ctx,
    );
    endpoint.path = Some("/admin/create-user");
    endpoint.session = session;
    let user =
        crate::plugins::user_admission::create_user_optional(create_user, "admin", &endpoint)
            .await?
            .ok_or(AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_CREATE_USER",
                message: "Failed to create user",
            })?;

    if let Some(password) = body
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        let password_hash =
            better_auth_core::hash_password(ctx.password_policy.hasher.as_ref(), password).await?;
        let _ = ctx
            .database
            .create_account_optional(CreateAccount {
                user_id: user.id().into_owned(),
                account_id: user.id().into_owned(),
                provider_id: ("credential".to_string()).into(),
                access_token: Default::default(),
                refresh_token: Default::default(),
                id_token: Default::default(),
                access_token_expires_at: Default::default(),
                refresh_token_expires_at: Default::default(),
                scope: Default::default(),
                password: (Some(password_hash))
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                ..Default::default()
            })
            .await?;
    }

    Ok(UserResponse {
        user: ctx.user_view(&user).await?,
    })
}

pub(crate) async fn update_user_core(
    body: &AdminUpdateUserRequest,
    acting_user: &UserView,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<AdminUserView>> {
    if body.data.is_empty() {
        return Err(AuthError::bad_request(MESSAGE_NO_DATA_TO_UPDATE));
    }

    if body.data.contains_key("password") {
        return Err(AuthError::bad_request(
            "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
        ));
    }
    let mut update = UpdateUser {
        additional_fields: better_auth_core::FieldMap::from_json(body.data.clone())?,
        ..Default::default()
    };

    if let Some(value) = body.data.get("role") {
        let permissions =
            std::collections::HashMap::from([("user".to_string(), vec!["set-role".to_string()])]);
        if !has_permission(
            acting_user.id.as_str(),
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

    if has_ban_data(&body.data) {
        require_user_permission(
            acting_user,
            config,
            "ban",
            "You are not allowed to ban users",
        )?;
        if body.data.get("banned") == Some(&serde_json::Value::Bool(true))
            && acting_user.id == body.user_id.as_str()
        {
            return Err(AuthError::bad_request("You cannot ban yourself"));
        }
    }
    if body.data.contains_key("email") || body.data.contains_key("emailVerified") {
        require_user_permission(
            acting_user,
            config,
            "set-email",
            "You are not allowed to update users email",
        )?;
        if let Some(value) = body.data.get("email") {
            let email = better_auth_core::SchemaValue::<String>::from_json(Some(value.clone()))?
                .display_string()?
                .to_lowercase();
            if !crate::plugins::json_body::valid_email(&email)? {
                return Err(AuthError::bad_request("Invalid email"));
            }
            if let Some(existing) = ctx.database.get_user_by_email(&email).await?
                && existing.id().into_owned() != body.user_id.as_str()
            {
                return Err(AuthError::bad_request(
                    "User already exists. Use another email.",
                ));
            }
            update.email = Some(email);
        }
    }
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;
    update.name = better_auth_core::SchemaValue::from_json(body.data.get("name").cloned())?;
    update.image = better_auth_core::SchemaValue::from_json(body.data.get("image").cloned())?;
    if let Some(value) = body
        .data
        .get("emailVerified")
        .and_then(|value| value.as_bool())
    {
        update.email_verified = Some(value);
    }
    if ctx.get_metadata("anonymous.enabled") == Some(&serde_json::Value::Bool(true)) {
        update.is_anonymous = body
            .data
            .get("isAnonymous")
            .and_then(serde_json::Value::as_bool);
    }
    if ctx.get_metadata("phone-number.enabled") == Some(&serde_json::Value::Bool(true)) {
        update.phone_number = body
            .data
            .get("phoneNumber")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        update.phone_number_verified = body
            .data
            .get("phoneNumberVerified")
            .and_then(serde_json::Value::as_bool);
    }
    if let Some(value) = body.data.get("banned").and_then(|value| value.as_bool()) {
        update.banned = Some(value);
    }
    if let Some(value) = body.data.get("banReason") {
        update.ban_reason = Some(
            serde_json::from_value(value.clone())
                .map_err(|_| AuthError::bad_request("Invalid banReason"))?,
        );
    }
    if body.data.contains_key("banExpires") {
        update.ban_expires = Some(ban_expiry(&body.data)?.map(Into::into));
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
        update.metadata = Some(better_auth_core::FieldMap::from_json(value.clone())?.into());
    }

    let updated_user = ctx
        .database
        .update_user_optional(&body.user_id, update)
        .await?;
    if body.data.get("banned") == Some(&serde_json::Value::Bool(true)) {
        ctx.database.delete_user_sessions(&body.user_id).await?;
    }
    match updated_user {
        Some(user) => ctx.user_view(&user).await.map(Some),
        None => Ok(None),
    }
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
        filter_value: query
            .filter_value
            .clone()
            .map(better_auth_core::FieldValue::from_json)
            .transpose()?,
        filter_operator: query.filter_operator.clone(),
    };

    let (users, total) = ctx.database.list_users(params).await?;
    let mut projected = Vec::with_capacity(users.len());
    for user in &users {
        projected.push(ctx.user_view(user).await?);
    }
    Ok(ListUsersResponse {
        users: projected,
        total,
        limit: query.limit,
        offset: query.offset,
    })
}

pub(crate) async fn list_user_sessions_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListSessionsResponse<SessionView>> {
    Ok(ListSessionsResponse {
        sessions: ctx
            .session_manager()
            .list_user_session_views(&body.user_id)
            .await?,
    })
}

pub(crate) async fn ban_user_core(
    body: &BanUserRequest,
    admin_user_id: impl AsRef<str>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    if body.user_id == admin_user_id.as_ref() {
        return Err(AuthError::bad_request("You cannot ban yourself"));
    }

    let seconds = body
        .ban_expires_in
        .filter(|value| *value != 0.0)
        .or_else(|| {
            config
                .default_ban_expires_in
                .filter(|value| *value != 0.0 && !value.is_nan())
        });
    let ban_expires = seconds
        .map(|seconds| {
            better_auth_core::utils::date::from_milliseconds(
                Utc::now().timestamp_millis() as f64 + seconds * 1000.0,
            )
            .ok_or_else(|| AuthError::internal("Invalid ban expiration date"))
        })
        .transpose()?;

    let update = UpdateUser {
        banned: Some(true),
        ban_reason: Some(Some(
            body.ban_reason
                .clone()
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    config
                        .default_ban_reason
                        .clone()
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_else(|| "No reason".to_string()),
        )),
        ban_expires: Some(ban_expires.map(Into::into)),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    let _ = ctx
        .session_manager()
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(UserResponse {
        user: ctx.user_view(&updated_user).await?,
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
        ban_reason: Some(None),
        ban_expires: Some(None),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(&body.user_id, update).await?;
    Ok(UserResponse {
        user: ctx.user_view(&updated_user).await?,
    })
}

pub(crate) async fn impersonate_user_core(
    body: &UserIdRequest,
    acting_user: &UserView,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(
    SessionUserResponse<SessionView, UserView>,
    better_auth_core::session::SessionData,
)> {
    if acting_user.id == body.user_id.as_str() {
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
        require_user_permission(
            acting_user,
            config,
            "impersonate-admins",
            MESSAGE_CANNOT_IMPERSONATE_ADMINS,
        )?;
    }

    if target.banned() {
        if target
            .ban_expires()
            .is_some_and(|expires| expires.milliseconds() <= Utc::now().timestamp_millis() as f64)
        {
            target = ctx
                .database
                .update_user(
                    &body.user_id,
                    UpdateUser {
                        banned: Some(false),
                        ban_reason: Some(None),
                        ban_expires: Some(None),
                        ..Default::default()
                    },
                )
                .await?;
        } else {
            return Err(AuthError::banned_user(
                config
                    .banned_user_message
                    .resolve(&ctx.internal_user_view(&target).await?)
                    .await?,
            ));
        }
    }

    let seconds = config
        .impersonation_session_duration
        .filter(|value| *value != 0.0 && !value.is_nan())
        .unwrap_or(3600.0);
    let expires_at = better_auth_core::utils::date::from_milliseconds(
        Utc::now().timestamp_millis() as f64 + seconds * 1000.0,
    )
    .ok_or_else(|| AuthError::internal("Invalid impersonation expiration date"))?;
    let create_session = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: target.id().into_owned(),
        expires_at: expires_at.into(),
        ip_address: ip_address.map(|value| value.to_string()),
        user_agent: user_agent.map(|value| value.to_string()),
        impersonated_by: acting_user.id.as_str().map(str::to_owned),
        active_organization_id: None,
    };

    let session = ctx
        .database
        .create_session_optional(create_session)
        .await?
        .ok_or(AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_CREATE_USER",
            message: "Failed to create user",
        })?;
    let data = ctx
        .session_manager()
        .internal_data(&target, &session)
        .await?;
    let response = SessionUserResponse {
        session: ctx.session_view(&session).await?,
        user: ctx.user_view(&target).await?,
    };

    Ok((response, data))
}

pub(crate) async fn stop_impersonating_core(
    session: &impl AuthSession,
    admin_cookie: &AdminSessionCookiePayload,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(
    SessionUserResponse<SessionView, UserView>,
    better_auth_core::session::SessionData,
)> {
    let admin_id = session.impersonated_by().field_value();
    if !admin_id.is_truthy() {
        return Err(AuthError::bad_request(MESSAGE_NOT_IMPERSONATING));
    }

    let admin_user = ctx
        .database
        .get_user_by_id_value(&admin_id)
        .await?
        .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_USER))?;

    let (admin_session, snapshot) = ctx
        .database
        .get_session_snapshot(&admin_cookie.session_token)
        .await?
        .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION))?;

    if admin_session.user_id() != admin_user.id() {
        return Err(AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION));
    }

    let snapshot = match snapshot {
        Some(data) => Some(
            data.into_typed()?
                .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION))?,
        ),
        None => None,
    };
    ctx.database
        .delete_session_by_token_value(&session.token().field_value())
        .await?;

    let data = if let Some(data) = snapshot {
        data
    } else {
        ctx.session_manager()
            .internal_data(&admin_user, &admin_session)
            .await?
    };
    let response = SessionUserResponse {
        session: ctx.session_view(&data.session).await?,
        user: ctx.user_view(&data.user).await?,
    };

    Ok((response, data))
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
        ctx.database.delete_account(account.id.typed()?).await?;
    }

    ctx.database.delete_user(&body.user_id).await?;
    Ok(SuccessResponse { success: true })
}

pub(crate) async fn set_user_password_core(
    body: &SetUserPasswordRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    better_auth_core::utils::password::validate_password(
        &body.new_password,
        ctx.password_policy.min_length,
        ctx.password_policy.max_length,
        ctx,
    )?;

    let user = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    let password_hash =
        better_auth_core::hash_password(ctx.password_policy.hasher.as_ref(), &body.new_password)
            .await?;

    let accounts = ctx.database.get_user_accounts(&body.user_id).await?;
    if let Some(account) = accounts
        .iter()
        .find(|account| account.provider_id == "credential")
    {
        let account_update = better_auth_core::UpdateAccount {
            password: (Some(password_hash))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            ..Default::default()
        };
        let _ = ctx
            .database
            .update_account(account.id.typed()?, account_update)
            .await?;
    } else {
        let _ = ctx
            .database
            .create_account_optional(CreateAccount {
                user_id: body.user_id.clone().into(),
                account_id: user.id.clone(),
                provider_id: "credential".into(),
                password: better_auth_core::SchemaValue::Typed(Some(password_hash)),
                ..Default::default()
            })
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
        success: has_permission(user.id.as_str(), user.role.as_deref(), config, requested),
    })
}
