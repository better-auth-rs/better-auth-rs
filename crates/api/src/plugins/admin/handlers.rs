use chrono::{Duration, Utc};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthContext, AuthError, AuthResult, ListUsersParams};
use better_auth_core::{CreateAccount, CreateSession, UpdateUser};

use crate::plugins::StatusResponse;

use super::AdminConfig;
use super::types::*;

// ---------------------------------------------------------------------------
// Core functions -- framework-agnostic business logic
// ---------------------------------------------------------------------------

pub(crate) async fn set_role_core(
    body: &SetRoleRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<UserView>> {
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
    Ok(UserResponse {
        user: UserView::from(&updated_user),
    })
}

pub(crate) async fn create_user_core(
    body: &CreateUserRequest,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<UserView>> {
    if ctx.database.get_user_by_email(&body.email).await?.is_some() {
        return Err(AuthError::conflict("A user with this email already exists"));
    }

    let role = body
        .role
        .clone()
        .unwrap_or_else(|| config.default_user_role.clone());

    let metadata = if let Some(serde_json::Value::Object(obj)) = body.data.clone() {
        serde_json::Value::Object(obj)
    } else {
        serde_json::json!({})
    };

    let create_user = better_auth_core::CreateUser::new()
        .with_email(&body.email)
        .with_name(&body.name)
        .with_role(role)
        .with_email_verified(true)
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
        user: UserView::from(&user),
    })
}

pub(crate) async fn list_users_core(
    query: &ListUsersQueryParams,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListUsersResponse<UserView>> {
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
        users: users.iter().map(UserView::from).collect(),
        total,
        limit,
        offset,
    })
}

pub(crate) async fn list_user_sessions_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListSessionsResponse<SessionView>> {
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

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
) -> AuthResult<UserResponse<UserView>> {
    if body.user_id == admin_user_id.as_ref() {
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

    let _ = ctx
        .session_manager()
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(UserResponse {
        user: UserView::from(&updated_user),
    })
}

pub(crate) async fn unban_user_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<UserView>> {
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
    Ok(UserResponse {
        user: UserView::from(&updated_user),
    })
}

pub(crate) async fn impersonate_user_core(
    body: &UserIdRequest,
    admin_user_id: impl AsRef<str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionUserResponse<SessionView, UserView>, String)> {
    if body.user_id == admin_user_id.as_ref() {
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
    session_token: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionUserResponse<SessionView, UserView>, String)> {
    let admin_id = session
        .impersonated_by()
        .ok_or_else(|| AuthError::bad_request("Current session is not an impersonation session"))?
        .to_string();

    ctx.session_manager().delete_session(session_token).await?;

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
    let _target = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

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
        .ok_or_else(|| AuthError::not_found("User not found"))?;

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
        return Err(AuthError::bad_request(format!(
            "Password must be at least {} characters long",
            ctx.config.password.min_length
        )));
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
    user: &impl AuthUser,
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
