//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).

use better_auth_core::config::OAuthStateStrategy;
use better_auth_core::entity::AuthUser;
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, CreateUser, UpdateUser};
use chrono::Utc;

mod user_input;
pub(crate) use user_input::apply_user_create_fields;

pub(crate) fn session_is_fresh(
    session: &impl better_auth_core::AuthSession,
    config: &better_auth_core::AuthConfig,
) -> bool {
    let fresh_age = config
        .session
        .fresh_age
        .unwrap_or_else(|| chrono::Duration::hours(24));
    fresh_age.is_zero() || Utc::now() - session.created_at() < fresh_age
}

/// Convert an `expiresIn` value (**seconds** from now) into an RFC 3339
/// `expires_at` timestamp string.
///
/// Returns `None` when `expires_in_secs` is `None`.
pub fn expires_in_to_at(expires_in_secs: Option<i64>) -> AuthResult<Option<String>> {
    match expires_in_secs {
        Some(secs) => {
            let duration = chrono::Duration::try_seconds(secs)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            let dt = chrono::Utc::now()
                .checked_add_signed(duration)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            Ok(Some(
                dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ))
        }
        None => Ok(None),
    }
}

/// Fetch an API key by ID and verify that it belongs to the given user.
///
/// Returns `AuthError::not_found` if the key does not exist or belongs to
/// another user.  This pattern was duplicated in `handle_get`, `handle_update`,
/// and `handle_delete`.
pub async fn get_owned_api_key(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &crate::plugins::api_key::ApiKeyConfig,
    key_id: &str,
    user_id: &str,
    action: &str,
) -> AuthResult<better_auth_core::ApiKey> {
    use crate::plugins::api_key::{ApiKeyReferences, config_id_matches};

    let api_key = crate::plugins::api_key::storage::get_by_id(config, ctx, key_id)
        .await?
        .ok_or_else(|| AuthError::not_found("API Key not found"))?;

    // A key only exists as far as the configuration that addressed it.
    if !config_id_matches(&api_key.config_id, &config.config_id) {
        return Err(AuthError::not_found("API Key not found"));
    }

    match config.references {
        ApiKeyReferences::User => {
            if api_key.reference_id != user_id {
                return Err(AuthError::not_found("API Key not found"));
            }
        }
        ApiKeyReferences::Organization => {
            require_org_api_key_permission(ctx, user_id, &api_key.reference_id, action).await?;
        }
    }

    Ok(api_key)
}

/// Authorize a user against an organization-owned API key, mirroring
/// upstream's `checkOrgApiKeyPermission`.
pub async fn require_org_api_key_permission(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_id: &str,
    organization_id: &str,
    action: &str,
) -> AuthResult<()> {
    use crate::plugins::api_key::{ApiKeyErrorCode, api_key_error};
    use crate::plugins::organization::rbac::check_permission;
    use crate::plugins::organization::{
        METADATA_AC, METADATA_CREATOR_ROLE, METADATA_DYNAMIC_ACCESS_CONTROL, METADATA_ENABLED,
        METADATA_ROLES, OrganizationConfig, RolePermissions,
    };
    use std::collections::HashMap;

    // Organization-owned keys are meaningless without the organization plugin,
    // which is what supplies the access control below.
    if !ctx
        .get_metadata(METADATA_ENABLED)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return Err(api_key_error(ApiKeyErrorCode::OrganizationPluginRequired));
    }

    let Some(member) = ctx.database.get_member(organization_id, user_id).await? else {
        return Err(api_key_error(ApiKeyErrorCode::UserNotMemberOfOrganization));
    };

    // Upstream passes `allowCreatorAllPermissions`, so the creator role clears
    // every action without consulting the statements. Roles are composite
    // (comma-separated), so holding it alongside others still counts.
    let creator_role = ctx
        .get_metadata(METADATA_CREATOR_ROLE)
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "owner".to_string());
    if member
        .role
        .typed()?
        .split(',')
        .map(str::trim)
        .any(|role| role == creator_role)
    {
        return Ok(());
    }

    let custom_roles: Option<HashMap<String, RolePermissions>> = ctx
        .get_metadata(METADATA_ROLES)
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?
        .flatten();

    let config = OrganizationConfig {
        roles: custom_roles,
        dynamic_access_control: ctx
            .get_metadata(METADATA_DYNAMIC_ACCESS_CONTROL)
            .and_then(serde_json::Value::as_bool)
            == Some(true),
        ac: ctx
            .get_metadata(METADATA_AC)
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?
            .flatten(),
        ..Default::default()
    };
    let allowed = check_permission(
        member.role.typed()?,
        organization_id,
        "apikey",
        &[action],
        &config,
        ctx,
    )
    .await?;

    if allowed {
        Ok(())
    } else {
        Err(api_key_error(
            ApiKeyErrorCode::InsufficientApiKeyPermissions,
        ))
    }
}

/// Fetch the user's credential account, if present.
pub async fn get_credential_account<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: impl Into<better_auth_core::SchemaValue<String>>,
) -> AuthResult<Option<better_auth_core::wire::AccountView>> {
    let user_id = user_id.into();
    let Some(user_id) = user_id.as_str() else {
        return Ok(None);
    };
    Ok(ctx
        .database
        .get_user_accounts(user_id)
        .await?
        .into_iter()
        .find(|account| account.provider_id == "credential"))
}

/// Resolve the user's stored password hash from the credential account.
pub async fn get_credential_password_hash(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<Option<String>> {
    let Some(account) = get_credential_account(ctx, user.id().into_owned()).await? else {
        return Ok(None);
    };
    if !account.password.is_truthy()? {
        return Ok(None);
    }
    Ok(account.password.typed()?.clone())
}

/// Whether the user currently has a password set.
pub async fn user_has_password(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<bool> {
    Ok(get_credential_password_hash(ctx, user).await?.is_some())
}

/// Apply the configured default admin role to a new user when the caller
/// didn't set an explicit role.
pub fn apply_default_role(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    create_user: &mut CreateUser,
) {
    if create_user.role.is_some() {
        return;
    }

    if let Some(default_role) = ctx
        .get_metadata("admin.default_role")
        .and_then(|value| value.as_str())
    {
        create_user.role = Some(default_role.to_string());
    }
}

/// Result of issuing a real session for a user.
pub struct IssuedSession {
    pub user: better_auth_core::wire::UserView,
    pub session: better_auth_core::wire::SessionView,
}

/// Session issuance failures that callers may need to surface differently from
/// a generic auth error (for example OAuth callback redirects).
pub enum SessionIssueError {
    Auth(AuthError),
    Banned { message: String },
}

impl SessionIssueError {
    pub fn into_auth_error(self) -> AuthError {
        match self {
            Self::Auth(error) => error,
            Self::Banned { message } => AuthError::banned_user(message),
        }
    }

    pub fn banned_message(&self) -> Option<&str> {
        match self {
            Self::Banned { message } => Some(message.as_str()),
            Self::Auth(_) => None,
        }
    }
}

impl From<AuthError> for SessionIssueError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

/// Whether the admin plugin is active for this auth instance.
pub fn admin_plugin_enabled(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> bool {
    ctx.get_metadata("admin.enabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

/// Resolve the configured message shown when a banned user attempts to create
/// a session.
pub async fn admin_banned_user_message(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<String> {
    let message = ctx
        .extensions
        .get::<super::admin::BannedUserMessage>()
        .cloned()
        .unwrap_or_default();
    message.resolve(&ctx.internal_user_view(user)?).await
}

/// Issue a session for the given user, applying admin-plugin ban semantics
/// when the admin plugin is enabled.
pub async fn issue_user_session<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSession, SessionIssueError> {
    issue_user_session_with_lifetime(
        ctx,
        user_id,
        ip_address,
        user_agent,
        ctx.config.session.expires_in,
    )
    .await
}

pub(crate) async fn issue_user_session_with_lifetime<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_in: chrono::Duration,
) -> Result<IssuedSession, SessionIssueError> {
    let user = session_user(ctx, user_id, None).await?;

    let session = ctx
        .session_manager()
        .create_session_with_lifetime(&user, ip_address, user_agent, expires_in)
        .await?;

    Ok(IssuedSession { user, session })
}

/// Resolve the user and apply session admission through the active transaction.
pub(crate) async fn session_user<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
) -> Result<better_auth_core::wire::UserView, SessionIssueError> {
    let user = match transaction {
        Some(tx) => tx.get_user_by_id(user_id).await?,
        None => ctx.database.get_user_by_id(user_id).await?,
    }
    .ok_or(AuthError::UserNotFound)?;

    if admin_plugin_enabled(ctx) && user.banned() {
        if user
            .ban_expires()
            .is_some_and(|expires| expires < Utc::now())
        {
            let update = UpdateUser {
                banned: Some(false),
                ban_reason: Some(None),
                ban_expires: Some(None),
                ..Default::default()
            };
            // Session admission updates storage without replacing the route's user snapshot.
            let _ = match transaction {
                Some(tx) => tx.update_user(user_id, update).await?,
                None => ctx.database.update_user(user_id, update).await?,
            };
        } else {
            return Err(SessionIssueError::Banned {
                message: admin_banned_user_message(ctx, &user).await?,
            });
        }
    }

    Ok(user)
}

/// Parse a cookie value from the request's `Cookie` header.
pub fn get_cookie(req: &AuthRequest, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
    header
        .split(';')
        .filter_map(|cookie| {
            let trimmed = cookie.trim();
            let (cookie_name, cookie_value) = trimmed.split_once('=')?;
            (cookie_name == name).then_some(cookie_value.to_string())
        })
        .next()
}

/// TS-style cookie clearing used by `deleteSessionCookie`.
pub fn delete_session_cookie_headers(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
) -> Vec<String> {
    use better_auth_core::utils::cookie_utils::{
        create_clear_chunked_cookies, create_clear_cookie, create_clear_session_cookie,
        related_cookie_name,
    };
    let mut cookies = vec![create_clear_session_cookie(config)];
    cookies.extend(create_clear_chunked_cookies(
        req,
        &config.auth_cookie("session_data", Default::default()),
    ));
    cookies.push(create_clear_cookie(
        &related_cookie_name(config, "dont_remember"),
        config,
    ));
    if config.account.store_account_cookie() {
        cookies.extend(create_clear_chunked_cookies(
            req,
            &config.auth_cookie("account_data", Default::default()),
        ));
    }
    if matches!(
        config.account.store_state_strategy(),
        OAuthStateStrategy::Cookie
    ) {
        cookies.push(create_clear_cookie(
            &related_cookie_name(config, "oauth_state"),
            config,
        ));
    }
    cookies
}

/// Parse the comma-delimited scopes stored on an OAuth account.
pub(crate) fn parse_stored_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or_default()
        .split(',')
        .map(|scope| scope.trim_matches(oauth_scope_whitespace))
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn oauth_scope_whitespace(character: char) -> bool {
    (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
}

#[cfg(test)]
#[path = "helpers/response_tests.rs"]
mod response_tests;
