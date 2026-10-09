//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).

use better_auth_core::entity::AuthUser;
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, FieldMap, UpdateUser};
use chrono::Utc;

pub(crate) fn user_email(user: &impl AuthUser) -> AuthResult<String> {
    let email = user.email().field_value();
    match email {
        better_auth_core::FieldValue::String(email) => Ok(email),
        better_auth_core::FieldValue::Utf16String(email) => email.to_utf8().map_err(|error| {
            AuthError::internal(format!(
                "Cannot represent user email as a Rust string: {error}"
            ))
        }),
        _ => Err(AuthError::internal(
            "user.email.toLowerCase is not a function",
        )),
    }
}

pub(crate) fn session_is_fresh(
    session: &impl better_auth_core::AuthSession,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<bool> {
    let fresh_age = config
        .session
        .fresh_age
        .unwrap_or_else(|| chrono::Duration::hours(24));
    if fresh_age.is_zero() {
        return Ok(true);
    }
    let created_at = session.created_at().converted_date()?.date_milliseconds()?;
    let stale =
        Utc::now().timestamp_millis() as f64 - created_at >= fresh_age.num_milliseconds() as f64;
    Ok(!stale)
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
    user_id: &better_auth_core::FieldValue,
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
            if !api_key.reference_id.field_value().strict_equals(user_id) {
                return Err(AuthError::not_found("API Key not found"));
            }
        }
        ApiKeyReferences::Organization => {
            require_org_api_key_permission_value(
                ctx,
                user_id,
                &api_key.reference_id.field_value(),
                action,
            )
            .await?;
        }
    }

    Ok(api_key)
}

/// Authorize a user against an organization-owned API key, mirroring
/// upstream's `checkOrgApiKeyPermission`.
pub async fn require_org_api_key_permission(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_id: &better_auth_core::FieldValue,
    organization_id: &str,
    action: &str,
) -> AuthResult<()> {
    require_org_api_key_permission_value(ctx, user_id, &organization_id.into(), action).await
}

async fn require_org_api_key_permission_value(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_id: &better_auth_core::FieldValue,
    organization_id: &better_auth_core::FieldValue,
    action: &str,
) -> AuthResult<()> {
    use crate::plugins::api_key::{ApiKeyErrorCode, api_key_error};
    use crate::plugins::organization::rbac::check_api_key_permission;
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

    let Some(member) = ctx
        .database
        .get_member_value(organization_id, user_id)
        .await?
    else {
        return Err(api_key_error(ApiKeyErrorCode::UserNotMemberOfOrganization));
    };

    let creator_role = ctx
        .get_metadata(METADATA_CREATOR_ROLE)
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "owner".to_string());
    let custom_roles: Option<HashMap<String, RolePermissions>> = ctx
        .get_metadata(METADATA_ROLES)
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?
        .flatten();

    let config = OrganizationConfig {
        creator_role,
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
    // The upstream API key boundary denies permission when the organization checker throws.
    let allowed = check_api_key_permission(&member.role, organization_id, action, &config, ctx)
        .await
        .unwrap_or(false);

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
    ctx.database.get_credential_account(user_id).await
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

/// Apply the configured default admin role when the input has no role property.
pub fn apply_default_role(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    fields: &mut FieldMap,
) {
    if let Some(default_role) = ctx
        .get_metadata("admin.default_role")
        .and_then(|value| value.as_str())
    {
        let _ = fields
            .entry("role".into())
            .or_insert_with(|| default_role.into());
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
    message.resolve(&ctx.internal_user_view(user).await?).await
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
        ctx.config.session.expires_in(),
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

/// Preserve cancellation and missing readback separately from admission and storage errors.
pub(crate) async fn issue_selected_user_session_optional<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user: better_auth_core::FieldValue,
    meta: &better_auth_core::RequestMeta,
    expires_in: chrono::Duration,
) -> Result<Option<better_auth_core::session::NativeSessionData>, SessionIssueError> {
    let user_id = better_auth_core::SchemaValue::<String>::from_field(
        user.as_object()
            .and_then(|fields| fields.get("id"))
            .cloned()
            .unwrap_or_default(),
    );
    let session = issue_session_for_id_optional(ctx, user_id, meta, expires_in).await?;
    Ok(session.map(|session| better_auth_core::session::NativeSessionData { user, session }))
}

/// Apply session admission without replacing the supplied owner with a projected User ID.
pub(crate) async fn issue_session_for_id_optional<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: better_auth_core::SchemaValue<String>,
    meta: &better_auth_core::RequestMeta,
    expires_in: chrono::Duration,
) -> Result<Option<better_auth_core::wire::SessionView>, SessionIssueError> {
    admit_session_for_id(ctx, &user_id, None).await?;
    Ok(ctx
        .session_manager()
        .create_session_for_id_with_lifetime_optional(
            user_id,
            meta.ip_address.clone(),
            meta.user_agent.clone(),
            expires_in,
        )
        .await?)
}

/// Apply the admin plugin's admission lookup through the active transaction.
pub(crate) async fn admit_session_for_id<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &better_auth_core::SchemaValue<String>,
    transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
) -> Result<(), SessionIssueError> {
    if admin_plugin_enabled(ctx) && user_id.is_truthy()? {
        let stored_user = match transaction {
            Some(tx) => tx.get_user_by_id_field(user_id).await?,
            None => ctx.database.get_user_by_id_field(user_id).await?,
        };
        if let Some(stored_user) = stored_user {
            apply_session_ban(ctx, user_id, &stored_user, transaction).await?;
        }
    }
    Ok(())
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

    apply_session_ban(ctx, &user_id.into(), &user, transaction).await?;
    Ok(user)
}

async fn apply_session_ban<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &better_auth_core::SchemaValue<String>,
    user: &better_auth_core::wire::UserView,
    transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
) -> Result<(), SessionIssueError> {
    if !admin_plugin_enabled(ctx) {
        return Ok(());
    }
    let fields = better_auth_core::FieldMap::from(user.clone());
    if fields
        .get("banned")
        .is_some_and(better_auth_core::FieldValue::is_truthy)
    {
        let expires = fields.get("banExpires");
        let expired = match expires.filter(|value| value.is_truthy()) {
            Some(expires) => {
                better_auth_core::query::field_date(expires)?.milliseconds()
                    < Utc::now().timestamp_millis() as f64
            }
            None => false,
        };
        if expired {
            let update = UpdateUser {
                banned: Some(false),
                ban_reason: Some(None),
                ban_expires: Some(None),
                ..Default::default()
            };
            // Session admission updates storage without replacing the route's user snapshot.
            let _ = match transaction {
                Some(tx) => {
                    tx.update_user_by_id_value(&user_id.field_value(), update)
                        .await?
                }
                None => {
                    ctx.database
                        .update_user_by_id_value(&user_id.field_value(), update)
                        .await?
                }
            };
        } else {
            return Err(SessionIssueError::Banned {
                message: admin_banned_user_message(ctx, user).await?,
            });
        }
    }

    Ok(())
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

/// Clear session cookies, publishing each header before attempting the next cookie.
pub use better_auth_core::utils::cookie_utils::delete_session_cookies;

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

#[cfg(test)]
#[path = "helpers/session_tests.rs"]
mod session_tests;

#[cfg(test)]
#[path = "helpers/nullable_session_tests.rs"]
mod nullable_session_tests;
