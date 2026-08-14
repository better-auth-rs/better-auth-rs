//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).

use better_auth_core::config::OAuthStateStrategy;
use better_auth_core::entity::{AuthAccount, AuthApiKey, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, CreateUser, UpdateUser};
use chrono::Utc;

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
            Ok(Some(dt.to_rfc3339()))
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
    key_id: &str,
    user_id: impl AsRef<str>,
) -> AuthResult<better_auth_core::ApiKey> {
    let api_key = ctx
        .database
        .get_api_key_by_id(key_id)
        .await?
        .ok_or_else(|| AuthError::not_found("API key not found"))?;

    if api_key.user_id().as_ref() != user_id.as_ref() {
        return Err(AuthError::not_found("API key not found"));
    }

    Ok(api_key)
}

/// Fetch the user's credential account, if present.
pub async fn get_credential_account<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: impl AsRef<str>,
) -> AuthResult<Option<S::Account>> {
    Ok(ctx
        .database
        .get_user_accounts(user_id.as_ref())
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential"))
}

/// Resolve the user's stored password hash from the credential account.
pub async fn get_credential_password_hash(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<Option<String>> {
    Ok(get_credential_account(ctx, user.id())
        .await?
        .and_then(|account| account.password().map(str::to_string)))
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
pub struct IssuedSession<S: better_auth_core::AuthSchema> {
    pub user: S::User,
    pub session: S::Session,
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
pub fn admin_banned_user_message(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Option<String> {
    ctx.get_metadata("admin.banned_user_message")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

/// Issue a session for the given user, applying admin-plugin ban semantics
/// when the admin plugin is enabled.
pub async fn issue_user_session<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSession<S>, SessionIssueError> {
    let mut user = ctx
        .database
        .get_user_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    if admin_plugin_enabled(ctx) && user.banned() {
        if user
            .ban_expires()
            .is_some_and(|expires| expires <= Utc::now())
        {
            user = ctx
                .database
                .update_user(
                    user_id,
                    UpdateUser {
                        banned: Some(false),
                        ban_reason: None,
                        ban_expires: None,
                        ..Default::default()
                    },
                )
                .await?;
        } else {
            return Err(SessionIssueError::Banned {
                message: admin_banned_user_message(ctx).unwrap_or_else(|| {
                    "You have been banned from this application. Please contact support if you believe this is an error.".to_string()
                }),
            });
        }
    }

    let session = ctx
        .session_manager()
        .create_session(&user, ip_address, user_agent)
        .await?;

    Ok(IssuedSession { user, session })
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
pub fn delete_session_cookie_headers(config: &better_auth_core::AuthConfig) -> Vec<String> {
    let mut cookies = vec![
        better_auth_core::utils::cookie_utils::create_clear_session_cookie(config),
        better_auth_core::utils::cookie_utils::create_clear_cookie(
            &better_auth_core::utils::cookie_utils::related_cookie_name(config, "session_data"),
            config,
        ),
        better_auth_core::utils::cookie_utils::create_clear_cookie(
            &better_auth_core::utils::cookie_utils::related_cookie_name(config, "dont_remember"),
            config,
        ),
    ];

    if config.account.store_account_cookie {
        cookies.push(better_auth_core::utils::cookie_utils::create_clear_cookie(
            &better_auth_core::utils::cookie_utils::related_cookie_name(config, "account_data"),
            config,
        ));
    }

    if matches!(
        config.account.store_state_strategy,
        OAuthStateStrategy::Cookie
    ) {
        cookies.push(better_auth_core::utils::cookie_utils::create_clear_cookie(
            &better_auth_core::utils::cookie_utils::related_cookie_name(config, "oauth_state"),
            config,
        ));
    }

    cookies
}
