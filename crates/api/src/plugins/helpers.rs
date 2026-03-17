//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).

use better_auth_core::entity::{AuthAccount, AuthApiKey, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthResult};

/// Convert an `expiresIn` value (milliseconds from now) into an RFC 3339
/// `expires_at` timestamp string.
///
/// Returns `None` when `expires_in_ms` is `None`.
pub fn expires_in_to_at(expires_in_ms: Option<i64>) -> AuthResult<Option<String>> {
    match expires_in_ms {
        Some(ms) => {
            let duration = chrono::Duration::try_milliseconds(ms)
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
    ctx: &AuthContext,
    key_id: &str,
    user_id: &str,
) -> AuthResult<better_auth_core::ApiKey> {
    let api_key = ctx
        .database
        .get_api_key_by_id(key_id)
        .await?
        .ok_or_else(|| AuthError::not_found("API key not found"))?;

    if api_key.user_id() != user_id {
        return Err(AuthError::not_found("API key not found"));
    }

    Ok(api_key)
}

/// Fetch the user's credential account, if present.
pub async fn get_credential_account(
    ctx: &AuthContext,
    user_id: &str,
) -> AuthResult<Option<better_auth_core::Account>> {
    Ok(ctx
        .database
        .get_user_accounts(user_id)
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential"))
}

/// Resolve the user's stored password hash from the credential account.
pub async fn get_credential_password_hash(
    ctx: &AuthContext,
    user: &better_auth_core::User,
) -> AuthResult<Option<String>> {
    Ok(get_credential_account(ctx, user.id())
        .await?
        .and_then(|account| account.password().map(str::to_string)))
}

/// Whether the user currently has a password set.
pub async fn user_has_password(
    ctx: &AuthContext,
    user: &better_auth_core::User,
) -> AuthResult<bool> {
    Ok(get_credential_password_hash(ctx, user).await?.is_some())
}
