//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthApiKey, AuthSession};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult};

/// Extract the authenticated user and session from a Bearer token in the
/// `Authorization` header.
///
/// This logic was previously duplicated in `api_key`, `passkey`, and
/// `two_factor` plugins.
pub async fn get_authenticated_user<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<(DB::User, DB::Session)> {
    let token = req
        .headers
        .get("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AuthError::Unauthenticated)?;

    let session = ctx
        .database
        .get_session(token)
        .await?
        .ok_or(AuthError::Unauthenticated)?;

    if session.expires_at() < chrono::Utc::now() {
        return Err(AuthError::Unauthenticated);
    }

    let user = ctx
        .database
        .get_user_by_id(session.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;

    Ok((user, session))
}

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
pub async fn get_owned_api_key<DB: DatabaseAdapter>(
    ctx: &AuthContext<DB>,
    key_id: &str,
    user_id: &str,
) -> AuthResult<DB::ApiKey> {
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
