use chrono::{Duration, Utc};
use uuid::Uuid;

use better_auth_core::{AuthContext, AuthError, AuthResult, PASSWORD_HASH_KEY};
use better_auth_core::{AuthSession, AuthUser, AuthVerification, DatabaseAdapter};

use better_auth_core::utils::password::{self as password_utils};

use super::types::*;
use super::{PasswordManagementConfig, StatusResponse};

// ---------------------------------------------------------------------------
// Core functions (framework-agnostic business logic)
// ---------------------------------------------------------------------------

pub(crate) async fn forget_password_core<DB: DatabaseAdapter>(
    body: &ForgetPasswordRequest,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Check if user exists
    let user = match ctx.database.get_user_by_email(&body.email).await? {
        Some(user) => user,
        None => {
            // Don't reveal whether email exists or not for security
            return Ok(StatusResponse { status: true });
        }
    };

    // Generate password reset token
    let reset_token = format!("reset_{}", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::hours(config.reset_token_expiry_hours);

    // Create verification token
    let create_verification = better_auth_core::CreateVerification {
        identifier: user.email().unwrap_or_default().to_string(),
        value: reset_token.clone(),
        expires_at,
    };

    ctx.database
        .create_verification(create_verification)
        .await?;

    // Build reset URL — only allow redirect_to when it shares the same
    // origin as the configured base_url to prevent open-redirect /
    // token-exfiltration attacks.
    let reset_url = if let Some(redirect_to) = &body.redirect_to {
        if redirect_to.starts_with('/') || redirect_to.starts_with(&ctx.config.base_url) {
            format!("{}?token={}", redirect_to, reset_token)
        } else {
            // Untrusted origin — fall back to server-side base URL.
            tracing::warn!(
                redirect_to = %redirect_to,
                "Ignoring untrusted redirect_to"
            );
            format!(
                "{}/reset-password?token={}",
                ctx.config.base_url, reset_token
            )
        }
    } else {
        format!(
            "{}/reset-password?token={}",
            ctx.config.base_url, reset_token
        )
    };

    if config.send_email_notifications {
        if let Some(sender) = &config.send_reset_password {
            let user_value = password_utils::serialize_to_value(&user)?;
            if let Err(e) = sender.send(&user_value, &reset_url, &reset_token).await {
                tracing::warn!(
                    email = %body.email,
                    error = %e,
                    "Custom send_reset_password callback failed"
                );
            }
        } else if let Ok(provider) = ctx.email_provider() {
            let subject = "Reset your password";
            let html = format!(
                "<p>Click the link below to reset your password:</p>\
                 <p><a href=\"{url}\">Reset Password</a></p>",
                url = reset_url
            );
            let text = format!("Reset your password: {}", reset_url);

            if let Err(e) = provider.send(&body.email, subject, &html, &text).await {
                tracing::warn!(
                    email = %body.email,
                    error = %e,
                    "Failed to send password reset email"
                );
            }
        } else {
            tracing::warn!(
                email = %body.email,
                "No email provider configured, skipping password reset email"
            );
        }
    }

    Ok(StatusResponse { status: true })
}

pub(crate) async fn reset_password_core<DB: DatabaseAdapter>(
    body: &ResetPasswordRequest,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Validate password
    password_utils::validate_password(
        &body.new_password,
        ctx.config.password.min_length,
        usize::MAX,
        ctx,
    )?;

    // Find user by reset token
    let token = body.token.as_deref().unwrap_or("");
    if token.is_empty() {
        return Err(AuthError::bad_request("Reset token is required"));
    }

    let (user, verification) = find_user_by_reset_token(token, ctx)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired reset token"))?;

    // Hash new password
    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.new_password).await?;

    // Update user password
    let mut metadata = user.metadata().clone();
    metadata[PASSWORD_HASH_KEY] = serde_json::Value::String(password_hash);

    ctx.database
        .update_user(user.id(), password_utils::update_user_metadata(metadata))
        .await?;

    // Delete the used verification token
    ctx.database.delete_verification(verification.id()).await?;

    // Revoke all existing sessions for security (when configured)
    if config.revoke_sessions_on_password_reset {
        ctx.database.delete_user_sessions(user.id()).await?;
    }

    // Call on_password_reset callback if configured.
    if let Some(callback) = &config.on_password_reset {
        match password_utils::serialize_to_value(&user) {
            Ok(user_value) => {
                if let Err(e) = callback(user_value).await {
                    tracing::warn!(
                        error = %e,
                        "on_password_reset callback failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to serialize user for on_password_reset callback"
                );
            }
        }
    }

    Ok(StatusResponse { status: true })
}

pub(crate) async fn reset_password_token_core<DB: DatabaseAdapter>(
    token: &str,
    query: &ResetPasswordTokenQuery,
    ctx: &AuthContext<DB>,
) -> AuthResult<ResetPasswordTokenResult> {
    // Validate the reset token exists and is not expired
    match find_user_by_reset_token(token, ctx).await? {
        Some((_user, _verification)) => {}
        None => {
            // Redirect to callback URL with error if provided
            if let Some(callback_url) = &query.callback_url {
                let redirect_url = format!("{}?error=INVALID_TOKEN", callback_url);
                return Ok(ResetPasswordTokenResult::Redirect(redirect_url));
            }
            return Err(AuthError::bad_request("Invalid or expired reset token"));
        }
    };

    // If callback URL is provided, redirect with valid token
    if let Some(callback_url) = &query.callback_url {
        let redirect_url = format!("{}?token={}", callback_url, token);
        return Ok(ResetPasswordTokenResult::Redirect(redirect_url));
    }

    // Otherwise return the token directly
    Ok(ResetPasswordTokenResult::Json(ResetPasswordTokenResponse {
        token: token.to_string(),
    }))
}

/// Change the user's password. Returns the response and an optional new session token.
pub(crate) async fn change_password_core<DB: DatabaseAdapter>(
    body: &ChangePasswordRequest,
    user: &DB::User,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<(ChangePasswordResponse<DB::User>, Option<String>)> {
    // Verify current password
    if config.require_current_password {
        let stored_hash = user
            .password_hash()
            .ok_or_else(|| AuthError::bad_request("No password set for this user"))?;

        password_utils::verify_password(
            config.password_hasher.as_ref(),
            &body.current_password,
            stored_hash,
        )
        .await
        .map_err(|_| AuthError::InvalidCredentials)?;
    }

    // Validate new password
    password_utils::validate_password(
        &body.new_password,
        ctx.config.password.min_length,
        usize::MAX,
        ctx,
    )?;

    // Hash new password
    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.new_password).await?;

    // Update user password
    let mut metadata = user.metadata().clone();
    metadata[PASSWORD_HASH_KEY] = serde_json::Value::String(password_hash);

    let updated_user = ctx
        .database
        .update_user(user.id(), password_utils::update_user_metadata(metadata))
        .await?;

    // Handle session revocation
    let new_token = if body.revoke_other_sessions == Some(true) {
        // Revoke all sessions except current one
        ctx.database.delete_user_sessions(user.id()).await?;

        // Create new session
        let session = ctx
            .session_manager()
            .create_session(&updated_user, None, None)
            .await?;
        Some(session.token().to_string())
    } else {
        None
    };

    let response = ChangePasswordResponse {
        token: new_token.clone(),
        user: updated_user,
    };

    Ok((response, new_token))
}

pub(crate) async fn set_password_core<DB: DatabaseAdapter>(
    body: &SetPasswordRequest,
    user: &DB::User,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Verify the user does NOT already have a password
    if user.password_hash().is_some()
    {
        return Err(AuthError::bad_request(
            "User already has a password. Use /change-password instead.",
        ));
    }

    // Validate new password
    password_utils::validate_password(
        &body.new_password,
        ctx.config.password.min_length,
        usize::MAX,
        ctx,
    )?;

    // Hash and store the new password
    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.new_password).await?;

    let mut metadata = user.metadata().clone();
    metadata[PASSWORD_HASH_KEY] = serde_json::Value::String(password_hash);

    ctx.database
        .update_user(user.id(), password_utils::update_user_metadata(metadata))
        .await?;

    Ok(StatusResponse { status: true })
}

/// Shared helper: find a user by reset token value.
pub(super) async fn find_user_by_reset_token<DB: DatabaseAdapter>(
    token: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<Option<(DB::User, DB::Verification)>> {
    let verification = match ctx.database.get_verification_by_value(token).await? {
        Some(verification) => verification,
        None => return Ok(None),
    };

    let user = match ctx
        .database
        .get_user_by_email(verification.identifier())
        .await?
    {
        Some(user) => user,
        None => return Ok(None),
    };

    Ok(Some((user, verification)))
}
