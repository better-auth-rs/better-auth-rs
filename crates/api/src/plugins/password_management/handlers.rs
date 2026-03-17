use chrono::{Duration, Utc};
use url::Url;
use uuid::Uuid;

use better_auth_core::utils::password::{self as password_utils};
use better_auth_core::{
    AuthAccount, AuthContext, AuthError, AuthResult, AuthSession, AuthUser, AuthVerification,
    CreateAccount, RequestMeta, UpdateAccount, extract_origin,
};

use crate::plugins::helpers::{get_credential_account, get_credential_password_hash};

use super::types::*;
use super::{PasswordManagementConfig, StatusResponse};

const PASSWORD_RESET_SUCCESS_MESSAGE: &str =
    "If this email exists in our system, check your email for the reset link";

// ---------------------------------------------------------------------------
// Core functions (framework-agnostic business logic)
// ---------------------------------------------------------------------------

pub(crate) async fn request_password_reset_core(
    body: &RequestPasswordResetRequest,
    config: &PasswordManagementConfig,
    ctx: &AuthContext,
) -> AuthResult<RequestPasswordResetResponse> {
    if let Some(redirect_to) = &body.redirect_to {
        validate_redirect_target(redirect_to, ctx, "Invalid redirectURL")?;
    }

    let sender = config
        .send_reset_password
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("Reset password isn't enabled"))?;

    let success = RequestPasswordResetResponse {
        status: true,
        message: PASSWORD_RESET_SUCCESS_MESSAGE.to_string(),
    };

    let user = match ctx.database.get_user_by_email(&body.email).await? {
        Some(user) => user,
        None => {
            let _ = Uuid::new_v4().simple().to_string();
            let _ = ctx
                .database
                .get_verification_by_identifier("dummy-verification-token")
                .await?;
            tracing::error!(email = %body.email, "Reset Password: User not found");
            return Ok(success);
        }
    };

    let reset_token = Uuid::new_v4().simple().to_string();
    let expires_at = Utc::now() + Duration::hours(config.reset_token_expiry_hours);

    let _ = ctx
        .database
        .create_verification(better_auth_core::CreateVerification {
            identifier: format!("reset-password:{}", reset_token),
            value: user.id().to_string(),
            expires_at,
        })
        .await?;

    let callback_url = body
        .redirect_to
        .as_deref()
        .map(urlencoding::encode)
        .unwrap_or_default();
    let reset_url = format!(
        "{}/reset-password/{}?callbackURL={}",
        ctx.config.base_url, reset_token, callback_url
    );

    let user_value = password_utils::serialize_to_value(&user)?;
    if let Err(error) = sender.send(&user_value, &reset_url, &reset_token).await {
        tracing::warn!(
            email = %body.email,
            error = %error,
            "Custom send_reset_password callback failed"
        );
    }

    Ok(success)
}

pub(crate) async fn reset_password_core(
    body: &ResetPasswordRequest,
    config: &PasswordManagementConfig,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    password_utils::validate_password(
        &body.new_password,
        ctx.config.password.min_length,
        usize::MAX,
        ctx,
    )?;

    let token = body.token.as_deref().unwrap_or("");
    if token.is_empty() {
        return Err(AuthError::bad_request("Invalid token"));
    }

    let verification = ctx
        .database
        .get_verification_by_identifier(&format!("reset-password:{}", token))
        .await?
        .filter(|verification| verification.expires_at() >= Utc::now())
        .ok_or_else(|| AuthError::bad_request("Invalid token"))?;
    let user_id = verification.value().to_string();

    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.new_password).await?;

    if let Some(account) = get_credential_account(ctx, &user_id).await? {
        let _ = ctx
            .database
            .update_account(
                account.id(),
                UpdateAccount {
                    password: Some(password_hash),
                    ..Default::default()
                },
            )
            .await?;
    } else {
        let _ = ctx
            .database
            .create_account(CreateAccount {
                user_id: user_id.clone(),
                account_id: user_id.clone(),
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

    ctx.database.delete_verification(verification.id()).await?;

    if let Some(callback) = &config.on_password_reset
        && let Some(user) = ctx.database.get_user_by_id(&user_id).await?
    {
        match password_utils::serialize_to_value(&user) {
            Ok(user_value) => {
                if let Err(error) = callback(user_value).await {
                    tracing::warn!(error = %error, "on_password_reset callback failed");
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Failed to serialize user for on_password_reset callback"
                );
            }
        }
    }

    if config.revoke_sessions_on_password_reset {
        ctx.database.delete_user_sessions(&user_id).await?;
    }

    Ok(StatusResponse { status: true })
}

pub(crate) async fn reset_password_token_core(
    token: &str,
    query: &ResetPasswordTokenQuery,
    ctx: &AuthContext,
) -> AuthResult<ResetPasswordTokenResult> {
    if let Some(callback_url) = &query.callback_url {
        validate_redirect_target(callback_url, ctx, "Invalid callbackURL")?;
    }

    if token.is_empty() || query.callback_url.is_none() {
        return Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
            &ctx.config.base_url,
            query.callback_url.as_deref(),
            &[("error", "INVALID_TOKEN")],
        )?));
    }

    let verification = ctx
        .database
        .get_verification_by_identifier(&format!("reset-password:{}", token))
        .await?;

    if verification
        .as_ref()
        .is_none_or(|verification| verification.expires_at() < Utc::now())
    {
        return Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
            &ctx.config.base_url,
            query.callback_url.as_deref(),
            &[("error", "INVALID_TOKEN")],
        )?));
    }

    Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
        &ctx.config.base_url,
        query.callback_url.as_deref(),
        &[("token", token)],
    )?))
}

/// Change the user's password. Returns the response and an optional new session token.
pub(crate) async fn change_password_core(
    body: &ChangePasswordRequest,
    user: &better_auth_core::User,
    config: &PasswordManagementConfig,
    meta: &RequestMeta,
    ctx: &AuthContext,
) -> AuthResult<(
    ChangePasswordResponse<better_auth_core::User>,
    Option<String>,
)> {
    if config.require_current_password {
        let stored_hash = get_credential_password_hash(ctx, user)
            .await?
            .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;

        password_utils::verify_password(
            config.password_hasher.as_ref(),
            &body.current_password,
            &stored_hash,
        )
        .await
        .map_err(|_| AuthError::bad_request("Invalid password"))?;
    }

    password_utils::validate_password(
        &body.new_password,
        ctx.config.password.min_length,
        usize::MAX,
        ctx,
    )?;

    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.new_password).await?;

    let credential_account = get_credential_account(ctx, user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
    let _ = ctx
        .database
        .update_account(
            credential_account.id(),
            UpdateAccount {
                password: Some(password_hash),
                ..Default::default()
            },
        )
        .await?;

    let new_token = if body.revoke_other_sessions == Some(true) {
        ctx.database.delete_user_sessions(user.id()).await?;
        let session = ctx
            .session_manager()
            .create_session(user, meta.ip_address.clone(), meta.user_agent.clone())
            .await?;
        Some(session.token().to_string())
    } else {
        None
    };

    let response = ChangePasswordResponse {
        token: new_token.clone(),
        user: ctx
            .database
            .get_user_by_id(user.id())
            .await?
            .ok_or(AuthError::UserNotFound)?,
    };

    Ok((response, new_token))
}

fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext,
    error_message: &str,
) -> AuthResult<()> {
    if !target.starts_with("//") && Url::parse(target).is_err() {
        return Ok(());
    }

    let origin =
        extract_origin(target).ok_or_else(|| AuthError::forbidden(error_message.to_string()))?;
    if ctx.config.is_origin_trusted(&origin) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_string()))
    }
}

fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    let base = Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {}", error)))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url)
            .map_err(|error| AuthError::bad_request(format!("Invalid callbackURL: {}", error)))?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {}", error)))?
    };

    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            let _ = pairs.append_pair(key, value);
        }
    }

    Ok(url.to_string())
}
