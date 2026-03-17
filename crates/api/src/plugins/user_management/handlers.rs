use chrono::{Duration, Utc};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::utils::password as password_utils;
use better_auth_core::{AuthContext, AuthError, AuthResult, StatusResponse, UpdateUser};

use super::types::{ChangeEmailRequest, DeleteUserRequest};
use super::{UserInfo, UserManagementConfig};
use crate::plugins::email_verification::token::create_email_verification_token;
use better_auth_core::SuccessMessageResponse;

/// Send an email using the configured email provider, logging on failure.
pub(super) async fn send_email_or_log(
    ctx: &AuthContext,
    to: &str,
    subject: &str,
    html: &str,
    text: &str,
    action: &str,
) {
    if let Ok(provider) = ctx.email_provider() {
        if let Err(error) = provider.send(to, subject, html, text).await {
            tracing::warn!(
                plugin = "user-management",
                action = action,
                email = to,
                error = %error,
                "Failed to send email"
            );
        }
    } else {
        tracing::warn!(
            plugin = "user-management",
            action = action,
            email = to,
            "No email provider configured, skipping email"
        );
    }
}

pub(crate) async fn change_email_core(
    body: &ChangeEmailRequest,
    user: &better_auth_core::User,
    config: &UserManagementConfig,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    let new_email = body.new_email.to_lowercase();

    if user
        .email()
        .map(|email| email == new_email)
        .unwrap_or(false)
    {
        return Err(AuthError::bad_request("Email is the same"));
    }

    if ctx.database.get_user_by_email(&new_email).await?.is_some() {
        return Err(AuthError::UnprocessableEntity(
            "User already exists. Use another email.".to_string(),
        ));
    }

    if !user.email_verified() && config.change_email.update_without_verification {
        let update_user = UpdateUser {
            email: Some(new_email),
            ..Default::default()
        };
        let _ = ctx.database.update_user(user.id(), update_user).await?;

        return Ok(StatusResponse { status: true });
    }

    let request_type =
        if user.email_verified() && config.change_email.send_change_email_confirmation.is_some() {
            "change-email-confirmation"
        } else {
            "change-email-verification"
        };
    let callback_url = body.callback_url.as_deref().unwrap_or("/");
    let verification_token = create_email_verification_token(
        &ctx.config.secret,
        user.email().unwrap_or_default(),
        Some(&new_email),
        Duration::hours(24),
        Some(request_type),
    )?;
    let verification_url = format!(
        "{}/verify-email?token={}&callbackURL={}",
        ctx.config.base_url,
        verification_token,
        urlencoding::encode(callback_url),
    );

    if let Some(ref callback) = config.change_email.send_change_email_confirmation {
        callback
            .send(
                &UserInfo::from_auth_user(user),
                &new_email,
                &verification_url,
                &verification_token,
            )
            .await?;
    } else {
        let subject = "Confirm your email change";
        let html = format!(
            "<p>Click the link below to confirm your new email address:</p>\
             <p><a href=\"{url}\">Confirm Email Change</a></p>",
            url = verification_url
        );
        let text = format!("Confirm your email change: {}", verification_url);
        send_email_or_log(ctx, &new_email, subject, &html, &text, "change-email").await;
    }

    Ok(StatusResponse { status: true })
}

pub(crate) async fn delete_user_core(
    body: &DeleteUserRequest,
    user: &better_auth_core::User,
    session: &better_auth_core::Session,
    config: &UserManagementConfig,
    ctx: &AuthContext,
) -> AuthResult<SuccessMessageResponse> {
    if let Some(password) = body.password.as_deref() {
        let account = ctx
            .database
            .get_user_accounts(user.id())
            .await?
            .into_iter()
            .find(|account| account.provider_id() == "credential" && account.password().is_some())
            .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
        let stored_hash = account
            .password()
            .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
        password_utils::verify_password(None, password, stored_hash)
            .await
            .map_err(|_| AuthError::bad_request("Invalid password"))?;
    }

    if let Some(token) = body.token.as_deref() {
        let _ = delete_user_callback_core(token, user, config, ctx).await?;
        return Ok(SuccessMessageResponse {
            success: true,
            message: "User deleted".to_string(),
        });
    }

    if config.delete_user.require_verification {
        let email = user
            .email()
            .filter(|email| !email.is_empty())
            .ok_or_else(|| {
                AuthError::bad_request("Cannot send verification email: user has no email address")
            })?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let _ = ctx
            .database
            .create_verification(better_auth_core::CreateVerification {
                identifier: format!("delete-account-{token}"),
                value: user.id().to_string(),
                expires_at: Utc::now() + config.delete_user.delete_token_expires_in,
            })
            .await?;
        let verification_url = format!(
            "{}/delete-user/callback?token={}&callbackURL={}",
            ctx.config.base_url,
            token,
            urlencoding::encode(body.callback_url.as_deref().unwrap_or("/")),
        );

        let subject = "Confirm account deletion";
        let html = format!(
            "<p>Click the link below to confirm the deletion of your account:</p>\
             <p><a href=\"{url}\">Confirm Account Deletion</a></p>\
             <p>If you did not request this, please ignore this email.</p>",
            url = verification_url
        );
        let text = format!("Confirm account deletion: {}", verification_url);
        send_email_or_log(ctx, email, subject, &html, &text, "delete-user").await;

        return Ok(SuccessMessageResponse {
            success: true,
            message: "Verification email sent".to_string(),
        });
    }

    if body.password.is_none()
        && let Some(fresh_age) = ctx.config.session.fresh_age
        && session.created_at() + fresh_age < Utc::now()
    {
        return Err(AuthError::bad_request(
            "Session expired. Re-authenticate to perform this action.",
        ));
    }

    perform_user_deletion(user, config, ctx).await?;

    Ok(SuccessMessageResponse {
        success: true,
        message: "User deleted".to_string(),
    })
}

pub(crate) async fn delete_user_callback_core(
    token: &str,
    current_user: &better_auth_core::User,
    config: &UserManagementConfig,
    ctx: &AuthContext,
) -> AuthResult<SuccessMessageResponse> {
    if let Some(verification) = ctx
        .database
        .get_verification_by_identifier(&format!("delete-account-{token}"))
        .await?
    {
        if verification.expires_at() < Utc::now() || verification.value() != current_user.id() {
            return Err(AuthError::not_found("Invalid token"));
        }

        perform_user_deletion(current_user, config, ctx).await?;
        ctx.database.delete_verification(verification.id()).await?;

        return Ok(SuccessMessageResponse {
            success: true,
            message: "User deleted".to_string(),
        });
    }

    Err(AuthError::not_found("Invalid token"))
}

/// Delete a user together with all their sessions and accounts.
async fn perform_user_deletion(
    user: &better_auth_core::User,
    config: &UserManagementConfig,
    ctx: &AuthContext,
) -> AuthResult<()> {
    let user_info = UserInfo::from_auth_user(user);

    if let Some(ref hook) = config.delete_user.before_delete {
        hook.before_delete(&user_info).await?;
    }

    ctx.database.delete_user_sessions(user.id()).await?;

    let accounts = ctx.database.get_user_accounts(user.id()).await?;
    for account in &accounts {
        ctx.database.delete_account(account.id()).await?;
    }

    ctx.database.delete_user(user.id()).await?;

    if let Some(ref hook) = config.delete_user.after_delete
        && let Err(error) = hook.after_delete(&user_info).await
    {
        tracing::warn!(
            error = %error,
            user_id = %user_info.id,
            "after_delete hook failed (user already deleted)"
        );
    }

    Ok(())
}
