use chrono::{Duration, Utc};

use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::utils::password as password_utils;
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, StatusResponse, UpdateUser,
};

use super::types::{ChangeEmailRequest, DeleteUserRequest};
use super::{UserInfo, UserManagementConfig};
use crate::plugins::email_verification::token::create_email_verification_token;
use better_auth_core::SuccessMessageResponse;

/// Send an email using the configured email provider, logging on failure.
pub(super) async fn send_email_or_log(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
    user: &impl AuthUser,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
        let _ = ctx.database.update_user(&user.id(), update_user).await?;

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
        ctx.config.signing_secret(),
        user.email().unwrap_or_default(),
        Some(&new_email),
        Duration::hours(24),
        Some(request_type),
    )?;
    let verification_url = format!(
        "{}/verify-email?token={}&callbackURL={}",
        ctx.base_url(),
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
    user: &UserView,
    session: &impl AuthSession,
    req: &AuthRequest,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessMessageResponse> {
    if let Some(password) = body
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        ctx.password_policy.validate_max_length(password)?;
        let stored_hash = super::super::helpers::get_credential_password_hash(ctx, user)
            .await?
            .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
        password_utils::verify_password(
            ctx.password_policy.hasher.as_ref(),
            password,
            &stored_hash,
        )
        .await
        .map_err(|_| AuthError::bad_request("Invalid password"))?;
    }

    if let Some(token) = body.token.as_deref().filter(|token| !token.is_empty()) {
        let (user, _) = ctx.require_authoritative_session(req).await?;
        let _ = delete_user_callback_core(token, &user, req, config, ctx).await?;
        return Ok(SuccessMessageResponse {
            success: true,
            message: "User deleted".to_string(),
        });
    }

    if let Some(sender) = &config.delete_user.send_delete_account_verification {
        let token = uuid::Uuid::new_v4().simple().to_string();
        let expires_in = if config.delete_user.delete_token_expires_in.is_zero() {
            Duration::hours(24)
        } else {
            config.delete_user.delete_token_expires_in
        };
        let _ = ctx
            .database
            .create_verification(better_auth_core::CreateVerification {
                identifier: (format!("delete-account-{token}")).into(),
                value: (user.id.to_owned()).into(),
                expires_at: (Utc::now()
                    .checked_add_signed(expires_in)
                    .ok_or_else(|| AuthError::config("Delete token expiry is out of range"))?)
                .into(),
                ..Default::default()
            })
            .await?;
        let url = format!(
            "{}/delete-user/callback?token={}&callbackURL={}",
            ctx.base_url(),
            token,
            urlencoding::encode(body.callback_url.as_deref().unwrap_or("/")),
        );
        // Upstream runInBackgroundOrAwait logs notification failures after storing the token.
        if let Err(error) = sender.send(user, &url, &token, Some(req)).await {
            tracing::error!(%error, "Delete account verification sender failed");
        }
        return Ok(SuccessMessageResponse {
            success: true,
            message: "Verification email sent".into(),
        });
    }

    if body.password.as_deref().is_none_or(str::is_empty)
        && !crate::plugins::helpers::session_is_fresh(session, &ctx.config)
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "SESSION_EXPIRED",
            message: "Session expired. Re-authenticate to perform this action.",
        });
    }
    perform_user_deletion(user, req, config, ctx).await?;

    Ok(SuccessMessageResponse {
        success: true,
        message: "User deleted".to_string(),
    })
}

pub(crate) async fn delete_user_callback_core(
    token: &str,
    current_user: &UserView,
    req: &AuthRequest,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessMessageResponse> {
    let verification = ctx
        .database
        .consume_verification_by_identifier(&format!("delete-account-{token}"))
        .await?
        .ok_or_else(|| AuthError::not_found("Invalid token"))?;
    if verification.value != current_user.id {
        return Err(AuthError::not_found("Invalid token"));
    }
    perform_user_deletion(current_user, req, config, ctx).await?;
    Ok(SuccessMessageResponse {
        success: true,
        message: "User deleted".into(),
    })
}

async fn perform_user_deletion(
    user: &UserView,
    req: &AuthRequest,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if let Some(hook) = &config.delete_user.before_delete {
        hook.before_delete(user, Some(req)).await?;
    }
    ctx.database.delete_user_sessions(&user.id).await?;
    for account in ctx.database.get_user_accounts(&user.id).await? {
        ctx.database.delete_account(account.id.typed()?).await?;
    }
    ctx.database.delete_user(&user.id).await?;
    // Queue revocation before the application hook so error responses also clear credentials.
    ctx.session_manager().clear_cookies(req)?;
    if let Some(hook) = &config.delete_user.after_delete {
        hook.after_delete(user, Some(req)).await?;
    }
    Ok(())
}
