use chrono::{Duration, Utc};

use better_auth_core::entity::AuthSession;
use better_auth_core::utils::password as password_utils;
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, StatusResponse, UpdateUser,
};

use super::UserManagementConfig;
use super::types::{ChangeEmailRequest, DeleteUserRequest};
use crate::plugins::email_verification::token::create_email_verification_token;
use better_auth_core::SuccessMessageResponse;

pub(crate) async fn change_email_core(
    body: &ChangeEmailRequest,
    user: &UserView,
    session: &better_auth_core::wire::SessionView,
    req: &AuthRequest,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if !config.change_email.enabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "CHANGE_EMAIL_DISABLED",
            message: "Change email is disabled",
        });
    }
    let new_email = body.new_email.to_lowercase();
    if user.email.as_deref() == Some(new_email.as_str()) {
        return Err(AuthError::bad_request("Email is the same"));
    }
    let verification = ctx
        .extensions
        .get::<crate::plugins::email_verification::EmailVerificationConfig>();
    let sender = verification
        .and_then(|options| options.send_verification_email.as_ref())
        .or(ctx.email_verification_policy.override_sender.as_ref());
    let provider = verification
        .filter(|options| options.send_email_notifications)
        .and(ctx.email_provider.as_ref());
    let can_send = sender.is_some() || provider.is_some();
    let update_now = !user.email_verified && config.change_email.update_without_verification;
    if !update_now && !can_send {
        return Err(better_auth_core::AuthResponse::json(
            400,
            &serde_json::json!({"message":"Verification email isn't enabled"}),
        )?
        .into());
    }
    let expires_in = verification.map_or(Duration::hours(1), |options| {
        options.verification_token_expiry
    });
    let old_email = user.email.as_deref().unwrap_or_default();
    if ctx.database.get_user_by_email(&new_email).await?.is_some() {
        let _ = create_email_verification_token(
            ctx.config.signing_secret(),
            old_email,
            Some(&new_email),
            expires_in,
            None,
        )?;
        return Ok(StatusResponse { status: true });
    }
    let confirmation = config
        .change_email
        .send_change_email_confirmation
        .as_ref()
        .filter(|_| user.email_verified && can_send);
    let mut recipient = user.clone();
    if update_now {
        let _ = ctx
            .database
            .update_user_optional(
                user.id.typed()?,
                UpdateUser {
                    email: Some(new_email.clone()),
                    ..Default::default()
                },
            )
            .await?;
        recipient.email = Some(new_email.clone());
        ctx.session_manager()
            .set_session_cookie(
                req,
                better_auth_core::session::SessionData {
                    user: recipient.clone(),
                    session: session.clone(),
                },
                None,
            )
            .await?;
        if !can_send {
            return Ok(StatusResponse { status: true });
        }
    }
    let (email, update_to, request_type) = if update_now {
        (new_email.as_str(), None, None)
    } else if confirmation.is_some() {
        (
            old_email,
            Some(new_email.as_str()),
            Some("change-email-confirmation"),
        )
    } else {
        recipient.email = Some(new_email.clone());
        (
            old_email,
            Some(new_email.as_str()),
            Some("change-email-verification"),
        )
    };
    let token = create_email_verification_token(
        ctx.config.signing_secret(),
        email,
        update_to,
        expires_in,
        request_type,
    )?;
    let callback = body
        .callback_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .unwrap_or("/");
    let url = format!(
        "{}/verify-email?token={}&callbackURL={}",
        ctx.base_url(),
        token,
        urlencoding::encode(callback)
    );
    let delivered = if let Some(confirmation) = confirmation {
        confirmation.send(user, &new_email, &url, &token).await
    } else if let Some(sender) = sender {
        sender.send(&recipient, &url, &token).await
    } else if let Some(provider) = provider {
        let html = format!("<p><a href=\"{url}\">Verify Email</a></p>");
        let text = format!("Verify your email address: {url}");
        provider
            .send(&new_email, "Verify your email address", &html, &text)
            .await
    } else {
        return Err(AuthError::config(
            "Email verification sender became unavailable",
        ));
    };
    // Upstream runInBackgroundOrAwait logs asynchronous delivery errors after the write and cookie.
    if let Err(error) = delivered {
        better_auth_core::observability::logger::current().error(
            "Failed to run background task",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
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
                value: user.id.clone(),
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
            better_auth_core::observability::logger::current().error(
                "Delete account verification sender failed",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
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
    ctx.database.delete_user_sessions(user.id.typed()?).await?;
    for account in ctx.database.get_user_accounts(user.id.typed()?).await? {
        ctx.database.delete_account(account.id.typed()?).await?;
    }
    ctx.database.delete_user(user.id.typed()?).await?;
    // Queue revocation before the application hook so error responses also clear credentials.
    ctx.session_manager().clear_cookies(req)?;
    if let Some(hook) = &config.delete_user.after_delete {
        hook.after_delete(user, Some(req)).await?;
    }
    Ok(())
}
