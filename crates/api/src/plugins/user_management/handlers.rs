use chrono::{Duration, Utc};
use uuid::Uuid;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthUser, AuthVerification};
use better_auth_core::{AuthContext, AuthError, AuthResult, UpdateUser};

use super::types::StatusMessageResponse;
use super::{UserInfo, UserManagementConfig};

// ---------------------------------------------------------------------------
// Shared helpers (DRY: token creation, token verification, email sending)
// ---------------------------------------------------------------------------

/// Create a verification token, persist it, and return `(token_value, verification_url)`.
pub(super) async fn create_verification_token<DB: DatabaseAdapter>(
    ctx: &AuthContext<DB>,
    identifier: &str,
    token_prefix: &str,
    expires_at: chrono::DateTime<Utc>,
    callback_url: Option<&str>,
    default_path: &str,
) -> AuthResult<(String, String)> {
    let token_value = format!("{}_{}", token_prefix, Uuid::new_v4());

    let create_verification = better_auth_core::CreateVerification {
        identifier: identifier.to_string(),
        value: token_value.clone(),
        expires_at,
    };

    ctx.database
        .create_verification(create_verification)
        .await?;

    let verification_url = if let Some(cb_url) = callback_url {
        format!("{}?token={}", cb_url, token_value)
    } else {
        format!(
            "{}/{}?token={}",
            ctx.config.base_url, default_path, token_value
        )
    };

    Ok((token_value, verification_url))
}

/// Send an email using the configured email provider, logging on failure.
pub(super) async fn send_email_or_log<DB: DatabaseAdapter>(
    ctx: &AuthContext<DB>,
    to: &str,
    subject: &str,
    html: &str,
    text: &str,
    action: &str,
) {
    if let Ok(provider) = ctx.email_provider() {
        if let Err(e) = provider.send(to, subject, html, text).await {
            tracing::warn!(
                plugin = "user-management",
                action = action,
                email = to,
                error = %e,
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

// ---------------------------------------------------------------------------
// Core functions (framework-agnostic business logic)
// ---------------------------------------------------------------------------

pub(crate) async fn change_email_core<DB: DatabaseAdapter>(
    body: &super::types::ChangeEmailRequest,
    user: &DB::User,
    config: &UserManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusMessageResponse> {
    // Prevent changing to the same email
    if user.email().map(|e| e == body.new_email).unwrap_or(false) {
        return Err(AuthError::bad_request(
            "New email must be different from the current email",
        ));
    }

    // Check if the new email is already in use
    if ctx
        .database
        .get_user_by_email(&body.new_email)
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request(
            "Email is already in use by another account",
        ));
    }

    // If update_without_verification is true, update the email immediately
    if config.change_email.update_without_verification {
        let update_user = UpdateUser {
            email: Some(body.new_email.clone()),
            email_verified: Some(false),
            ..Default::default()
        };
        ctx.database.update_user(user.id(), update_user).await?;

        return Ok(StatusMessageResponse {
            status: true,
            message: "Email updated successfully".to_string(),
        });
    }

    // Create verification token
    let identifier = format!("change_email:{}:{}", user.id(), body.new_email);
    let expires_at = Utc::now() + Duration::hours(24);
    let (verification_token, verification_url) = create_verification_token(
        ctx,
        &identifier,
        "ce",
        expires_at,
        body.callback_url.as_deref(),
        "change-email/verify",
    )
    .await?;

    // Send confirmation email via custom callback or default provider
    if let Some(ref cb) = config.change_email.send_change_email_confirmation {
        let user_info = UserInfo::from_auth_user(user);
        cb.send(
            &user_info,
            &body.new_email,
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

        send_email_or_log(ctx, &body.new_email, subject, &html, &text, "change-email").await;
    }

    Ok(StatusMessageResponse {
        status: true,
        message: "Verification email sent to your new email address".to_string(),
    })
}

pub(crate) async fn change_email_verify_core<DB: DatabaseAdapter>(
    token: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusMessageResponse> {
    // Find verification by token value
    let verification = ctx
        .database
        .get_verification_by_value(token)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired verification token"))?;

    if verification.expires_at() < Utc::now() {
        ctx.database.delete_verification(verification.id()).await?;
        return Err(AuthError::bad_request("Verification token has expired"));
    }

    let identifier = verification.identifier();
    let parts: Vec<String> = identifier.splitn(3, ':').map(|s| s.to_string()).collect();
    if parts.len() != 3 || parts[0] != "change_email" {
        return Err(AuthError::bad_request("Invalid verification token"));
    }

    let user_id = &parts[1];
    let new_email = &parts[2];
    let verification_id = verification.id().to_string();

    // Fetch the user
    let user = ctx
        .database
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    // Check if the new email is still available
    if ctx.database.get_user_by_email(new_email).await?.is_some() {
        ctx.database.delete_verification(&verification_id).await?;
        return Err(AuthError::bad_request(
            "Email is already in use by another account",
        ));
    }

    let update_user = UpdateUser {
        email: Some(new_email.to_string()),
        email_verified: Some(true),
        ..Default::default()
    };

    ctx.database.update_user(user.id(), update_user).await?;

    // Consume the verification token
    ctx.database.delete_verification(&verification_id).await?;

    Ok(StatusMessageResponse {
        status: true,
        message: "Email updated successfully".to_string(),
    })
}

pub(crate) async fn delete_user_core<DB: DatabaseAdapter>(
    user: &DB::User,
    config: &UserManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusMessageResponse> {
    if config.delete_user.require_verification {
        // Verification requires a valid email to send the token to.
        let email = user.email().filter(|e| !e.is_empty()).ok_or_else(|| {
            AuthError::bad_request("Cannot send verification email: user has no email address")
        })?;
        let email = email.to_string();

        let identifier = format!("delete_user:{}", user.id());
        let expires_at = Utc::now() + config.delete_user.delete_token_expires_in;
        let (_delete_token, verification_url) = create_verification_token(
            ctx,
            &identifier,
            "del",
            expires_at,
            None,
            "delete-user/verify",
        )
        .await?;

        // Send confirmation email
        let subject = "Confirm account deletion";
        let html = format!(
            "<p>Click the link below to confirm the deletion of your account:</p>\
             <p><a href=\"{url}\">Confirm Account Deletion</a></p>\
             <p>If you did not request this, please ignore this email.</p>",
            url = verification_url
        );
        let text = format!("Confirm account deletion: {}", verification_url);

        send_email_or_log(ctx, &email, subject, &html, &text, "delete-user").await;

        Ok(StatusMessageResponse {
            status: true,
            message: "Verification email sent. Please confirm to delete your account.".to_string(),
        })
    } else {
        // Immediate deletion (no verification required)
        perform_user_deletion(user, config, ctx).await?;

        Ok(StatusMessageResponse {
            status: true,
            message: "Account deleted successfully".to_string(),
        })
    }
}

pub(crate) async fn delete_user_verify_core<DB: DatabaseAdapter>(
    token: &str,
    config: &UserManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusMessageResponse> {
    // Find verification by token value
    let verification = ctx
        .database
        .get_verification_by_value(token)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired verification token"))?;

    if verification.expires_at() < Utc::now() {
        ctx.database.delete_verification(verification.id()).await?;
        return Err(AuthError::bad_request("Verification token has expired"));
    }

    let identifier = verification.identifier();
    let parts: Vec<String> = identifier.splitn(2, ':').map(|s| s.to_string()).collect();
    if parts.len() != 2 || parts[0] != "delete_user" {
        return Err(AuthError::bad_request("Invalid verification token"));
    }

    let user_id = &parts[1];
    let verification_id = verification.id().to_string();

    // Fetch the user
    let user = ctx
        .database
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    // Perform the actual deletion first, then consume the token.
    perform_user_deletion(&user, config, ctx).await?;

    // Consume the verification token after successful deletion
    ctx.database.delete_verification(&verification_id).await?;

    Ok(StatusMessageResponse {
        status: true,
        message: "Account deleted successfully".to_string(),
    })
}

/// Delete a user together with all their sessions and accounts.
async fn perform_user_deletion<DB: DatabaseAdapter>(
    user: &DB::User,
    config: &UserManagementConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<()> {
    let user_info = UserInfo::from_auth_user(user);

    // before_delete hook
    if let Some(ref hook) = config.delete_user.before_delete {
        hook.before_delete(&user_info).await?;
    }

    // Delete all sessions
    ctx.database.delete_user_sessions(user.id()).await?;

    // Delete all linked accounts
    let accounts = ctx.database.get_user_accounts(user.id()).await?;
    for account in &accounts {
        use better_auth_core::entity::AuthAccount;
        ctx.database.delete_account(account.id()).await?;
    }

    // Delete the user record
    ctx.database.delete_user(user.id()).await?;

    // after_delete hook (non-fatal)
    if let Some(ref hook) = config.delete_user.after_delete
        && let Err(e) = hook.after_delete(&user_info).await
    {
        tracing::warn!(
            error = %e,
            user_id = %user_info.id,
            "after_delete hook failed (user already deleted)"
        );
    }

    Ok(())
}
