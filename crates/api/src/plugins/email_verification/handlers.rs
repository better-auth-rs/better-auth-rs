use chrono::Utc;
use uuid::Uuid;

use better_auth_core::User;
use better_auth_core::{AuthContext, AuthResult};
use better_auth_core::{AuthError, CreateVerification, UpdateUser};
use better_auth_core::{AuthSession, AuthUser, AuthVerification, DatabaseAdapter, SessionManager};

use super::types::*;
use super::{EmailVerificationConfig, StatusResponse};

pub(super) async fn send_verification_email_core<DB: DatabaseAdapter>(
    body: &SendVerificationEmailRequest,
    config: &EmailVerificationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Check if user exists
    let user = ctx
        .database
        .get_user_by_email(&body.email)
        .await?
        .ok_or_else(|| AuthError::not_found("No user found with this email address"))?;

    // Check if user is already verified
    if user.email_verified() {
        return Err(AuthError::bad_request("Email is already verified"));
    }

    // Generate verification token
    let verification_token = format!("verify_{}", Uuid::new_v4());
    let expires_at = Utc::now() + config.verification_token_expiry;

    let create_verification = CreateVerification {
        identifier: body.email.to_string(),
        value: verification_token.clone(),
        expires_at,
    };

    ctx.database
        .create_verification(create_verification)
        .await?;

    let verification_url = if let Some(ref callback_url) = body.callback_url {
        format!("{}?token={}", callback_url, verification_token)
    } else {
        format!(
            "{}/verify-email?token={}",
            ctx.config.base_url, verification_token
        )
    };

    // Use custom sender if configured, otherwise fall back to EmailProvider
    if let Some(ref custom_sender) = config.send_verification_email {
        let user = User::from(&user);
        custom_sender
            .send(&user, &verification_url, &verification_token)
            .await?;
    } else if config.send_email_notifications {
        if ctx.email_provider.is_some() {
            let subject = "Verify your email address";
            let html = format!(
                "<p>Click the link below to verify your email address:</p>\
                 <p><a href=\"{url}\">Verify Email</a></p>",
                url = verification_url
            );
            let text = format!("Verify your email address: {}", verification_url);

            ctx.email_provider()?
                .send(&body.email, subject, &html, &text)
                .await?;
        } else {
            tracing::warn!(
                email = %body.email,
                "No email provider configured, skipping verification email"
            );
        }
    }

    Ok(StatusResponse { status: true })
}

pub(super) async fn verify_email_core<DB: DatabaseAdapter>(
    query: &VerifyEmailQuery,
    config: &EmailVerificationConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<DB>,
) -> AuthResult<VerifyEmailResult<DB::User, DB::Session>> {
    // Find verification token
    let verification = ctx
        .database
        .get_verification_by_value(&query.token)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired verification token"))?;

    // Get user by email (stored in identifier field)
    let user = ctx
        .database
        .get_user_by_email(verification.identifier())
        .await?
        .ok_or_else(|| AuthError::not_found("User associated with this token not found"))?;

    // Check if already verified
    if user.email_verified() {
        return Ok(VerifyEmailResult::AlreadyVerified(VerifyEmailResponse {
            user,
            status: true,
        }));
    }

    // Run before_email_verification hook
    if let Some(ref hook) = config.before_email_verification {
        let hook_user = User::from(&user);
        hook(&hook_user).await?;
    }

    // Update user email verification status
    let update_user = UpdateUser {
        email_verified: Some(true),
        ..Default::default()
    };

    let updated_user = ctx.database.update_user(user.id(), update_user).await?;

    // Delete the used verification token
    ctx.database.delete_verification(verification.id()).await?;

    // Run after_email_verification hook
    if let Some(ref hook) = config.after_email_verification {
        let hook_user = User::from(&updated_user);
        hook(&hook_user).await?;
    }

    // Optionally create a session when auto_sign_in_after_verification is enabled.
    let session_info = if config.auto_sign_in_after_verification {
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager
            .create_session(&updated_user, ip_address, user_agent)
            .await?;
        let token = session.token().to_string();
        Some((session, token))
    } else {
        None
    };

    // If callback URL is provided, redirect
    if let Some(ref callback_url) = query.callback_url {
        let redirect_url = format!("{}?verified=true", callback_url);
        return Ok(VerifyEmailResult::Redirect {
            url: redirect_url,
            session_token: session_info.map(|(_, t)| t),
        });
    }

    // Return JSON
    match session_info {
        Some((session, token)) => Ok(VerifyEmailResult::JsonWithSession {
            response: VerifyEmailWithSessionResponse {
                user: updated_user,
                session,
                status: true,
            },
            session_token: token,
        }),
        None => Ok(VerifyEmailResult::Json(VerifyEmailResponse {
            user: updated_user,
            status: true,
        })),
    }
}
