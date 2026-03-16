use jsonwebtoken::errors::ErrorKind;

use better_auth_core::{AuthContext, AuthError, AuthResult, UpdateUser};
use better_auth_core::{AuthSession, AuthUser};

use super::token::{create_email_verification_token, decode_email_verification_token};
use super::types::*;
use super::{EmailVerificationConfig, StatusResponse};

fn verification_url(base_url: &str, token: &str, callback_url: Option<&str>) -> String {
    let callback_url = callback_url.unwrap_or("/");
    format!(
        "{base_url}/verify-email?token={token}&callbackURL={}",
        urlencoding::encode(callback_url),
    )
}

pub(super) async fn send_verification_email_core(
    body: &SendVerificationEmailRequest,
    current_user: Option<&better_auth_core::User>,
    config: &EmailVerificationConfig,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    if config.send_verification_email.is_none() {
        return Err(AuthError::bad_request("Verification email isn't enabled"));
    }

    match current_user {
        Some(user) => {
            let session_email = user.email().unwrap_or_default();
            if session_email != body.email {
                return Err(AuthError::bad_request("Email mismatch"));
            }
            if user.email_verified() {
                return Err(AuthError::bad_request("Email is already verified"));
            }

            let token = create_email_verification_token(
                &ctx.config.secret,
                &body.email,
                None,
                config.verification_token_expiry,
                None,
            )?;
            let url = verification_url(&ctx.config.base_url, &token, body.callback_url.as_deref());
            let user = better_auth_core::User::from(user);
            if let Some(ref sender) = config.send_verification_email {
                sender.send(&user, &url, &token).await?;
            }
        }
        None => {
            let user = match ctx.database.get_user_by_email(&body.email).await? {
                Some(user) => user,
                None => return Ok(StatusResponse { status: true }),
            };

            if user.email_verified() {
                let _ = create_email_verification_token(
                    &ctx.config.secret,
                    &body.email,
                    None,
                    config.verification_token_expiry,
                    None,
                )?;
                return Ok(StatusResponse { status: true });
            }

            let token = create_email_verification_token(
                &ctx.config.secret,
                &body.email,
                None,
                config.verification_token_expiry,
                None,
            )?;
            let url = verification_url(&ctx.config.base_url, &token, body.callback_url.as_deref());
            let user = better_auth_core::User::from(&user);
            if let Some(ref sender) = config.send_verification_email {
                sender.send(&user, &url, &token).await?;
            }
        }
    }

    Ok(StatusResponse { status: true })
}

fn redirect_url(callback_url: &str, error: Option<&str>) -> String {
    match error {
        Some(error) if callback_url.contains('?') => format!("{callback_url}&error={error}"),
        Some(error) => format!("{callback_url}?error={error}"),
        None => callback_url.to_string(),
    }
}

pub(super) async fn verify_email_core(
    query: &VerifyEmailQuery,
    current_session: Option<(better_auth_core::User, better_auth_core::Session)>,
    config: &EmailVerificationConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext,
) -> AuthResult<VerifyEmailResult> {
    let claims = match decode_email_verification_token(&ctx.config.secret, &query.token) {
        Ok(claims) => claims,
        Err(AuthError::Jwt(error)) => {
            if matches!(
                error.kind(),
                ErrorKind::InvalidToken
                    | ErrorKind::InvalidSignature
                    | ErrorKind::InvalidAlgorithm
                    | ErrorKind::MissingRequiredClaim(_)
                    | ErrorKind::ExpiredSignature
            ) {
                if let Some(callback_url) = query.callback_url.as_deref() {
                    let error_code = if matches!(error.kind(), ErrorKind::ExpiredSignature) {
                        "token_expired"
                    } else {
                        "invalid_token"
                    };
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, Some(error_code)),
                        session_token: None,
                    });
                }

                let error_code = if matches!(error.kind(), ErrorKind::ExpiredSignature) {
                    "token_expired"
                } else {
                    "invalid_token"
                };
                return Err(AuthError::bad_request(error_code));
            }

            return Err(AuthError::Jwt(error));
        }
        Err(error) => return Err(error),
    };

    let user = ctx
        .database
        .get_user_by_email(&claims.email)
        .await?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    if let Some(update_to) = claims.update_to.as_deref() {
        if let Some((ref session_user, _)) = current_session
            && session_user.email().unwrap_or_default() != claims.email
        {
            return Err(AuthError::bad_request("unauthorized"));
        }

        match claims.request_type.as_deref() {
            Some("change-email-confirmation") => {
                let new_token = create_email_verification_token(
                    &ctx.config.secret,
                    &claims.email,
                    Some(update_to),
                    config.verification_token_expiry,
                    Some("change-email-verification"),
                )?;
                let url = verification_url(
                    &ctx.config.base_url,
                    &new_token,
                    query.callback_url.as_deref(),
                );
                if let Some(ref sender) = config.send_verification_email {
                    let mut updated_user = better_auth_core::User::from(&user);
                    updated_user.email = Some(update_to.to_string());
                    sender.send(&updated_user, &url, &new_token).await?;
                }

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: None,
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({ "status": true }),
                    session_token: None,
                });
            }
            Some("change-email-verification") => {
                let (session_user, session) = match current_session {
                    Some((user, session)) => (user, session),
                    None => {
                        let session = ctx
                            .session_manager()
                            .create_session(&user, ip_address, user_agent)
                            .await?;
                        (user.clone(), session)
                    }
                };

                let updated_user = ctx
                    .database
                    .update_user(
                        user.id(),
                        UpdateUser {
                            email: Some(update_to.to_string()),
                            email_verified: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?;

                if let Some(ref hook) = config.after_email_verification {
                    let hook_user = better_auth_core::User::from(&updated_user);
                    hook(&hook_user).await?;
                }

                let _session_user = better_auth_core::User {
                    email: Some(update_to.to_string()),
                    email_verified: true,
                    ..session_user
                };

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: Some(session.token().to_string()),
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({
                        "status": true,
                        "user": updated_user,
                    }),
                    session_token: Some(session.token().to_string()),
                });
            }
            _ => {
                let updated_user = ctx
                    .database
                    .update_user(
                        user.id(),
                        UpdateUser {
                            email: Some(update_to.to_string()),
                            email_verified: Some(false),
                            ..Default::default()
                        },
                    )
                    .await?;
                let new_token = create_email_verification_token(
                    &ctx.config.secret,
                    update_to,
                    None,
                    config.verification_token_expiry,
                    None,
                )?;
                let url = verification_url(
                    &ctx.config.base_url,
                    &new_token,
                    query.callback_url.as_deref(),
                );
                if let Some(ref sender) = config.send_verification_email {
                    sender.send(&updated_user, &url, &new_token).await?;
                }

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: None,
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({
                        "status": true,
                        "user": updated_user,
                    }),
                    session_token: None,
                });
            }
        }
    }

    if user.email_verified() {
        if let Some(callback_url) = query.callback_url.as_deref() {
            return Ok(VerifyEmailResult::Redirect {
                url: redirect_url(callback_url, None),
                session_token: None,
            });
        }

        return Ok(VerifyEmailResult::Json {
            body: serde_json::json!({ "status": true, "user": serde_json::Value::Null }),
            session_token: None,
        });
    }

    if let Some(ref hook) = config.before_email_verification {
        let hook_user = better_auth_core::User::from(&user);
        hook(&hook_user).await?;
    }

    let updated_user = ctx
        .database
        .update_user(
            user.id(),
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;

    if let Some(ref hook) = config.after_email_verification {
        let hook_user = better_auth_core::User::from(&updated_user);
        hook(&hook_user).await?;
    }

    let session_token = if config.auto_sign_in_after_verification {
        if let Some((session_user, session)) = current_session {
            if session_user.email().unwrap_or_default() == claims.email {
                Some(session.token().to_string())
            } else {
                Some(
                    ctx.session_manager()
                        .create_session(&user, ip_address, user_agent)
                        .await?
                        .token()
                        .to_string(),
                )
            }
        } else {
            Some(
                ctx.session_manager()
                    .create_session(&user, ip_address, user_agent)
                    .await?
                    .token()
                    .to_string(),
            )
        }
    } else {
        None
    };

    if let Some(callback_url) = query.callback_url.as_deref() {
        return Ok(VerifyEmailResult::Redirect {
            url: redirect_url(callback_url, None),
            session_token,
        });
    }

    Ok(VerifyEmailResult::Json {
        body: serde_json::json!({ "status": true, "user": serde_json::Value::Null }),
        session_token,
    })
}
