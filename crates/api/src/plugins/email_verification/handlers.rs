use jsonwebtoken::errors::ErrorKind;

use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::helpers::{SessionIssueError, issue_selected_user_session_optional};
use better_auth_core::session::{NativeSessionData, SessionRead};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, FieldMap, FieldValue, UpdateUser,
};

use super::token::{create_email_verification_token, decode_email_verification_token};
use super::types::*;
use super::{EmailVerificationConfig, StatusResponse, VerificationEmail};

fn verification_url(base_url: &str, token: &str, callback_url: Option<&str>) -> String {
    let callback_url = callback_url.filter(|url| !url.is_empty()).unwrap_or("/");
    format!(
        "{base_url}/verify-email?token={token}&callbackURL={}",
        urlencoding::encode(callback_url),
    )
}

async fn send_for_user<S: better_auth_core::AuthSchema>(
    user: FieldValue,
    email: &FieldValue,
    body: &SendVerificationEmailRequest,
    config: &EmailVerificationConfig,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<()> {
    let ctx = endpoint.auth;
    let token = create_email_verification_token(
        ctx.config.signing_secret(),
        &crate::plugins::helpers::user_email_field(email)?,
        None,
        config.verification_token_expiry(),
        None,
    )?;
    let url = verification_url(ctx.base_url(), &token, body.callback_url.as_deref());
    if let Some(task) = super::delivery::delivery(
        Some(config),
        VerificationEmail { user, url, token },
        endpoint,
    )? {
        task.await?;
    }
    Ok(())
}

pub(super) async fn send_verification_email_core(
    body: &SendVerificationEmailRequest,
    req: &AuthRequest,
    config: &EmailVerificationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if !super::delivery::available(Some(config), ctx) {
        return Err(AuthError::bad_request("Verification email isn't enabled"));
    }
    let mut endpoint_body = FieldMap::from([("email".into(), body.email.clone().into())]);
    if let Some(callback_url) = &body.callback_url {
        let _ = endpoint_body.insert("callbackURL".into(), callback_url.clone().into());
    }
    let mut endpoint = EndpointContext::new(Some(req), endpoint_body.into(), ctx);
    endpoint.session = ctx.native_session(req, SessionRead::Cached).await?;
    if let Some(data) = &endpoint.session {
        let email = data.user_property("email")?;
        if crate::plugins::helpers::user_email_field(email)?.to_lowercase()
            != body.email.to_lowercase()
        {
            return Err(AuthError::bad_request("Email mismatch"));
        }
        if data.user_property("emailVerified")?.is_truthy() {
            return Err(AuthError::bad_request("Email is already verified"));
        }
        send_for_user(data.user.clone(), email, body, config, &endpoint).await?;
    } else {
        let start = std::time::Instant::now();
        let user = ctx.database.get_user_by_email(&body.email).await?;
        let result = match user.filter(|user| !user.email_verified.field_value().is_truthy()) {
            Some(user) => {
                let email = user.email.field_value();
                send_for_user(FieldMap::from(user).into(), &email, body, config, &endpoint).await
            }
            None => {
                let _ = create_email_verification_token(
                    ctx.config.signing_secret(),
                    &body.email,
                    None,
                    config.verification_token_expiry(),
                    None,
                )?;
                Ok(())
            }
        };
        // Preserve the upstream timing floor even when delivery fails.
        if let Some(remaining) = std::time::Duration::from_millis(500).checked_sub(start.elapsed())
        {
            tokio::time::sleep(remaining).await;
        }
        result?;
    }
    Ok(StatusResponse { status: true })
}

fn verification_error(
    query: &VerifyEmailQuery,
    code: &'static str,
    message: &'static str,
) -> AuthResult<VerifyEmailResult> {
    if let Some(callback_url) = query.callback_url.as_deref().filter(|url| !url.is_empty()) {
        return Ok(VerifyEmailResult::Redirect {
            url: better_auth_core::utils::url::append_query_params(
                callback_url,
                &format!("error={code}"),
            )?,
        });
    }
    Err(AuthError::Upstream {
        status: 401,
        code,
        message,
    })
}

fn success(query: &VerifyEmailQuery, user: Option<FieldValue>) -> VerifyEmailResult {
    if let Some(url) = query.callback_url.as_ref().filter(|url| !url.is_empty()) {
        return VerifyEmailResult::Redirect { url: url.clone() };
    }
    let mut body = FieldMap::from([("status".into(), true.into())]);
    if let Some(user) = user {
        let _ = body.insert("user".into(), user);
    }
    VerifyEmailResult::Json { body: body.into() }
}

async fn active_session(
    current: Option<NativeSessionData>,
    user: &FieldValue,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<NativeSessionData> {
    if let Some(current) = current {
        return Ok(current);
    }
    issue_selected_user_session_optional(
        ctx,
        user.clone(),
        &better_auth_core::RequestMeta {
            ip_address: ctx.config.advanced.ip_address.resolve(req),
            user_agent: req.headers.get("user-agent").cloned(),
        },
        ctx.config.session.expires_in(),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?
    .ok_or(AuthError::Upstream {
        status: 500,
        code: "FAILED_TO_CREATE_SESSION",
        message: "Failed to create session",
    })
}

pub(super) async fn verify_email_core(
    query: &VerifyEmailQuery,
    config: &EmailVerificationConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<VerifyEmailResult> {
    let claims = match decode_email_verification_token(ctx.config.signing_secret(), &query.token) {
        Ok(claims) => claims,
        Err(AuthError::Jwt(error)) => {
            if matches!(error.kind(), ErrorKind::ExpiredSignature) {
                return verification_error(query, "TOKEN_EXPIRED", "Token expired");
            }
            return verification_error(query, "INVALID_TOKEN", "Invalid token");
        }
        Err(error) => return Err(error),
    };
    let Some(user) = ctx.database.get_user_by_email(&claims.email).await? else {
        return verification_error(query, "USER_NOT_FOUND", "User not found");
    };
    let verified = user.email_verified.field_value().is_truthy();
    let user = FieldValue::from(FieldMap::from(user));
    let email = FieldValue::from(claims.email.clone());
    let mut endpoint = EndpointContext::new(Some(req), FieldValue::Null, ctx);
    if let Some(update_to) = claims
        .update_to
        .as_deref()
        .filter(|email| !email.is_empty())
    {
        endpoint.session = ctx.native_session(req, SessionRead::Cached).await?;
        if let Some(data) = &endpoint.session
            && !data.user_property("email")?.strict_equals(&email)
        {
            return verification_error(query, "INVALID_USER", "Invalid user");
        }
        if claims.request_type.as_deref() == Some("change-email-confirmation") {
            let token = create_email_verification_token(
                ctx.config.signing_secret(),
                &claims.email,
                Some(update_to),
                config.verification_token_expiry(),
                Some("change-email-verification"),
            )?;
            let url = verification_url(ctx.base_url(), &token, query.callback_url.as_deref());
            if super::delivery::available(Some(config), ctx) {
                let mut fields = user.enumerable_fields();
                let _ = fields.insert("email".into(), update_to.into());
                let task = super::delivery::delivery(
                    Some(config),
                    VerificationEmail {
                        user: fields.into(),
                        url,
                        token,
                    },
                    &endpoint,
                )?;
                better_auth_core::background::run_or_await(
                    task,
                    ctx.config.advanced.background_tasks.as_ref(),
                    &ctx.config.logger,
                )
                .await;
            }
            return Ok(success(query, None));
        }
        let mut active = active_session(endpoint.session.clone(), &user, req, ctx).await?;
        let verified = claims.request_type.as_deref() == Some("change-email-verification");
        let updated = ctx
            .database
            .update_user_by_field_value(
                "email",
                &email,
                UpdateUser {
                    email: Some(update_to.into()),
                    email_verified: Some(verified),
                    ..Default::default()
                },
            )
            .await?;
        let updated_value = updated
            .clone()
            .map(|user| FieldMap::from(user).into())
            .unwrap_or(FieldValue::Null);
        if verified {
            if let Some(hook) = &config.after_email_verification {
                hook(&updated_value).await?;
            }
        } else {
            let token = create_email_verification_token(
                ctx.config.signing_secret(),
                update_to,
                None,
                chrono::Duration::hours(1),
                None,
            )?;
            let url = verification_url(ctx.base_url(), &token, query.callback_url.as_deref());
            if super::delivery::available(Some(config), ctx) {
                let task = super::delivery::delivery(
                    Some(config),
                    VerificationEmail {
                        user: updated_value,
                        url,
                        token,
                    },
                    &endpoint,
                )?;
                better_auth_core::background::run_or_await(
                    task,
                    ctx.config.advanced.background_tasks.as_ref(),
                    &ctx.config.logger,
                )
                .await;
            }
        }
        let mut fields = active.user.enumerable_fields();
        let _ = fields.insert("email".into(), update_to.into());
        let _ = fields.insert("emailVerified".into(), verified.into());
        active.user = fields.into();
        ctx.session_manager()
            .set_native_session_cookie(req, active, None)
            .await?;
        // Redirects precede public projection, so projection errors cannot replace the redirect.
        if query
            .callback_url
            .as_ref()
            .is_some_and(|url| !url.is_empty())
        {
            return Ok(success(query, None));
        }
        let output = match updated {
            Some(user) => FieldMap::from(ctx.user_view(&user).await?).into(),
            None => FieldValue::Null,
        };
        return Ok(success(query, Some(output)));
    }
    if verified {
        return Ok(success(query, Some(FieldValue::Null)));
    }
    if let Some(hook) = &config.before_email_verification {
        hook(&user).await?;
    }
    let updated = ctx
        .database
        .update_user_by_field_value(
            "email",
            &email,
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    if let Some(hook) = &config.after_email_verification {
        let updated = updated
            .map(|user| FieldMap::from(user).into())
            .unwrap_or(FieldValue::Null);
        hook(&updated).await?;
    }
    if config.auto_sign_in_after_verification {
        let current = ctx.native_session(req, SessionRead::Cached).await?;
        let current = match current {
            Some(data) if data.user_property("email")?.strict_equals(&email) => Some(data),
            _ => None,
        };
        let mut data = active_session(current, &user, req, ctx).await?;
        let mut fields = data.user.enumerable_fields();
        let _ = fields.insert("emailVerified".into(), true.into());
        data.user = fields.into();
        ctx.session_manager()
            .set_native_session_cookie(req, data, None)
            .await?;
    }
    Ok(success(query, Some(FieldValue::Null)))
}
