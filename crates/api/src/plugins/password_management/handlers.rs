use chrono::Utc;
use url::Url;
use uuid::Uuid;

use better_auth_core::utils::password::{self as password_utils};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthResult, AuthUser, CreateAccount, RequestMeta, UpdateAccount,
};

use crate::plugins::helpers::{
    SessionIssueError, get_credential_account, get_credential_password_hash,
    issue_selected_user_session_optional,
};

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
    req: &better_auth_core::AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<RequestPasswordResetResponse> {
    if let Some(redirect_to) = &body.redirect_to {
        validate_redirect_target(redirect_to, ctx, "Invalid redirectURL")?;
    }

    super::callbacks::require_sender(config, ctx)?;

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
            better_auth_core::observability::logger::current().error(
                "Reset Password: User not found",
                &[better_auth_core::observability::LogArgument::Value(
                    &serde_json::json!(body.email),
                )],
            );
            return Ok(success);
        }
    };

    let reset_token = Uuid::new_v4().simple().to_string();
    let expires_at = config.reset_token_expires_at(Utc::now())?;

    let _ = ctx
        .database
        .create_verification_optional(better_auth_core::CreateVerification {
            identifier: (format!("reset-password:{}", reset_token)).into(),
            value: user.id().into_owned(),
            expires_at: (expires_at).into(),
            ..Default::default()
        })
        .await?;

    let callback_url = body
        .redirect_to
        .as_deref()
        .map(urlencoding::encode)
        .unwrap_or_default();
    let reset_url = format!(
        "{}/reset-password/{}?callbackURL={}",
        ctx.base_url(),
        reset_token,
        callback_url
    );

    let mut parsed = serde_json::Map::from_iter([("email".into(), serde_json::json!(body.email))]);
    if let Some(redirect) = &body.redirect_to {
        let _ = parsed.insert("redirectTo".into(), serde_json::json!(redirect));
    }
    let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        better_auth_core::FieldValue::from_json(parsed.into())?,
        ctx,
    );
    let task = super::callbacks::delivery(
        config,
        super::PasswordResetEmail {
            user: ctx.internal_user_view(&user).await?,
            url: reset_url,
            token: reset_token,
        },
        &endpoint,
    )?;
    better_auth_core::background::run_or_await(
        task,
        ctx.config.advanced.background_tasks.as_ref(),
        &ctx.config.logger,
    )
    .await;

    Ok(success)
}

pub(crate) async fn reset_password_core(
    body: &ResetPasswordRequest,
    req: &better_auth_core::AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let token = body.token.as_deref().unwrap_or("");
    if token.is_empty() {
        return Err(AuthError::bad_request("Invalid token"));
    }
    password_utils::validate_password(
        &body.new_password,
        ctx.password_policy.min_length,
        ctx.password_policy.max_length,
        ctx,
    )?;

    let verification = ctx
        .database
        .consume_verification_by_identifier(&format!("reset-password:{}", token))
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid token"))?;
    let user_id = verification.value.typed()?.clone();

    let user = ctx
        .database
        .get_user_by_id(&user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("User not found"))?;

    let password_hash =
        password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.new_password)
            .await?;

    if get_credential_account(ctx, user_id.as_str())
        .await?
        .is_some()
    {
        crate::plugins::helpers::update_password(ctx, &user_id.as_str().into(), password_hash)
            .await?;
    } else {
        let _ = ctx
            .database
            .create_account_optional(CreateAccount {
                user_id: (user_id.clone()).into(),
                account_id: (user_id.clone()).into(),
                provider_id: ("credential".to_string()).into(),
                access_token: Default::default(),
                refresh_token: Default::default(),
                id_token: Default::default(),
                access_token_expires_at: Default::default(),
                refresh_token_expires_at: Default::default(),
                scope: Default::default(),
                password: (Some(password_hash))
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                ..Default::default()
            })
            .await?;
    }

    if let Some(callback) = &ctx.password_policy.on_password_reset {
        callback(super::PasswordResetEvent {
            user: ctx.internal_user_view(&user).await?,
            request: Some(req.clone()),
        })
        .await?;
    }

    if ctx.password_policy.revoke_sessions_on_password_reset {
        ctx.database.delete_user_sessions(&user_id).await?;
    }

    Ok(StatusResponse { status: true })
}

pub(crate) async fn reset_password_token_core(
    token: &str,
    query: &ResetPasswordTokenQuery,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ResetPasswordTokenResult> {
    if let Some(callback_url) = &query.callback_url {
        validate_redirect_target(callback_url, ctx, "Invalid callbackURL")?;
    }

    if token.is_empty() || query.callback_url.is_none() {
        return Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
            ctx.base_url(),
            query.callback_url.as_deref(),
            &[("error", "INVALID_TOKEN")],
        )?));
    }

    let verification = ctx
        .database
        .get_verification_by_identifier(&format!("reset-password:{}", token))
        .await?;

    let expired = match &verification {
        Some(verification) => verification.expires_at.is_before(Utc::now())?,
        None => true,
    };
    if expired {
        return Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
            ctx.base_url(),
            query.callback_url.as_deref(),
            &[("error", "INVALID_TOKEN")],
        )?));
    }

    Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
        ctx.base_url(),
        query.callback_url.as_deref(),
        &[("token", token)],
    )?))
}

/// Change the password before revoking sessions and issuing replacement credentials.
pub(crate) async fn change_password_core(
    body: &ChangePasswordRequest,
    user: &impl AuthUser,
    config: &PasswordManagementConfig,
    req: &better_auth_core::AuthRequest,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ChangePasswordResponse<UserView>> {
    password_utils::validate_password(
        &body.new_password,
        ctx.password_policy.min_length,
        ctx.password_policy.max_length,
        ctx,
    )?;
    ctx.password_policy
        .validate_max_length(&body.current_password)?;
    let stored_hash = get_credential_password_hash(ctx, user)
        .await?
        .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
    let password_hash =
        password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.new_password)
            .await?;
    if config.require_current_password {
        password_utils::verify_password(
            ctx.password_policy.hasher.as_ref(),
            &body.current_password,
            &stored_hash,
        )
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => AuthError::bad_request("Invalid password"),
            other => other,
        })?;
    }

    let credential_account = get_credential_account(ctx, user.id().into_owned())
        .await?
        .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
    let _ = ctx
        .database
        .update_account(
            credential_account.id.typed()?,
            UpdateAccount {
                password: (Some(password_hash))
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                ..Default::default()
            },
        )
        .await?;

    let new_token = if body.revoke_other_sessions == Some(true) {
        ctx.database
            .delete_user_sessions(user.id().typed()?)
            .await?;
        let issued = issue_selected_user_session_optional(
            ctx,
            better_auth_core::FieldMap::from(ctx.internal_user_view(user).await?).into(),
            meta,
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?
        .ok_or(AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_GET_SESSION",
            message: "Failed to get session",
        })?;
        let token = issued.session.token.field_value();
        ctx.session_manager()
            .set_native_session_cookie(req, issued, None)
            .await?;
        token
    } else {
        better_auth_core::FieldValue::Null
    };

    let response = ChangePasswordResponse {
        token: new_token,
        user: ctx.user_view(user).await?,
    };

    Ok(response)
}

pub(crate) async fn verify_password_core(
    body: &VerifyPasswordRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    ctx.password_policy.validate_max_length(&body.password)?;
    let stored_hash = get_credential_password_hash(ctx, user)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;

    password_utils::verify_password(
        ctx.password_policy.hasher.as_ref(),
        &body.password,
        &stored_hash,
    )
    .await
    .map_err(|error| match error {
        AuthError::InvalidCredentials => AuthError::bad_request("Invalid password"),
        other => other,
    })?;

    Ok(StatusResponse { status: true })
}

fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.advanced.disable_origin_check {
        return Ok(());
    }
    if ctx.is_redirect_target_trusted(target) {
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
        base.join(callback_url).map_err(|error| {
            // Upstream sends the bare message so the response carries the
            // INVALID_CALLBACK_URL code; keep the parse detail in the log.
            better_auth_core::observability::logger::current().warn(
                "Invalid callbackURL",
                &[
                    better_auth_core::observability::LogArgument::Error(&error),
                    better_auth_core::observability::LogArgument::Value(&serde_json::json!(
                        callback_url
                    )),
                ],
            );
            AuthError::bad_request("Invalid callbackURL")
        })?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck respects ctx.context.skipOriginCheck.
    #[tokio::test]
    async fn validate_redirect_target_respects_disable_origin_check() {
        let config = test_helpers::create_test_config().disable_origin_check(true);
        let ctx = test_helpers::create_test_context_with_config(config).await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid redirectURL").is_ok()
        );
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck rejects untrusted origins by default.
    #[tokio::test]
    async fn validate_redirect_target_rejects_untrusted_by_default() {
        let ctx = test_helpers::create_test_context().await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid redirectURL")
                .is_err()
        );
    }
}
