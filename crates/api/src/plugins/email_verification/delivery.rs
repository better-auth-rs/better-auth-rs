use super::{EmailVerificationCallbacks, EmailVerificationConfig, VerificationEmail};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthContext, AuthResult, AuthSchema, FieldValue, background::BackgroundFuture,
    email::EmailVerificationHook,
};
use std::sync::Arc;

pub(crate) fn available<S: AuthSchema>(
    config: Option<&EmailVerificationConfig>,
    ctx: &AuthContext<S>,
) -> bool {
    ctx.extensions
        .get::<Arc<EmailVerificationCallbacks<S>>>()
        .is_some_and(|callbacks| callbacks.has_sender())
        || config.is_some_and(|config| config.send_verification_email.is_some())
        || ctx.email_verification_policy.override_sender.is_some()
        || crate::plugins::email_otp::callbacks::overrides_verification(ctx)
        || (config.is_some_and(|config| config.send_email_notifications)
            && ctx.email_provider.is_some())
}

/// Construct delivery before scheduling so synchronous callback errors reach the endpoint.
pub(crate) fn delivery<S: AuthSchema>(
    config: Option<&EmailVerificationConfig>,
    message: VerificationEmail,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<BackgroundFuture>> {
    let ctx = endpoint.auth;
    if ctx
        .extensions
        .get::<Arc<EmailVerificationCallbacks<S>>>()
        .is_none_or(|callbacks| !callbacks.has_sender())
        && config.is_none_or(|config| config.send_verification_email.is_none())
        && crate::plugins::email_otp::callbacks::overrides_verification(ctx)
    {
        let retained = endpoint.to_owned();
        let email = crate::plugins::helpers::user_email(&message.user_view()?)?;
        return Ok(Some(Box::pin(async move {
            crate::plugins::email_otp::callbacks::send_verification_override(
                &email,
                &retained.as_endpoint(),
            )
            .await
        })));
    }
    if let Some(sender) = ctx
        .extensions
        .get::<Arc<EmailVerificationCallbacks<S>>>()
        .and_then(|callbacks| callbacks.sender.as_ref())
    {
        return sender(&message, endpoint);
    }
    if let Some(sender) = config
        .and_then(|config| config.send_verification_email.as_ref())
        .or(ctx.email_verification_policy.override_sender.as_ref())
    {
        let sender = sender.clone();
        return Ok(Some(Box::pin(async move {
            sender
                .send(&message.user, &message.url, &message.token)
                .await
        })));
    }
    if config.is_some_and(|config| config.send_email_notifications) {
        if let Some(provider) = ctx.email_provider.clone() {
            return Ok(Some(Box::pin(async move {
                let html = format!(
                    "<p>Click the link below to verify your email address:</p><p><a href=\"{url}\">Verify Email</a></p>",
                    url = message.url
                );
                let text = format!("Verify your email address: {}", message.url);
                provider
                    .send(
                        &crate::plugins::helpers::user_email(&message.user_view()?)?,
                        "Verify your email address",
                        &html,
                        &text,
                    )
                    .await
            })));
        }
        better_auth_core::observability::logger::current().warn(
            "No email provider configured, skipping verification email",
            &[],
        );
    }
    Ok(None)
}

async fn lifecycle<S: AuthSchema>(
    user: &FieldValue,
    endpoint: &EndpointContext<'_, S>,
    callback: Option<&Arc<super::callbacks::Lifecycle<S>>>,
    legacy: Option<&EmailVerificationHook>,
) -> AuthResult<()> {
    if let Some(callback) = callback {
        if let Some(task) = callback(user, endpoint)? {
            task.await?;
        }
    } else if let Some(legacy) = legacy {
        legacy(user).await?;
    }
    Ok(())
}

pub(crate) async fn before<S: AuthSchema>(
    user: &FieldValue,
    config: Option<&EmailVerificationConfig>,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<()> {
    let callbacks = endpoint
        .auth
        .extensions
        .get::<Arc<EmailVerificationCallbacks<S>>>();
    let legacy = config.map_or(
        endpoint
            .auth
            .email_verification_policy
            .before_email_verification
            .as_ref(),
        |config| config.before_email_verification.as_ref(),
    );
    lifecycle(
        user,
        endpoint,
        callbacks.and_then(|callbacks| callbacks.before.as_ref()),
        legacy,
    )
    .await
}

pub(crate) async fn after<S: AuthSchema>(
    user: &FieldValue,
    config: Option<&EmailVerificationConfig>,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<()> {
    let callbacks = endpoint
        .auth
        .extensions
        .get::<Arc<EmailVerificationCallbacks<S>>>();
    let legacy = config.map_or(
        endpoint
            .auth
            .email_verification_policy
            .after_email_verification
            .as_ref(),
        |config| config.after_email_verification.as_ref(),
    );
    lifecycle(
        user,
        endpoint,
        callbacks.and_then(|callbacks| callbacks.after.as_ref()),
        legacy,
    )
    .await
}
