use super::{PasswordManagementConfig, PasswordManagementPlugin};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthResult, AuthSchema, background::BackgroundFuture,
    wire::UserView,
};
use std::sync::Arc;

/// Password reset notification after the reset token has been persisted.
#[derive(Clone)]
pub struct PasswordResetEmail {
    /// User snapshot supplied by the reset endpoint.
    pub user: UserView,
    /// Reset link, including the callback URL.
    pub url: String,
    /// Raw reset token.
    pub token: String,
}

type Sender<S> = dyn Fn(&PasswordResetEmail, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;

/// Password reset delivery with the complete endpoint context.
pub struct PasswordManagementCallbacks<S: AuthSchema> {
    sender: Arc<Sender<S>>,
}
impl<S: AuthSchema> PasswordManagementCallbacks<S> {
    /// Start delivery before scheduling. Return `None` for synchronous completion.
    /// Use `EndpointContext::to_owned` when asynchronous delivery needs its context.
    pub fn send_reset_password(
        callback: impl Fn(
            &PasswordResetEmail,
            &EndpointContext<'_, S>,
        ) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            sender: Arc::new(callback),
        }
    }
}
impl PasswordManagementPlugin {
    /// Attach typed delivery after configuring password management options.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: PasswordManagementCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}

pub(super) fn require_sender<S: AuthSchema>(
    config: &PasswordManagementConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<()> {
    if config.send_reset_password.is_none()
        && ctx
            .extensions
            .get::<Arc<PasswordManagementCallbacks<S>>>()
            .is_none()
    {
        return Err(AuthError::bad_request("Reset password isn't enabled"));
    }
    Ok(())
}

pub(super) fn delivery<S: AuthSchema>(
    config: &PasswordManagementConfig,
    email: PasswordResetEmail,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<BackgroundFuture>> {
    if let Some(callbacks) = endpoint
        .auth
        .extensions
        .get::<Arc<PasswordManagementCallbacks<S>>>()
    {
        return (callbacks.sender)(&email, endpoint);
    }
    let sender = config
        .send_reset_password
        .clone()
        .ok_or_else(|| AuthError::bad_request("Reset password isn't enabled"))?;
    let user = serde_json::to_value(email.user)?;
    let request = endpoint.request.cloned();
    Ok(Some(Box::pin(async move {
        sender
            .send_with_request(&user, &email.url, &email.token, request.as_ref())
            .await
    })))
}
