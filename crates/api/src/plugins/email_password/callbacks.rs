use super::{EmailPasswordConfig, EmailPasswordPlugin};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{
    AuthPlugin, AuthResult, AuthSchema, background::BackgroundFuture, wire::UserView,
};
use std::sync::Arc;

type ExistingUserSender<S> = dyn Fn(&UserView, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;

/// Enumeration-safe signup notification with its active transaction and request.
pub struct EmailPasswordCallbacks<S: AuthSchema> {
    sender: Arc<ExistingUserSender<S>>,
}
impl<S: AuthSchema> EmailPasswordCallbacks<S> {
    /// Construct notification work before scheduling. `None` completes synchronously.
    pub fn existing_user_sign_up(
        sender: impl Fn(&UserView, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            sender: Arc::new(sender),
        }
    }
}
impl EmailPasswordPlugin {
    /// Attach typed notification callbacks after configuring the password options.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: EmailPasswordCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
pub(super) fn delivery<S: AuthSchema>(
    config: &EmailPasswordConfig,
    user: &UserView,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<BackgroundFuture>> {
    if let Some(callbacks) = endpoint
        .auth
        .extensions
        .get::<Arc<EmailPasswordCallbacks<S>>>()
    {
        return (callbacks.sender)(user, endpoint);
    }
    let Some(sender) = config.on_existing_user_sign_up.clone() else {
        return Ok(None);
    };
    let user = user.clone();
    let request = endpoint.request.cloned();
    Ok(Some(Box::pin(async move {
        sender
            .on_existing_user_sign_up(&user, request.as_ref())
            .await
    })))
}
