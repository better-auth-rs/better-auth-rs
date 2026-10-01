use super::{InvitationEmail, OrganizationConfig, OrganizationPlugin};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema, background::BackgroundFuture};
use std::sync::Arc;

type InvitationSender<S> = dyn Fn(&InvitationEmail, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;

/// Invitation delivery with the validated endpoint context.
pub struct OrganizationCallbacks<S: AuthSchema> {
    sender: Arc<InvitationSender<S>>,
}
impl<S: AuthSchema> OrganizationCallbacks<S> {
    /// Construct delivery before scheduling. Factory errors remain endpoint errors.
    pub fn invitation_email(
        sender: impl Fn(
            &InvitationEmail,
            &EndpointContext<'_, S>,
        ) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            sender: Arc::new(sender),
        }
    }
}
impl OrganizationPlugin {
    /// Attach typed notification callbacks after configuring the organization options.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: OrganizationCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
pub(super) fn delivery<S: AuthSchema>(
    config: &OrganizationConfig,
    message: InvitationEmail,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<BackgroundFuture>> {
    if let Some(callbacks) = endpoint
        .auth
        .extensions
        .get::<Arc<OrganizationCallbacks<S>>>()
    {
        return (callbacks.sender)(&message, endpoint);
    }
    let Some(sender) = config.send_invitation_email.clone() else {
        return Ok(None);
    };
    Ok(Some(Box::pin(async move { sender.send(&message).await })))
}
