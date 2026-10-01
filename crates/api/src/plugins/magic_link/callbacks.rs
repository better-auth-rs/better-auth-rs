use super::{MagicLinkMessage, MagicLinkPlugin};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema};
use std::{future::Future, pin::Pin, sync::Arc};

/// A sender future that can borrow the message and active endpoint.
pub type MagicLinkCallbackFuture<'a> = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'a>>;
type Sender<S> = dyn for<'a> Fn(&'a MagicLinkMessage, &'a EndpointContext<'_, S>) -> MagicLinkCallbackFuture<'a>
    + Send
    + Sync;

/// Magic-link delivery with the parsed input and typed authentication runtime.
pub struct MagicLinkCallbacks<S: AuthSchema> {
    pub(super) sender: Arc<Sender<S>>,
}

impl<S: AuthSchema> MagicLinkCallbacks<S> {
    /// Deliver a link after the verification proof has been stored.
    pub fn new<F>(sender: F) -> Self
    where
        F: for<'a> Fn(
                &'a MagicLinkMessage,
                &'a EndpointContext<'_, S>,
            ) -> MagicLinkCallbackFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        Self {
            sender: Arc::new(sender),
        }
    }
}

impl MagicLinkPlugin {
    /// Attach schema-aware delivery after configuring plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: MagicLinkCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
