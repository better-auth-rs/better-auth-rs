use std::{future::Future, pin::Pin, sync::Arc};

use better_auth_core::{AuthPlugin, AuthResult, AuthSchema, wire::UserView};

use super::TwoFactorPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};

/// Borrowing future returned by a context-aware two-factor delivery callback.
pub type TwoFactorCallbackFuture<'a> = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'a>>;

type Sender<S> = dyn for<'a> Fn(&'a UserView, &'a str, &'a EndpointContext<'_, S>) -> TwoFactorCallbackFuture<'a>
    + Send
    + Sync;

/// Two-factor callbacks with validated input and the active typed runtime.
pub struct TwoFactorCallbacks<S: AuthSchema> {
    pub(super) sender: Option<Arc<Sender<S>>>,
}

impl<S: AuthSchema> Default for TwoFactorCallbacks<S> {
    fn default() -> Self {
        Self { sender: None }
    }
}

impl<S: AuthSchema> TwoFactorCallbacks<S> {
    /// Deliver an OTP after its verification record has been persisted.
    pub fn send<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(
                &'a UserView,
                &'a str,
                &'a EndpointContext<'_, S>,
            ) -> TwoFactorCallbackFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.sender = Some(Arc::new(callback));
        self
    }
}

impl TwoFactorPlugin {
    /// Attach schema-aware callbacks after configuring the plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: TwoFactorCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
