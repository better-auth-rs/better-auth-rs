use std::sync::Arc;

use better_auth_core::{
    AuthPlugin, AuthResult, AuthSchema, FieldValue, background::BackgroundFuture,
};

use super::TwoFactorPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};

type Sender<S> = dyn Fn(&FieldValue, &str, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
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
    /// Construct delivery work after persisting the OTP. Factory errors propagate immediately.
    /// Retain the endpoint with `to_owned` when delivery needs its active runtime.
    pub fn send<F>(mut self, callback: F) -> Self
    where
        F: Fn(&FieldValue, &str, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
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
