use super::OneTimeTokenPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema, session::NativeSessionData};
use std::{future::Future, pin::Pin, sync::Arc};

/// Token generation that borrows the native Session and active endpoint.
pub type OneTimeTokenGeneratorFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<String>> + Send + 'a>>;
type Generator<S> = dyn for<'a> Fn(&'a NativeSessionData, &'a EndpointContext<'_, S>) -> OneTimeTokenGeneratorFuture<'a>
    + Send
    + Sync;

/// Schema-aware token generation with the complete endpoint context.
pub struct OneTimeTokenCallbacks<S: AuthSchema> {
    pub(super) generator: Arc<Generator<S>>,
}

impl<S: AuthSchema> OneTimeTokenCallbacks<S> {
    /// Generate before hashing and persistence. Errors propagate without invoking the legacy generator.
    pub fn generate<F>(callback: F) -> Self
    where
        F: for<'a> Fn(
                &'a NativeSessionData,
                &'a EndpointContext<'_, S>,
            ) -> OneTimeTokenGeneratorFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        Self {
            generator: Arc::new(callback),
        }
    }
}

impl OneTimeTokenPlugin {
    /// Attach schema-aware generation after configuring the plugin options.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: OneTimeTokenCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
