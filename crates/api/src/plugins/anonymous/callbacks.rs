use super::{AnonymousLink, AnonymousPlugin};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema};
use std::{future::Future, pin::Pin, sync::Arc};

/// A callback future that borrows the active endpoint.
pub type AnonymousCallbackFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
type Name<S> =
    dyn for<'a> Fn(&'a EndpointContext<'_, S>) -> AnonymousCallbackFuture<'a, String> + Send + Sync;
type Link<S> = dyn for<'a> Fn(&'a AnonymousLink, &'a EndpointContext<'_, S>) -> AnonymousCallbackFuture<'a, ()>
    + Send
    + Sync;

/// Anonymous identity callbacks with the complete endpoint context.
pub struct AnonymousCallbacks<S: AuthSchema> {
    pub(super) name: Option<Arc<Name<S>>>,
    pub(super) link: Option<Arc<Link<S>>>,
}

impl<S: AuthSchema> Default for AnonymousCallbacks<S> {
    fn default() -> Self {
        Self {
            name: None,
            link: None,
        }
    }
}

impl<S: AuthSchema> AnonymousCallbacks<S> {
    /// Generate a display name before creating the anonymous user.
    pub fn generate_name<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a EndpointContext<'_, S>) -> AnonymousCallbackFuture<'a, String>
            + Send
            + Sync
            + 'static,
    {
        self.name = Some(Arc::new(callback));
        self
    }

    /// Transfer application data before deleting the old anonymous user.
    pub fn on_link_account<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(
                &'a AnonymousLink,
                &'a EndpointContext<'_, S>,
            ) -> AnonymousCallbackFuture<'a, ()>
            + Send
            + Sync
            + 'static,
    {
        self.link = Some(Arc::new(callback));
        self
    }
}

impl AnonymousPlugin {
    /// Attach schema-aware callbacks after configuring plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: AnonymousCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
