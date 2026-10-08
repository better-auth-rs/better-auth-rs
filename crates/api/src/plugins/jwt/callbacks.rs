use super::JwtPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema, CreateJwk, Jwk};
use std::{future::Future, pin::Pin, sync::Arc};

/// A JWT adapter callback that borrows the active endpoint.
pub type JwtAdapterFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
type Get<S> = dyn for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Vec<Jwk>>>
    + Send
    + Sync;
type Create<S> = dyn for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Jwk>>
    + Send
    + Sync;

/// Independent key reads and writes for one registered JWT plugin.
pub struct JwtCallbacks<S: AuthSchema> {
    pub(super) get: Option<Arc<Get<S>>>,
    pub(super) create: Option<Arc<Create<S>>>,
}

impl<S: AuthSchema> Default for JwtCallbacks<S> {
    fn default() -> Self {
        Self {
            get: None,
            create: None,
        }
    }
}

impl<S: AuthSchema> JwtCallbacks<S> {
    /// Read a custom keyring. `None` represents an absent keyset, not a database fallback.
    pub fn get_jwks<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Vec<Jwk>>>
            + Send
            + Sync
            + 'static,
    {
        self.get = Some(Arc::new(callback));
        self
    }

    /// Persist generated key material and return the nullable adapter readback.
    pub fn create_jwk<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Jwk>>
            + Send
            + Sync
            + 'static,
    {
        self.create = Some(Arc::new(callback));
        self
    }
}

impl JwtPlugin {
    /// Attach schema-aware key adapter callbacks after configuring plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: JwtCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
