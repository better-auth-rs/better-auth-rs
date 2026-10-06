use super::OAuthPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

/// An ID-token verifier that borrows the token and active endpoint.
pub type OAuthVerifierFuture<'a> = Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>>;
type Verify<S> = dyn for<'a> Fn(&'a str, Option<&'a str>, &'a EndpointContext<'_, S>) -> OAuthVerifierFuture<'a>
    + Send
    + Sync;

/// Schema-aware verification callbacks keyed by the registered provider name.
pub struct OAuthCallbacks<S: AuthSchema> {
    pub(crate) verifiers: HashMap<String, Arc<Verify<S>>>,
}

impl<S: AuthSchema> Default for OAuthCallbacks<S> {
    fn default() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }
}

impl<S: AuthSchema> OAuthCallbacks<S> {
    /// Override the registered provider's ID-token verifier. False and errors reject the token.
    /// This callback takes precedence over `OAuthProvider::verify_id_token`.
    pub fn verify_id_token<F>(mut self, provider: impl Into<String>, callback: F) -> Self
    where
        F: for<'a> Fn(
                &'a str,
                Option<&'a str>,
                &'a EndpointContext<'_, S>,
            ) -> OAuthVerifierFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        let _ = self.verifiers.insert(provider.into(), Arc::new(callback));
        self
    }
}

impl OAuthPlugin {
    /// Attach schema-aware verifiers after configuring providers.
    pub fn callbacks<S: AuthSchema>(self, callbacks: OAuthCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
