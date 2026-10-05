use crate::{AuthRequest, AuthResult};
use std::{future::Future, pin::Pin, sync::Arc};

use super::ValidatedBody;

type ValidationFuture = Pin<Box<dyn Future<Output = AuthResult<ValidatedBody>> + Send>>;
type SyncCallback = dyn Fn(&AuthRequest) -> AuthResult<ValidatedBody> + Send + Sync;

/// One body validator, evaluated before query validation and endpoint middleware.
#[derive(Clone)]
pub struct BodyValidator(Callback);

#[derive(Clone)]
enum Callback {
    Sync(Arc<SyncCallback>),
    Async(Arc<dyn Fn(AuthRequest) -> ValidationFuture + Send + Sync>),
}

impl BodyValidator {
    /// Preserve an existing synchronous body validator.
    pub fn new(
        callback: impl Fn(&AuthRequest) -> AuthResult<ValidatedBody> + Send + Sync + 'static,
    ) -> Self {
        Self(Callback::Sync(Arc::new(callback)))
    }

    /// Give an asynchronous validator its own request snapshot.
    pub fn new_async<F, Fut>(callback: F) -> Self
    where
        F: Fn(AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<ValidatedBody>> + Send + 'static,
    {
        Self(Callback::Async(Arc::new(move |request| {
            Box::pin(callback(request))
        })))
    }

    /// Evaluate the configured validator exactly once and preserve its original error.
    pub async fn validate(&self, request: &AuthRequest) -> AuthResult<ValidatedBody> {
        match &self.0 {
            Callback::Sync(callback) => callback(request),
            Callback::Async(callback) => callback(request.clone()).await,
        }
    }
}
