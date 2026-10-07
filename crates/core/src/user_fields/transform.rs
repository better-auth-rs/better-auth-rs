use crate::FieldValue as Value;
use crate::{AuthError, AuthResult};
use std::{future::Future, pin::Pin, sync::Arc};

type TransformResult = AuthResult<Value>;
type TransformFuture = Pin<Box<dyn Future<Output = TransformResult> + Send>>;

/// A field callback. Undefined, null, and native object values remain distinct.
#[derive(Clone)]
pub struct UserFieldTransform(Callback);

#[derive(Clone)]
enum Callback {
    Sync(Arc<dyn Fn(Value) -> TransformResult + Send + Sync>),
    Async(Arc<dyn Fn(Value) -> TransformFuture + Send + Sync>),
}

impl UserFieldTransform {
    /// Use a synchronous callback at public-input and adapter boundaries.
    pub fn new(callback: impl Fn(Value) -> TransformResult + Send + Sync + 'static) -> Self {
        Self(Callback::Sync(Arc::new(callback)))
    }

    /// Await a callback at core, Organization, and supported plugin adapter boundaries.
    /// Synchronous public-input parsing rejects async callbacks.
    pub fn new_async<F, Fut>(callback: F) -> Self
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TransformResult> + Send + 'static,
    {
        Self(Callback::Async(Arc::new(move |value| {
            Box::pin(callback(value))
        })))
    }

    /// Invoke a callback and await its result without changing its original error.
    pub async fn call(&self, value: Value) -> TransformResult {
        match &self.0 {
            Callback::Sync(callback) => callback(value),
            Callback::Async(callback) => callback(value).await,
        }
    }

    /// Invoke a callback at a synchronous policy boundary.
    /// Async callbacks return a configuration error before application work starts.
    pub fn call_sync(&self, value: Value) -> TransformResult {
        match &self.0 {
            Callback::Sync(callback) => callback(value),
            Callback::Async(_) => Err(AuthError::config(
                "Async field transforms require an adapter boundary; public-input parsing is synchronous",
            )),
        }
    }

    pub(crate) fn is_async(&self) -> bool {
        matches!(self.0, Callback::Async(_))
    }
}
