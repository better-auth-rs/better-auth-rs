use super::JwtPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{
    AuthPlugin, AuthRecordFields, AuthResult, AuthSchema, CreateJwk, FieldFunction, FieldMap,
    FieldValue, Jwk,
};
use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

/// A JWT adapter callback that borrows the active endpoint.
pub type JwtAdapterFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
type Get<S> =
    dyn for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue> + Send + Sync;
type Create<S> = dyn for<'a> Fn(FieldValue, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
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
    pub fn get_jwks<F>(self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Vec<Jwk>>>
            + Send
            + Sync
            + 'static,
    {
        self.get_jwks_native(move |endpoint| {
            let result = callback(endpoint);
            Box::pin(async move {
                Ok(match result.await? {
                    Some(keys) => keys
                        .iter()
                        .map(|key| key.field_values().map(FieldValue::from))
                        .collect::<AuthResult<Vec<_>>>()?
                        .into(),
                    None => FieldValue::Null,
                })
            })
        })
    }

    /// Read a native logical keyring, preserving array methods, accessors, and record identity.
    pub fn get_jwks_native<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
            + Send
            + Sync
            + 'static,
    {
        self.get = Some(Arc::new(callback));
        self
    }

    /// Persist generated key material and return the nullable adapter readback.
    pub fn create_jwk<F>(self, callback: F) -> Self
    where
        F: for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Jwk>>
            + Send
            + Sync
            + 'static,
    {
        self.create_jwk_native(move |data, endpoint| {
            let result = callback(data, endpoint);
            Box::pin(async move {
                Ok(match result.await? {
                    Some(key) => key.field_values()?.into(),
                    None => FieldValue::Null,
                })
            })
        })
    }

    /// Persist generated material and retain the native logical adapter readback.
    pub fn create_jwk_native<F>(self, callback: F) -> Self
    where
        F: for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
            + Send
            + Sync
            + 'static,
    {
        self.create_jwk_value(move |data, endpoint| {
            let data = typed_create(data);
            let callback = data.map(|data| callback(data, endpoint));
            Box::pin(async move { callback?.await })
        })
    }

    /// Persist generated key material without narrowing dynamic fields before the callback.
    pub fn create_jwk_value<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(FieldValue, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
            + Send
            + Sync
            + 'static,
    {
        self.create = Some(Arc::new(callback));
        self
    }

    pub(super) fn to_native(&self) -> FieldValue {
        let mut fields = FieldMap::new();
        if let Some(callback) = &self.get {
            let _ = fields.insert(
                "getJwks".into(),
                FieldFunction::bound(AdapterBinding::Get(callback.clone())).into(),
            );
        }
        if let Some(callback) = &self.create {
            let _ = fields.insert(
                "createJwk".into(),
                FieldFunction::bound(AdapterBinding::Create(callback.clone())).into(),
            );
        }
        fields.into()
    }

    pub(super) fn into_native(self) -> FieldValue {
        self.to_native()
    }
}

pub(super) enum AdapterBinding<S: AuthSchema> {
    Get(Arc<Get<S>>),
    Create(Arc<Create<S>>),
}

pub(super) struct RegisteredCallbacks<S: AuthSchema> {
    pub(super) adapter: FieldValue,
    schema: PhantomData<fn() -> S>,
}

impl<S: AuthSchema> From<FieldValue> for RegisteredCallbacks<S> {
    fn from(adapter: FieldValue) -> Self {
        Self {
            adapter,
            schema: PhantomData,
        }
    }
}

impl<S: AuthSchema> From<JwtCallbacks<S>> for RegisteredCallbacks<S> {
    fn from(callbacks: JwtCallbacks<S>) -> Self {
        callbacks.into_native().into()
    }
}

fn typed_create(data: FieldValue) -> AuthResult<CreateJwk> {
    let mut fields = data.enumerable_fields()?;
    let mut take = |name: &str| fields.remove(name).unwrap_or_default();
    Ok(CreateJwk {
        alg: take("alg").decode()?,
        crv: take("crv").decode()?,
        public_key: take("publicKey").decode()?,
        private_key: take("privateKey").decode()?,
        created_at: take("createdAt").decode()?,
        expires_at: take("expiresAt").decode()?,
        additional_fields: fields,
    })
}

impl JwtPlugin {
    /// Attach schema-aware key adapter callbacks after configuring plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: JwtCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(RegisteredCallbacks::from(callbacks)),
        }
    }

    /// Retain a native adapter group, including its receiver, accessors, and callback identities.
    /// Unbound callbacks require an explicitly supplied [`EndpointContext::with_native_root`].
    pub fn native_callbacks<S: AuthSchema>(self, adapter: FieldValue) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(RegisteredCallbacks::<S>::from(adapter)),
        }
    }
}
