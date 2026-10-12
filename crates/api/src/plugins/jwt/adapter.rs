use super::{JwtPlugin, callbacks::AdapterBinding, overrides::NativeOptions};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthError, AuthResult, AuthSchema, FieldFunction, FieldValue, store::JwksStore,
};

pub(super) fn store<'a, S: AuthSchema>(endpoint: &'a EndpointContext<'_, S>) -> &'a dyn JwksStore {
    match endpoint.transaction {
        Some(transaction) => transaction,
        None => endpoint.auth.database.as_ref(),
    }
}

pub(super) struct Keyring<'a, 'ctx, S: AuthSchema> {
    store: &'a dyn JwksStore,
    options: &'a NativeOptions,
    endpoint: &'a EndpointContext<'ctx, S>,
}

impl<'a, 'ctx, S: AuthSchema> Keyring<'a, 'ctx, S> {
    pub(super) fn new(
        store: &'a dyn JwksStore,
        options: &'a NativeOptions,
        endpoint: &'a EndpointContext<'ctx, S>,
    ) -> Self {
        Self {
            store,
            options,
            endpoint,
        }
    }

    fn callback(&self, name: &str) -> AuthResult<Option<(FieldValue, FieldFunction)>> {
        if !self.options.property("adapter", name)?.is_truthy() {
            return Ok(None);
        }
        let receiver = self.options.0.model_property("adapter")?;
        let function = receiver.model_property(name)?;
        match function {
            FieldValue::Function(function) => Ok(Some((receiver, function))),
            _ => Err(AuthError::type_error(format!(
                "options.adapter.{name} is not a function"
            ))),
        }
    }

    async fn get(&self, receiver: FieldValue, function: FieldFunction) -> AuthResult<FieldValue> {
        if let Some(AdapterBinding::<S>::Get(callback)) = function.binding() {
            return callback(self.endpoint).await;
        }
        function
            .call_awaited_with(&receiver, std::slice::from_ref(self.native_root()?))
            .await
    }

    fn native_root(&self) -> AuthResult<&FieldValue> {
        self.endpoint.native_root().ok_or_else(|| {
            AuthError::config(
                "Native JWT adapter callbacks require an explicit native endpoint root",
            )
        })
    }

    async fn find(&self, id: &str) -> AuthResult<FieldValue> {
        if let Some((receiver, function)) = self.callback("getJwks")? {
            let keys = self.get(receiver, function).await?;
            if keys.is_null() || keys.is_undefined() {
                return Ok(FieldValue::Undefined);
            }
            return super::keys::find(&keys, id.into());
        }
        let key = self.store.get_jwk_value(&id.into()).await?;
        Ok(if key.is_null() {
            FieldValue::Undefined
        } else {
            key
        })
    }

    pub(super) async fn all(&self) -> AuthResult<FieldValue> {
        if let Some((receiver, function)) = self.callback("getJwks")? {
            return self.get(receiver, function).await;
        }
        self.store.list_jwk_values().await
    }

    pub(super) async fn latest(&self, algorithm: Option<FieldValue>) -> AuthResult<FieldValue> {
        let before = algorithm
            .is_none()
            .then(|| chrono::Utc::now().timestamp_millis());
        let keys = self.all().await?;
        if algorithm.is_some() && !keys.is_truthy() {
            return Ok(FieldValue::Undefined);
        }
        let default_algorithm = if algorithm.is_some() {
            self.options.primary_algorithm()?
        } else {
            FieldValue::Undefined
        };
        let now = before.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        super::keys::latest(keys, algorithm, default_algorithm, (now as f64).into())
    }

    pub(super) async fn create(&self, data: FieldValue) -> AuthResult<FieldValue> {
        if let Some((receiver, function)) = self.callback("createJwk")? {
            if let Some(AdapterBinding::<S>::Create(callback)) = function.binding() {
                return callback(data, self.endpoint).await;
            }
            return function
                .call_awaited_with(&receiver, &[data, self.native_root()?.clone()])
                .await;
        }
        let mut fields = data.enumerable_fields()?;
        let _ = fields.insert("createdAt".into(), chrono::Utc::now().into());
        Ok(self
            .store
            .create_jwk_record(fields)
            .await?
            .map(FieldValue::from)
            .unwrap_or(FieldValue::Null))
    }
}

impl JwtPlugin {
    pub(super) async fn read_key<S: AuthSchema>(
        &self,
        id: &str,
        options: &NativeOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        Keyring::new(store(endpoint), options, endpoint)
            .find(id)
            .await
    }

    pub(super) async fn read_keys<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        let options = self.options.clone();
        Keyring::new(store(endpoint), &options, endpoint)
            .all()
            .await
    }

    pub(super) async fn read_latest_key<S: AuthSchema>(
        &self,
        algorithm: Option<FieldValue>,
        options: &NativeOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        Keyring::new(store(endpoint), options, endpoint)
            .latest(algorithm)
            .await
    }
}
