use super::*;
use better_auth::{
    __private_core::{AuthSchema, AuthStore, CreateUser, SchemaValue, store::schema::EntityRole},
    BetterAuth,
    plugins::{DeviceAuthorizationPlugin, api_key::ApiKeyPlugin, passkey::PasskeyPlugin},
};
use std::sync::Arc;

#[derive(Clone, Copy)]
enum Model {
    ApiKey,
    Passkey,
    DeviceCode,
}

struct Store<S: AuthSchema, F> {
    model: Model,
    store: Arc<dyn AuthStore<S>>,
    raw: Arc<F>,
}

#[async_trait]
impl<S, F, Fut> Adapter for Store<S, F>
where
    S: AuthSchema,
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = TestResult<Value>> + Send,
{
    async fn create(&self, fields: FieldMap) -> AuthResult<Option<FieldMap>> {
        match self.model {
            Model::ApiKey => self.store.create_api_key_record(fields).await.map(Some),
            Model::Passkey => self.store.create_passkey_record(fields).await.map(Some),
            Model::DeviceCode => self.store.create_device_code_record(fields).await.map(Some),
        }
    }

    async fn read(&self, id: FieldValue) -> AuthResult<Option<FieldMap>> {
        let id = SchemaValue::from_field(id);
        match self.model {
            Model::ApiKey => self.store.get_api_key_record(&id).await,
            Model::Passkey => self.store.get_passkey_record(&id).await,
            Model::DeviceCode => self.store.get_device_code_record(&id).await,
        }
    }

    async fn update(&self, id: FieldValue, fields: FieldMap) -> AuthResult<Option<FieldMap>> {
        let id = SchemaValue::from_field(id);
        match self.model {
            Model::ApiKey => self.store.update_api_key_record(&id, fields).await,
            Model::Passkey => self.store.update_passkey_record(&id, fields).await,
            Model::DeviceCode => self.store.update_device_code_record(&id, fields).await,
        }
    }

    async fn delete(&self, id: FieldValue) -> AuthResult<Option<FieldMap>> {
        match self.model {
            Model::ApiKey => {
                self.store
                    .delete_api_key(&SchemaValue::from_field(id))
                    .await?
            }
            Model::Passkey => self.store.delete_passkey(&id.decode::<String>()?).await?,
            Model::DeviceCode => {
                self.store
                    .delete_device_code(&SchemaValue::from_field(id))
                    .await?
            }
        }
        Ok(None)
    }

    async fn stored(&self) -> TestResult<Value> {
        (self.raw)().await
    }
}

pub(crate) async fn with_store<S, F, Fut>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    expected: Value,
    observe_raw: F,
) -> TestResult
where
    S: AuthSchema,
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = TestResult<Value>> + Send,
{
    let target = Target::from_fixture(&expected)?;
    let model = match target.role {
        EntityRole::ApiKey => Model::ApiKey,
        EntityRole::Passkey => Model::Passkey,
        EntityRole::DeviceCode => Model::DeviceCode,
        _ => return Err(format!("Unsupported replacement model {}", target.model).into()),
    };
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Native replacement owner")
                .with_email("owner@native-replacements.test")
                .with_email_verified(false),
        )
        .await?;
    assert_eq!(owner.id.typed()?, OWNER);
    let observe_raw = Arc::new(observe_raw);
    contract(backend, expected, move |policy| {
        let raw = raw.clone();
        let observe_raw = observe_raw.clone();
        async move {
            let builder = BetterAuth::new(config()).store_arc(raw);
            let builder = match model {
                Model::ApiKey => builder.plugin(ApiKeyPlugin::builder().build()),
                Model::Passkey => builder.plugin(PasskeyPlugin::new()),
                Model::DeviceCode => builder.plugin(DeviceAuthorizationPlugin::new()),
            };
            let auth = builder.plugin(policy).build().await?;
            Ok(Store {
                model,
                store: auth.store().clone(),
                raw: observe_raw,
            })
        }
    })
    .await
}
