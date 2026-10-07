#![cfg(feature = "seaorm2")]

use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, AuthStore, CreateAccount, CreatePasskey, CreateSession, CreateUser,
    CreateVerification, FieldDate, FieldMap, FieldValue, UpdatePasskeyAuthentication,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

#[path = "plugin_model_fields_tests/aaguid.rs"]
mod aaguid;
#[path = "plugin_model_fields_tests/api_key.rs"]
mod api_key;
#[path = "plugin_model_fields_tests/api_key_cache.rs"]
mod api_key_cache;

#[path = "plugin_model_fields_tests/create_order.rs"]
mod create_order;

#[path = "plugin_model_fields_tests/core.rs"]
mod core;

#[path = "plugin_model_fields_tests/device_scope.rs"]
mod device_scope;

#[path = "plugin_model_fields_tests/device_consumption.rs"]
mod device_consumption;
#[path = "support/device_fields.rs"]
mod device_fixture;
#[path = "plugin_model_fields_tests/device_ownership.rs"]
mod device_ownership;
#[path = "plugin_model_fields_tests/device_ownership_sets.rs"]
mod device_ownership_sets;
#[path = "plugin_model_fields_tests/device_redemption.rs"]
mod device_redemption;

#[path = "plugin_model_fields_tests/live_passkeys.rs"]
mod live_passkeys;

#[path = "plugin_model_fields_tests/organization.rs"]
mod organization;

#[path = "plugin_model_fields_tests/organization_order.rs"]
mod organization_order;

#[path = "plugin_model_fields_tests/presence.rs"]
mod presence;
#[path = "plugin_model_fields_tests/presence_cache.rs"]
mod presence_cache;

#[derive(Clone)]
struct Fields(Vec<(EntityRole, UserConfig)>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-model-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        for (role, fields) in &self.0 {
            context.register_model_fields(*role, fields.clone())?;
        }
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn fields(name: &str, field: UserFieldConfig) -> UserConfig {
    UserConfig {
        additional_fields: Some([(name.into(), field)].into()),
    }
}

fn config() -> AuthConfig {
    AuthConfig::new("ordinary-model-fields-secret-at-least-32-characters")
        .base_url("http://fields.test")
}

async fn sqlite() -> AuthResult<Arc<dyn AuthStore<BundledSchema>>> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| {
            AuthError::internal(format!("SQLite fixture connection failed: {error}"))
        })?;
    migrator::run_migrations(&database).await.map_err(|error| {
        AuthError::internal(format!("SQLite fixture migration failed: {error}"))
    })?;
    Ok(Arc::new(SeaOrmStore::<BundledSchema>::new(
        config(),
        database,
    )))
}

fn memory() -> Arc<dyn AuthStore<StatelessSchema>> {
    Arc::new(EphemeralStore::new(Arc::new(config())))
}

fn required<T>(value: Option<T>, context: &str) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal(context))
}

fn trace_lock<T>(trace: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Model field contract trace lock poisoned"))
}

fn input(owner: &str, name: &str) -> CreatePasskey {
    CreatePasskey {
        additional_fields: Default::default(),
        user_id: owner.into(),
        name: Some(name.into()).into(),
        credential_id: format!("credential:{name}"),
        public_key: "ordinary-public-key".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        credential: "ordinary-private-record".into(),
        aaguid: None.into(),
    }
}

async fn owner<S: AuthSchema>(store: &dyn AuthStore<S>, label: &str) -> AuthResult<String> {
    Ok(store
        .create_user(
            CreateUser::new()
                .with_name(label)
                .with_email(format!("{label}@fields.test")),
        )
        .await?
        .id
        .typed()?
        .clone())
}

fn original_error(error: AuthError, expected: &str) {
    assert!(matches!(error, AuthError::Internal(message) if message == expected));
}

async fn passkey_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let input_events = events.clone();
    let output_events = events.clone();
    let policy = UserFieldConfig {
        on_update: Some(Arc::new(|| "Renewed".into())),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&input_events)?.push(format!(
                    "input:{}",
                    required(value.json()?, "Expected a present JSON callback value")?
                ));
                if value == FieldValue::from("input-error") {
                    return Err(AuthError::internal("ordinary input error"));
                }
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => required(value.as_str(), "Expected a string field callback value")?
                        .trim()
                        .into(),
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                trace_lock(&output_events)?.push(format!(
                    "output:{}",
                    required(value.json()?, "Expected a present JSON callback value")?
                ));
                if value == FieldValue::from("output-error") {
                    return Err(AuthError::internal("ordinary output error"));
                }
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => format!(
                        "{}:out",
                        required(value.as_str(), "Expected a string field callback value")?
                    )
                    .into(),
                })
            })),
        }),
        ..Default::default()
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(EntityRole::Passkey, fields("name", policy))]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "passkey").await?;
    let created = auth
        .store()
        .create_passkey(input(&owner, "  Desk  "))
        .await?;
    assert_eq!(created.name.typed()?.as_deref(), Some("Desk:out"));
    assert_eq!(created.credential.typed()?, "ordinary-private-record");
    assert_eq!(
        *trace_lock(&events)?,
        ["input:\"  Desk  \"", "output:\"Desk\""]
    );
    let id = created.id.typed()?;
    assert_eq!(
        raw.get_passkey_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Desk")
    );
    let updated = auth.store().update_passkey_name(id, "  Mobile  ").await?;
    assert_eq!(updated.name.typed()?.as_deref(), Some("Mobile:out"));
    assert_eq!(
        auth.store()
            .get_passkey_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Mobile:out")
    );
    assert_eq!(
        auth.store()
            .get_passkey_by_credential_id(&created.credential_id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Mobile:out")
    );
    let renewed = auth
        .store()
        .update_passkey_authentication(
            &created.id,
            UpdatePasskeyAuthentication::Legacy {
                credential: created.credential.typed()?.clone(),
                counter: created.counter,
                backed_up: created.backed_up,
                device_type: created.device_type.clone(),
            },
        )
        .await?;
    assert_eq!(renewed.name.typed()?.as_deref(), Some("Renewed:out"));
    assert_eq!(
        raw.get_passkey_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Renewed")
    );
    let _ = auth
        .store()
        .create_passkey(input(&owner, " Travel "))
        .await?;
    trace_lock(&events)?.clear();
    let listed = auth.store().list_passkeys_by_user(&owner).await?;
    let expected_events: Vec<_> = listed
        .iter()
        .map(|row| {
            let name = required(
                row.name.typed()?.as_deref(),
                "Expected a projected passkey name",
            )?;
            let stored = required(
                name.strip_suffix(":out"),
                "Expected the passkey output suffix",
            )?;
            Ok(format!("output:{}", json!(stored)))
        })
        .collect::<AuthResult<_>>()?;
    assert_eq!(*trace_lock(&events)?, expected_events);
    let mut names: Vec<_> = listed
        .iter()
        .map(|row| {
            required(
                row.name.typed()?.clone(),
                "Expected a projected passkey name",
            )
        })
        .collect::<AuthResult<_>>()?;
    names.sort();
    assert_eq!(names, ["Renewed:out", "Travel:out"]);
    assert!(listed.iter().all(|row| row.credential
        == better_auth::SchemaValue::Typed("ordinary-private-record".to_owned())));
    let stored = raw.list_passkeys_by_user(&owner).await?;
    assert_eq!(
        listed.iter().map(|row| &row.id).collect::<Vec<_>>(),
        stored.iter().map(|row| &row.id).collect::<Vec<_>>()
    );

    trace_lock(&events)?.clear();
    let rollback_owner = owner.clone();
    let rollback: AuthResult<()> =
        better_auth_core::store::transaction(auth.store().as_ref(), |tx| {
            Box::pin(async move {
                let row = tx
                    .create_passkey(input(&rollback_owner, " Rollback "))
                    .await?;
                assert_eq!(row.name.typed()?.as_deref(), Some("Rollback:out"));
                Err(AuthError::internal("ordinary transaction rollback"))
            })
        })
        .await;
    original_error(
        rollback
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary transaction rollback",
    );
    assert!(
        raw.get_passkey_by_credential_id("credential: Rollback ")
            .await?
            .is_none()
    );
    assert_eq!(
        *trace_lock(&events)?,
        ["input:\" Rollback \"", "output:\"Rollback\""]
    );

    original_error(
        auth.store()
            .create_passkey(input(&owner, "input-error"))
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary input error",
    );
    assert_eq!(raw.list_passkeys_by_user(&owner).await?.len(), 2);
    original_error(
        auth.store()
            .update_passkey_name(id, "input-error")
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary input error",
    );
    assert_eq!(
        raw.get_passkey_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Renewed")
    );
    original_error(
        auth.store()
            .create_passkey(input(&owner, "output-error"))
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary output error",
    );
    assert_eq!(
        raw.get_passkey_by_credential_id("credential:output-error")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("output-error")
    );
    Ok(())
}

struct Call {
    stage: &'static str,
    value: FieldValue,
    reply: oneshot::Sender<AuthResult<FieldValue>>,
}

fn awaited(sender: mpsc::UnboundedSender<Call>, stage: &'static str) -> UserFieldTransform {
    UserFieldTransform::new_async(move |value| {
        let sender = sender.clone();
        async move {
            let (reply, result) = oneshot::channel();
            sender
                .send(Call {
                    stage,
                    value,
                    reply,
                })
                .map_err(|_| AuthError::internal("Callback controller closed"))?;
            result
                .await
                .map_err(|_| AuthError::internal("Callback answer missing"))?
        }
    })
}

async fn async_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let (sender, mut calls) = mpsc::unbounded_channel();
    let policy = UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(awaited(sender.clone(), "input")),
            output: Some(awaited(sender, "output")),
        }),
        ..Default::default()
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(EntityRole::Passkey, fields("name", policy))]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "async").await?;
    let store = auth.store().clone();
    let pending = tokio::spawn(async move { store.create_passkey(input(&owner, "Waiting")).await });
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(call.stage, "input");
    assert_eq!(call.value, FieldValue::from("Waiting"));
    assert!(
        raw.get_passkey_by_credential_id("credential:Waiting")
            .await?
            .is_none()
    );
    call.reply
        .send(Ok(FieldValue::from("Stored")))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(call.stage, "output");
    assert_eq!(call.value, FieldValue::from("Stored"));
    assert_eq!(
        raw.get_passkey_by_credential_id("credential:Waiting")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Stored")
    );
    call.reply
        .send(Ok(FieldValue::from("Projected")))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    assert_eq!(
        pending
            .await
            .map_err(|error| AuthError::internal(format!("Model field task failed: {error}")))??
            .name
            .typed()?
            .as_deref(),
        Some("Projected")
    );
    Ok(())
}

#[tokio::test]
async fn memory_passkey_fields_persist_project_and_propagate_original_errors() -> AuthResult<()> {
    passkey_contract(memory()).await
}
#[tokio::test]
async fn sqlite_passkey_fields_persist_project_and_propagate_original_errors() -> AuthResult<()> {
    passkey_contract(sqlite().await?).await
}
#[tokio::test]
async fn memory_passkey_callbacks_await_outside_storage_locks() -> AuthResult<()> {
    async_contract(memory()).await
}
#[tokio::test]
async fn sqlite_passkey_callbacks_await_before_and_after_storage() -> AuthResult<()> {
    async_contract(sqlite().await?).await
}
