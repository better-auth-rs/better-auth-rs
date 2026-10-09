use super::*;
use crate::id::{IdGeneration, IdGenerator};
use crate::store::{JwksStore, WalletStore};
use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

const CREATED_AT: &str = "2030-01-02T03:04:05.000Z";
type Events = Arc<Mutex<Vec<JsonValue>>>;
type Target = Arc<OnceLock<Weak<EphemeralStore>>>;

#[derive(Clone, Copy)]
enum Model {
    Jwk,
    Wallet,
}

impl Model {
    fn name(self) -> &'static str {
        match self {
            Self::Jwk => "jwks",
            Self::Wallet => "walletAddress",
        }
    }

    fn role(self) -> EntityRole {
        match self {
            Self::Jwk => EntityRole::Jwk,
            Self::Wallet => EntityRole::WalletAddress,
        }
    }

    fn data(self, label: &str, owner: &str) -> AuthResult<FieldMap> {
        let mut fields = match self {
            Self::Jwk => FieldMap::from([
                ("publicKey".into(), format!("public-{label}").into()),
                ("privateKey".into(), format!("private-{label}").into()),
                ("createdAt".into(), date()?.into()),
                ("expiresAt".into(), Value::Null),
                ("alg".into(), "EdDSA".into()),
                ("crv".into(), Value::Null),
            ]),
            Self::Wallet => FieldMap::from([
                ("userId".into(), owner.into()),
                ("address".into(), format!("slot-{label}").into()),
                ("chainId".into(), 1.into()),
                ("isPrimary".into(), false.into()),
                ("createdAt".into(), date()?.into()),
            ]),
        };
        let _ = fields.insert("label".into(), label.into());
        Ok(fields)
    }

    fn request(self, label: &str, owner: &str) -> AuthResult<JsonValue> {
        Ok(json!({"model":self.name(), "data":observe_fields(self.data(label, owner)?, false)?}))
    }

    async fn create(
        self,
        store: &EphemeralStore,
        label: &str,
        owner: &str,
    ) -> AuthResult<JsonValue> {
        let fields = match self {
            Self::Jwk => store.create_jwk_record(self.data(label, owner)?).await?,
            Self::Wallet => {
                store
                    .create_wallet_address_record(self.data(label, owner)?)
                    .await?
            }
        };
        observe_fields(required(fields)?, false)
    }

    async fn get(self, store: &EphemeralStore, id: &str) -> AuthResult<JsonValue> {
        let fields = match self {
            Self::Jwk => required(store.get_jwk_record(&id.into()).await?)?,
            Self::Wallet => required(store.get_wallet_address_record(&id.into()).await?)?,
        };
        observe_fields(fields, false)
    }

    async fn write_selected_id(self, store: &EphemeralStore) -> AuthResult<JsonValue> {
        let update = [("id".into(), "00101".into())].into();
        let row = match self {
            Self::Jwk => store.update_jwk_record(&"1".into(), update).await?,
            Self::Wallet => {
                store
                    .update_wallet_address_record(&"1".into(), update)
                    .await?
            }
        };
        observe_fields(required(row)?, false)
    }
}

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("ID slot fixture value is missing"))
}

fn date() -> AuthResult<crate::FieldDate> {
    CREATED_AT
        .parse::<DateTime<Utc>>()
        .map(Into::into)
        .map_err(|error| AuthError::internal(format!("Invalid ID slot fixture date: {error}")))
}

fn observe_fields(fields: FieldMap, raw: bool) -> AuthResult<JsonValue> {
    let mut observed = serde_json::Map::new();
    for (name, value) in fields {
        // Native Undefined represents an omitted stored ID; output traversal materializes the undefined ID slot.
        if raw && name == "id" && value.is_undefined() {
            continue;
        }
        let value = match &value {
            Value::Undefined => json!({"type":"undefined"}),
            Value::Date(_) => json!({"type":"date", "value":required(value.json()?)?}),
            value => required(value.json()?)?,
        };
        let _ = observed.insert(name, value);
    }
    Ok(JsonValue::Object(observed))
}

fn observe_user(row: &UserView) -> AuthResult<JsonValue> {
    let fields = [
        "id",
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
    ]
    .into_iter()
    .map(|name| Ok((name.into(), required(row.native_field_value(name))?)))
    .collect::<AuthResult<FieldMap>>()?;
    observe_fields(fields, true)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The fixture asserts that unrelated tables remain empty while propagating storage and serialization errors"
)]
fn observe_memory(store: &EphemeralStore) -> AuthResult<JsonValue> {
    let state = store.lock()?;
    let users = state
        .users
        .snapshot()?
        .iter()
        .map(observe_user)
        .collect::<AuthResult<Vec<_>>>()?;
    let jwks = state
        .jwks
        .snapshot()?
        .iter()
        .map(|row| observe_fields(row.clone(), true))
        .collect::<AuthResult<Vec<_>>>()?;
    let wallets = state
        .wallets
        .snapshot()?
        .iter()
        .map(|row| observe_fields(row.clone(), true))
        .collect::<AuthResult<Vec<_>>>()?;
    assert!(state.accounts.snapshot()?.is_empty());
    assert!(state.sessions.snapshot()?.is_empty());
    assert!(state.verifications.snapshot()?.is_empty());
    Ok(
        json!({"user":users, "account":[], "session":[], "verification":[], "jwks":jwks, "walletAddress":wallets}),
    )
}

fn events_lock(events: &Events) -> AuthResult<MutexGuard<'_, Vec<JsonValue>>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("ID slot event lock poisoned"))
}

fn record(events: &Events, event: JsonValue) -> AuthResult<()> {
    events_lock(events)?.push(event);
    Ok(())
}

fn target_store(target: &Target) -> AuthResult<Arc<EphemeralStore>> {
    required(target.get().and_then(Weak::upgrade))
}

fn set_target(target: &Target, store: &Arc<EphemeralStore>) -> AuthResult<()> {
    target
        .set(Arc::downgrade(store))
        .map_err(|_| AuthError::internal("ID slot target already assigned"))
}

fn configured_id(events: &Events) -> UserFieldConfig {
    let input_events = events.clone();
    let output_events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(
                    &input_events,
                    json!(["input", "id", required(value.json()?)?]),
                )?;
                Err(AuthError::internal("configured-id-input-called"))
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(
                    &output_events,
                    json!(["output", "id", required(value.json()?)?]),
                )?;
                Err(AuthError::internal("configured-id-output-called"))
            })),
        }),
        ..Default::default()
    }
}

fn reader(
    writer: &Arc<EphemeralStore>,
    model: Model,
    before_label: bool,
    serial: bool,
    events: &Events,
) -> AuthResult<Arc<EphemeralStore>> {
    let target = Target::default();
    let input_target = target.clone();
    let input_events = events.clone();
    let output_events = events.clone();
    let output_writer = writer.clone();
    let owner = if serial { "1" } else { "ordinary-owner" };
    let label = UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = input_target.clone();
                let events = input_events.clone();
                async move {
                    record(&events, json!(["input", "label", required(value.json()?)?]))?;
                    if !serial && value.as_str() == Some("outer") {
                        let store = target_store(&target)?;
                        record(
                            &events,
                            json!([
                                "nested-create",
                                model.request("inner", owner)?,
                                observe_memory(&store)?
                            ]),
                        )?;
                        let inner = model.create(&store, "inner", owner).await?;
                        record(
                            &events,
                            json!(["nested-created", inner, observe_memory(&store)?]),
                        )?;
                    }
                    Ok(value)
                }
            })),
            output: Some(UserFieldTransform::new_async(move |value| {
                let writer = output_writer.clone();
                let events = output_events.clone();
                async move {
                    record(
                        &events,
                        json!(["output", "label", required(value.json()?)?]),
                    )?;
                    if serial {
                        let input = json!({"model":model.name(), "where":[{"field":"id", "value":"1"}], "update":{"id":"00101"}});
                        record(
                            &events,
                            json!(["writer-update", input, observe_memory(&writer)?]),
                        )?;
                        let updated = model.write_selected_id(&writer).await?;
                        record(
                            &events,
                            json!(["writer-updated", updated, observe_memory(&writer)?]),
                        )?;
                        return Ok(format!("{}:out", required(value.as_str())?).into());
                    }
                    Ok(value)
                }
            })),
        }),
        ..Default::default()
    };
    let id = configured_id(events);
    let fields = if before_label {
        [("id".into(), id), ("label".into(), label)]
    } else {
        [("label".into(), label), ("id".into(), id)]
    };
    let mut store = writer.as_ref().clone();
    store.model_fields = Default::default();
    store.model_fields.register(
        model.role(),
        UserConfig {
            additional_fields: Some(fields.into()),
        },
    );
    let store = Arc::new(store);
    set_target(&target, &store)?;
    Ok(store)
}

async fn seed_owner(writer: &EphemeralStore, serial: bool) -> AuthResult<JsonValue> {
    let id = if serial { "001" } else { "ordinary-owner" };
    let fields = FieldMap::from([
        ("id".into(), id.into()),
        ("name".into(), "Record owner".into()),
        ("email".into(), "owner@adapter-id-slot.test".into()),
        ("emailVerified".into(), false.into()),
        ("image".into(), Value::Null),
        ("createdAt".into(), date()?.into()),
        ("updatedAt".into(), date()?.into()),
    ]);
    let input = json!({"model":"user", "forceAllowId":true, "data":observe_fields(fields, false)?});
    let before = observe_memory(writer)?;
    let owner = writer
        .create_user(CreateUser {
            id: Some(id.into()),
            name: Some("Record owner".into()).into(),
            email: Some("owner@adapter-id-slot.test".into()),
            email_verified: Some(false),
            image: None::<String>.into(),
            created_at: Some(date()?),
            updated_at: Some(date()?),
            ..Default::default()
        })
        .await?;
    Ok(
        json!({"input":input, "before":before, "result":observe_user(&owner)?, "after":observe_memory(writer)?}),
    )
}

async fn capture(model: Model, slot: &str, operation: &str) -> AuthResult<JsonValue> {
    let serial = operation == "live-output-id-write";
    let events = Events::default();
    let target = Target::default();
    let generate_target = target.clone();
    let generate_events = events.clone();
    let sequence = AtomicUsize::new(0);
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(if serial {
        IdGeneration::Serial
    } else {
        IdGeneration::Custom(IdGenerator::new(move |request| {
            assert_eq!(request.size, None);
            let id = format!(
                "{}-generated-{}",
                request.model,
                sequence.fetch_add(1, Ordering::SeqCst) + 1
            );
            let store = target_store(&generate_target)?;
            record(
                &generate_events,
                json!(["generateId", {"model":request.model}, id, observe_memory(&store)?]),
            )?;
            Ok(Some(id))
        }))
    });
    let mut writer = EphemeralStore::new(Arc::new(config));
    writer.model_fields.register(
        model.role(),
        UserConfig {
            additional_fields: Some(
                [
                    ("id".into(), UserFieldConfig::default()),
                    ("label".into(), UserFieldConfig::default()),
                ]
                .into(),
            ),
        },
    );
    let writer = Arc::new(writer);
    set_target(&target, &writer)?;
    let mut setup = Vec::new();
    if matches!(model, Model::Wallet) {
        setup.push(seed_owner(&writer, serial).await?);
    }
    let reader = reader(&writer, model, slot == "before-label", serial, &events)?;
    let owner = if serial { "1" } else { "ordinary-owner" };
    if serial {
        let input = model.request("selected", owner)?;
        let before = observe_memory(&writer)?;
        let result = model.create(&writer, "selected", owner).await?;
        setup.push(json!({"input":input, "before":before, "result":result, "after":observe_memory(&writer)?}));
    }
    let seed_events = std::mem::take(&mut *events_lock(&events)?);
    let before = observe_memory(&writer)?;
    let (input, result) = if serial {
        (
            json!({"model":model.name(), "where":[{"field":"id", "value":"1"}]}),
            model.get(&reader, "1").await?,
        )
    } else {
        (
            model.request("outer", owner)?,
            model.create(&reader, "outer", owner).await?,
        )
    };
    let after = observe_memory(&writer)?;
    let events = events_lock(&events)?.clone();
    Ok(
        json!({"model":model.name(), "slot":slot, "operation":operation, "idGeneration":if serial { "serial" } else { "custom" }, "setup":setup, "seedEvents":seed_events, "before":before, "input":input, "events":events, "result":result, "error":null, "after":after}),
    )
}

#[tokio::test]
async fn memory_plugin_id_slot_matches_eight_upstream_cases() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-id-slot-1.7.6.json"
    )))?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("backend"), Some(&json!("memory")));
    let cases = required(fixture.get("cases").and_then(JsonValue::as_array))?;
    assert_eq!(cases.len(), 25);
    let mut compared = 0;
    for model in [Model::Jwk, Model::Wallet] {
        for slot in ["before-label", "after-label"] {
            for operation in ["nested-create", "live-output-id-write"] {
                let expected = required(cases.iter().find(|case| {
                    case.get("model").and_then(JsonValue::as_str) == Some(model.name())
                        && case.get("slot").and_then(JsonValue::as_str) == Some(slot)
                        && case.get("operation").and_then(JsonValue::as_str) == Some(operation)
                }))?;
                assert_eq!(
                    capture(model, slot, operation).await?,
                    *expected,
                    "{} {slot} {operation}",
                    model.name()
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 8);
    Ok(())
}
