use super::*;
use crate::middleware::EndpointRateLimit;
use crate::store::database_hooks::{DatabaseHookContext, SessionUpdate};
use crate::store::{JwksStore, RateLimitStore, WalletStore};
use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::OnceLock;

type Events = Arc<Mutex<Vec<JsonValue>>>;

#[derive(Clone, Copy)]
enum Model {
    Session,
    Jwk,
    Wallet,
}

impl Model {
    fn name(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Jwk => "jwks",
            Self::Wallet => "walletAddress",
        }
    }

    async fn create(self, store: &EphemeralStore, label: &str) -> AuthResult<JsonValue> {
        let additional_fields = [("label".into(), label.into())].into();
        let (id, fields) = match self {
            Self::Session => {
                let row = store
                    .create_session(CreateSession {
                        inherited_fields: Default::default(),
                        additional_fields,
                        user_id: "001".into(),
                        expires_at: fixed_date("2100-01-02T03:04:05.000Z")?,
                        ip_address: None,
                        user_agent: None,
                        impersonated_by: None,
                        active_organization_id: None,
                    })
                    .await?;
                (row.id, row.additional_fields)
            }
            Self::Jwk => {
                let row = store
                    .create_jwk(crate::CreateJwk {
                        created_at: fixed_date("2030-01-02T03:04:05.000Z")?,
                        public_key: format!("public-{label}"),
                        private_key: format!("private-{label}"),
                        expires_at: None,
                        alg: "EdDSA".into(),
                        crv: None,
                        additional_fields,
                    })
                    .await?;
                (row.id, row.additional_fields)
            }
            Self::Wallet => {
                let row = store
                    .create_wallet_address(crate::CreateWalletAddress {
                        user_id: "001".into(),
                        address: format!("serial-{label}"),
                        chain_id: 1,
                        is_primary: false,
                        created_at: fixed_date("2030-01-02T03:04:05.000Z")?,
                        additional_fields,
                    })
                    .await?;
                (row.id, row.additional_fields)
            }
        };
        observe_record(&id, &fields)
    }

    fn raw_ids(self, store: &EphemeralStore) -> AuthResult<JsonValue> {
        let state = store.lock()?;
        let ids = match self {
            Self::Session => state
                .sessions
                .snapshot()?
                .into_iter()
                .map(|row| row.id.field_value())
                .collect::<Vec<_>>(),
            Self::Jwk => state
                .jwks
                .snapshot()?
                .into_iter()
                .map(|row| row.get("id").cloned().unwrap_or_default())
                .collect(),
            Self::Wallet => state
                .wallets
                .snapshot()?
                .into_iter()
                .map(|row| row.get("id").cloned().unwrap_or_default())
                .collect(),
        };
        ids.iter()
            .map(observe)
            .collect::<AuthResult<Vec<_>>>()
            .map(JsonValue::Array)
    }
}

fn fixed_date(value: &str) -> AuthResult<crate::FieldDate> {
    value
        .parse::<DateTime<Utc>>()
        .map(Into::into)
        .map_err(|error| AuthError::internal(error.to_string()))
}

fn observe(value: &Value) -> AuthResult<JsonValue> {
    match value {
        Value::Undefined => Ok(json!({"type":"undefined"})),
        Value::Date(_) => Ok(json!({"type":"date", "value":required(value.json()?)?})),
        Value::Number(number) if !number.is_finite() => {
            Ok(json!({"type":"number", "value":crate::schema_value::number_string(*number)}))
        }
        value => required(value.json()?),
    }
}

fn observe_record(id: &crate::SchemaValue<String>, fields: &FieldMap) -> AuthResult<JsonValue> {
    Ok(json!({
        "id":observe(&id.field_value())?,
        "label":observe(required(fields.get("label"))?)?,
    }))
}

fn record(events: &Events, event: JsonValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Session plugin Serial event lock poisoned"))?
        .push(event);
    Ok(())
}

fn take_events(events: &Events) -> AuthResult<Vec<JsonValue>> {
    Ok(std::mem::take(&mut *events.lock().map_err(|_| {
        AuthError::internal("Session plugin Serial event lock poisoned")
    })?))
}

fn configured_store(
    model: Model,
    operation: &'static str,
    events: Events,
) -> AuthResult<Arc<EphemeralStore>> {
    let target = Arc::new(OnceLock::<Weak<EphemeralStore>>::new());
    let input_events = events.clone();
    let input_target = target.clone();
    let fields = UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new_async(move |value| {
                            let events = input_events.clone();
                            let target = input_target.clone();
                            async move {
                                record(&events, json!(["input", "label", observe(&value)?]))?;
                                if value.as_str() == Some("inner") && operation == "nested-failure"
                                {
                                    return Err(AuthError::internal("inner-field-failure"));
                                }
                                if value.as_str() == Some("outer") {
                                    let store = required(target.get().and_then(Weak::upgrade))?;
                                    let inner = model.create(&store, "inner").await?;
                                    record(&events, json!(["nested-created", inner]))?;
                                    if operation == "outer-failure" {
                                        return Err(AuthError::internal("outer-field-failure"));
                                    }
                                }
                                Ok(value)
                            }
                        })),
                        output: Some(UserFieldTransform::new(move |value| {
                            record(&events, json!(["output", "label", observe(&value)?]))?;
                            Ok(value)
                        })),
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let mut store = serial_store();
    match model {
        Model::Session => store.session_config.additional_fields = fields.additional_fields,
        Model::Jwk => store
            .model_fields
            .register(crate::store::schema::EntityRole::Jwk, fields)?,
        Model::Wallet => store
            .model_fields
            .register(crate::store::schema::EntityRole::WalletAddress, fields)?,
    }
    let store = Arc::new(store);
    target
        .set(Arc::downgrade(&store))
        .map_err(|_| AuthError::internal("Session plugin Serial target already assigned"))?;
    Ok(store)
}

fn captured_record(row: &JsonValue) -> AuthResult<JsonValue> {
    if row.is_null() {
        return Ok(JsonValue::Null);
    }
    Ok(json!({"id":required(row.get("id"))?, "label":required(row.get("label"))?}))
}

fn captured_ids(case: &JsonValue, phase: &str, model: Model) -> AuthResult<JsonValue> {
    required(required(required(case.get(phase))?.get(model.name()))?.as_array())?
        .iter()
        .map(|row| required(row.get("id")).cloned())
        .collect::<AuthResult<Vec<_>>>()
        .map(JsonValue::Array)
}

fn captured_event(event: &JsonValue) -> AuthResult<JsonValue> {
    match event.get(0).and_then(JsonValue::as_str) {
        Some("input" | "output" | "update-before") => Ok(event.clone()),
        Some("nested-created" | "update-after") => Ok(json!([
            required(event.get(0))?,
            captured_record(required(event.get(1))?)?,
        ])),
        _ => Err(AuthError::internal(
            "Unexpected event in the Serial ID contract",
        )),
    }
}

fn fixture() -> AuthResult<JsonValue> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/session-jwk-wallet-rate-limit-serial-1.7.6.json"
    )))?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(
        required(fixture.get("cases").and_then(JsonValue::as_array))?.len(),
        53
    );
    Ok(fixture)
}

#[tokio::test]
async fn serial_session_jwk_wallet_nested_creation_matches_upstream_id_contract() -> AuthResult<()>
{
    let fixture = fixture()?;
    let cases = required(fixture.get("cases").and_then(JsonValue::as_array))?;
    // Session creation generates its token and timestamps internally. Compare the ID contract;
    // the Bun contract retains strict full-row comparison, configured ID slots, and generic deletion.
    for model in [Model::Session, Model::Jwk, Model::Wallet] {
        for operation in ["nested-success", "nested-failure", "outer-failure"] {
            let case = required(cases.iter().find(|case| {
                case.get("model").and_then(JsonValue::as_str) == Some(model.name())
                    && case.get("slot").and_then(JsonValue::as_str) == Some("implicit")
                    && case.get("operation").and_then(JsonValue::as_str) == Some(operation)
            }))?;
            let events = Events::default();
            let store = configured_store(model, operation, events.clone())?;
            let before = model.raw_ids(&store)?;
            let (result, error) = match model.create(&store, "outer").await {
                Ok(row) => (row, JsonValue::Null),
                Err(AuthError::Internal(message)) => {
                    (JsonValue::Null, json!({"name":"Error", "message":message}))
                }
                Err(error) => return Err(error),
            };
            assert_eq!(
                json!({"before":before, "events":take_events(&events)?, "result":result,
                    "error":error, "after":model.raw_ids(&store)?}),
                json!({"before":captured_ids(case, "before", model)?,
                    "events":required(case.get("events").and_then(JsonValue::as_array))?.iter()
                        .map(captured_event).collect::<AuthResult<Vec<_>>>()?,
                    "result":captured_record(required(case.get("result"))?)?,
                    "error":required(case.get("error"))?, "after":captured_ids(case, "after", model)?}),
                "{} {operation}",
                model.name(),
            );
        }
    }
    Ok(())
}

struct SessionEvents(Events);

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for SessionEvents {
    async fn before_update_session(
        &self,
        update: &mut crate::FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<crate::store::database_hooks::DatabaseHookUpdate<crate::FieldMap>> {
        let fields = update.clone();
        let patch = fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), observe(value)?)))
            .collect::<AuthResult<serde_json::Map<_, _>>>()?;
        record(&self.0, json!(["update-before", patch]))?;
        Ok(crate::store::database_hooks::DatabaseHookUpdate::Continue)
    }

    async fn after_update_session(
        &self,
        row: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let row = required(row)?;
        record(
            &self.0,
            json!([
                "update-after",
                observe_record(&row.id, &row.additional_fields)?
            ]),
        )
    }
}

#[tokio::test]
async fn serial_session_string_id_updates_match_upstream_id_contract() -> AuthResult<()> {
    let fixture = fixture()?;
    let cases = required(fixture.get("cases").and_then(JsonValue::as_array))?;
    // This fixture checks string ID conversion. The shared ID-slot contracts cover native ID inputs.
    for (name, id) in [
        ("omitted", None),
        ("empty-string", Some("")),
        ("zero-string", Some("0")),
        ("whitespace", Some(" ")),
        ("padded-number", Some("002")),
        ("hex-number", Some("0x2")),
        ("invalid-string", Some("not-a-number")),
        ("infinity-string", Some("Infinity")),
    ] {
        let case = required(
            cases
                .iter()
                .find(|case| case.get("name").and_then(JsonValue::as_str) == Some(name)),
        )?;
        let events = Events::default();
        let configured = configured_store(Model::Session, "id-update", events.clone())?;
        let store = configured
            .as_ref()
            .clone()
            .with_hooks(vec![Arc::new(SessionEvents(events.clone()))]);
        let seeded = Model::Session.create(&store, "first").await?;
        let seed_events = take_events(&events)?;
        let token = required(store.lock()?.sessions.snapshot()?.first())?
            .token
            .typed()?
            .clone();
        let before = Model::Session.raw_ids(&store)?;
        let updated = required(
            store
                .update_session_with_writer(
                    &token,
                    SessionUpdate {
                        id: id.map(str::to_owned),
                        updated_at: Some(fixed_date("2030-01-02T03:04:05.000Z")?),
                        ..Default::default()
                    },
                    None,
                )
                .await?,
        )?;
        let read = required(store.get_session(&token).await?)?;
        let expected_events = required(case.get("events").and_then(JsonValue::as_array))?;
        let after_hook =
            required(expected_events.iter().position(|event| {
                event.get(0).and_then(JsonValue::as_str) == Some("update-after")
            }))?;
        // Retain callbacks through the token read. Rust has no public Session lookup by primary ID.
        let expected_events = required(expected_events.get(..after_hook + 2))?
            .iter()
            .map(captured_event)
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(
            json!({"seeded":seeded, "seedEvents":seed_events, "before":before,
                "events":take_events(&events)?, "result":observe_record(&updated.id, &updated.additional_fields)?,
                "byToken":observe_record(&read.id, &read.additional_fields)?, "error":null,
                "after":Model::Session.raw_ids(&store)?}),
            json!({"seeded":captured_record(required(case.get("seeded"))?)?,
                "seedEvents":required(case.get("seedEvents"))?, "before":captured_ids(case, "before", Model::Session)?,
                "events":expected_events, "result":captured_record(required(case.get("result"))?)?,
                "byToken":captured_record(required(required(case.get("reads"))?.get("byToken"))?)?,
                "error":required(case.get("error"))?, "after":captured_ids(case, "after", Model::Session)?}),
            "{name}",
        );
    }
    Ok(())
}

#[tokio::test]
async fn serial_jwk_padded_lookup_matches_complete_upstream_lifecycle() -> AuthResult<()> {
    let fixture = fixture()?;
    let case = required(
        required(fixture.get("cases").and_then(JsonValue::as_array))?
            .iter()
            .find(|case| {
                case.get("model").and_then(JsonValue::as_str) == Some("jwks")
                    && case.get("operation").and_then(JsonValue::as_str) == Some("lifecycle")
            }),
    )?;
    let events = Events::default();
    let store = configured_store(Model::Jwk, "lifecycle", events.clone())?;
    let mut operations = Vec::new();
    for (name, label) in [("create-first", "first"), ("create-second", "second")] {
        record(&events, json!(["operation", name]))?;
        let result = Model::Jwk.create(&store, label).await?;
        operations.push(json!({"name":name, "result":result, "after":Model::Jwk.raw_ids(&store)?}));
    }
    record(&events, json!(["operation", "read-padded-id"]))?;
    let read = required(store.get_jwk("001").await?)?;
    operations.push(
        json!({"name":"read-padded-id", "result":observe_record(&read.id, &read.additional_fields)?,
        "after":Model::Jwk.raw_ids(&store)?}),
    );
    let observe_fields = |fields: FieldMap| -> AuthResult<JsonValue> {
        Ok(json!({
            "id": observe(required(fields.get("id"))?)?,
            "label": observe(required(fields.get("label"))?)?,
        }))
    };
    for name in [
        "update-padded-id",
        "delete-padded-id",
        "read-deleted-id",
        "create-after-removal",
        "read-all",
    ] {
        record(&events, json!(["operation", name]))?;
        let result = match name {
            "update-padded-id" => observe_fields(required(
                store
                    .update_jwk_record(&"001".into(), [("label".into(), "updated".into())].into())
                    .await?,
            )?)?,
            "delete-padded-id" => {
                store.delete_jwk_record(&"001".into()).await?;
                json!({"type": "undefined"})
            }
            "read-deleted-id" => store
                .get_jwk_record(&"001".into())
                .await?
                .map(observe_fields)
                .transpose()?
                .unwrap_or(JsonValue::Null),
            "create-after-removal" => Model::Jwk.create(&store, "third").await?,
            "read-all" => JsonValue::Array(
                store
                    .list_jwk_records()
                    .await?
                    .into_iter()
                    .map(observe_fields)
                    .collect::<AuthResult<_>>()?,
            ),
            _ => return Err(AuthError::internal("Unknown JWK lifecycle operation")),
        };
        operations
            .push(json!({"name": name, "result": result, "after": Model::Jwk.raw_ids(&store)?}));
    }
    let expected_operations = required(case.get("operations").and_then(JsonValue::as_array))?
        .iter()
        .map(|step| {
            let result = required(step.get("result"))?;
            let result = if result.is_null() || result.get("type") == Some(&json!("undefined")) {
                result.clone()
            } else if let Some(rows) = result.as_array() {
                JsonValue::Array(
                    rows.iter()
                        .map(captured_record)
                        .collect::<AuthResult<_>>()?,
                )
            } else {
                captured_record(result)?
            };
            Ok(json!({"name":required(step.get("name"))?, "result": result,
                "after":captured_ids(step, "after", Model::Jwk)?}))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let expected_events = required(case.get("events").and_then(JsonValue::as_array))?.clone();
    assert_eq!(operations, expected_operations);
    assert_eq!(take_events(&events)?, expected_events);
    Ok(())
}

#[tokio::test]
async fn serial_wallet_owner_binding_matches_complete_upstream_rows() -> AuthResult<()> {
    let fixture = fixture()?;
    let case = required(
        required(fixture.get("cases").and_then(JsonValue::as_array))?
            .iter()
            .find(|case| {
                case.get("model").and_then(JsonValue::as_str) == Some("walletAddress")
                    && case.get("operation").and_then(JsonValue::as_str) == Some("lifecycle")
            }),
    )?;
    let store = configured_store(Model::Wallet, "lifecycle", Events::default())?;
    let created = store
        .create_wallet_address(crate::CreateWalletAddress {
            user_id: "001".into(),
            address: "serial-first".into(),
            chain_id: 1,
            is_primary: false,
            created_at: fixed_date("2030-01-02T03:04:05.000Z")?,
            additional_fields: [("label".into(), "first".into())].into(),
        })
        .await?;
    let observe_fields = |row: &FieldMap| -> AuthResult<JsonValue> {
        row.iter()
            .map(|(name, value)| Ok((name.clone(), observe(value)?)))
            .collect::<AuthResult<serde_json::Map<_, _>>>()
            .map(JsonValue::Object)
    };
    let first = required(required(case.get("operations"))?.get(0))?;
    assert_eq!(
        observe_fields(&created.field_values()?)?,
        *required(first.get("result"))?
    );
    let raw = store
        .lock()?
        .wallets
        .snapshot()?
        .iter()
        .map(observe_fields)
        .collect::<AuthResult<Vec<_>>>()?;
    assert_eq!(
        json!(raw),
        *required(required(first.get("after"))?.get("walletAddress"))?
    );
    let read = required(store.get_wallet_address("serial-first", Some(1)).await?)?;
    assert_eq!(
        observe_fields(&read.field_values()?)?,
        observe_fields(&created.field_values()?)?
    );
    Ok(())
}

#[tokio::test]
async fn serial_rate_limit_consumption_keeps_numeric_ids_and_reuses_existing_records()
-> AuthResult<()> {
    let store = serial_store();
    let rule = EndpointRateLimit {
        window: 3600.0,
        max_requests: 2.0,
    };
    for expected in [true, true, false] {
        assert_eq!(
            store
                .consume_rate_limit("first", rule, 3600.0)
                .await?
                .allowed,
            expected
        );
    }
    assert!(
        store
            .consume_rate_limit("second", rule, 3600.0)
            .await?
            .allowed
    );
    let state = store.lock()?;
    let first = required(state.rate_limits.get("first"))?;
    let second = required(state.rate_limits.get("second"))?;
    assert_eq!(
        (first.id.field_value(), first.count),
        (Value::Number(1.0), 2.0)
    );
    assert_eq!(
        (second.id.field_value(), second.count),
        (Value::Number(2.0), 1.0)
    );
    assert_eq!(state.rate_limits.len(), 2);
    Ok(())
}

#[tokio::test]
async fn serial_session_token_deletion_preserves_duplicate_ids_after_reuse() -> AuthResult<()> {
    let store = serial_store();
    let mut tokens = Vec::new();
    for expected in ["1", "2", "3"] {
        let row = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields: FieldMap::new(),
                user_id: "001".into(),
                expires_at: fixed_date("2100-01-02T03:04:05.000Z")?,
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        assert_eq!(row.id, expected);
        tokens.push(row.token.typed()?.clone());
    }
    store.delete_session(required(tokens.get(1))?).await?;
    let reused = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: FieldMap::new(),
            user_id: "001".into(),
            expires_at: fixed_date("2100-01-02T03:04:05.000Z")?,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    assert_eq!(reused.id, "3");
    assert_eq!(Model::Session.raw_ids(&store)?, json!([1, 3, 3]));
    store.delete_session(required(tokens.get(2))?).await?;
    assert!(store.get_session(required(tokens.get(2))?).await?.is_none());
    assert_eq!(
        required(store.get_session(reused.token.typed().unwrap()).await?)?.id,
        "3"
    );
    assert_eq!(Model::Session.raw_ids(&store)?, json!([1, 3]));
    Ok(())
}
