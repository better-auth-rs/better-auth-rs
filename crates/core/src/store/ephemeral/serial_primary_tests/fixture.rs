use super::*;
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::OnceLock;

type Events = Arc<Mutex<Vec<JsonValue>>>;

#[derive(Clone, Copy)]
enum Model {
    Account,
    Verification,
}

impl Model {
    fn name(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Verification => "verification",
        }
    }

    async fn create(self, store: &EphemeralStore, label: &str) -> AuthResult<JsonValue> {
        let date = fixed_date("2030-01-02T03:04:05.000Z")?;
        let additional_fields = [("label".into(), label.into())].into();
        let fields = match self {
            Self::Account => store
                .create_account(CreateAccount {
                    account_id: format!("serial-{label}").into(),
                    provider_id: "ordinary".into(),
                    user_id: "001".into(),
                    created_at: date.clone().into(),
                    updated_at: date.into(),
                    additional_fields,
                    ..Default::default()
                })
                .await?
                .field_values()?,
            Self::Verification => store
                .create_verification(CreateVerification {
                    identifier: format!("serial-{label}").into(),
                    value: format!("value-{label}").into(),
                    expires_at: fixed_date("2100-01-02T03:04:05.000Z")?.into(),
                    created_at: date.clone().into(),
                    updated_at: date.into(),
                    additional_fields,
                    ..Default::default()
                })
                .await?
                .field_values()?,
        };
        assert!(matches!(fields.get("id"), Some(Value::String(_))));
        observe_fields(&fields)
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
        value => required(value.json()?),
    }
}

fn observe_fields(fields: &FieldMap) -> AuthResult<JsonValue> {
    fields
        .iter()
        .map(|(name, value)| Ok((name.clone(), observe(value)?)))
        .collect::<AuthResult<serde_json::Map<_, _>>>()
        .map(JsonValue::Object)
}

fn raw_memory(store: &EphemeralStore) -> AuthResult<JsonValue> {
    let state = store.lock()?;
    let users = state
        .users
        .snapshot()?
        .iter()
        .map(|user| {
            let mut fields = FieldMap::new();
            for name in [
                "name",
                "email",
                "emailVerified",
                "image",
                "createdAt",
                "updatedAt",
                "id",
            ] {
                let _ = fields.insert(name.into(), required(user.native_field_value(name))?);
            }
            observe_fields(&fields)
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let accounts = state.accounts.snapshot()?;
    let verifications = state.verifications.snapshot()?;
    for row in accounts.iter().chain(&verifications) {
        assert!(matches!(row.get("id"), Some(Value::Number(_))));
    }
    let sessions = state
        .sessions
        .snapshot()?
        .iter()
        .map(|session| observe_fields(&session.field_values()?))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({
        "user":users,
        "account":accounts.iter().map(observe_fields).collect::<AuthResult<Vec<_>>>()?,
        "session":sessions,
        "verification":verifications.iter().map(observe_fields).collect::<AuthResult<Vec<_>>>()?,
    }))
}

fn record(events: &Events, event: JsonValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Serial event lock poisoned"))?
        .push(event);
    Ok(())
}

async fn capture(
    model: Model,
    slot: &'static str,
    operation: &'static str,
) -> AuthResult<JsonValue> {
    let events = Events::default();
    let target = Arc::new(OnceLock::<Weak<EphemeralStore>>::new());
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    let fields = match model {
        Model::Account => &mut config.account.additional_fields,
        Model::Verification => &mut config.verification.additional_fields,
    };
    if slot == "before-label" {
        let input_events = events.clone();
        let output_events = events.clone();
        let _ = fields.insert(
            "id".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        record(&input_events, json!(["input", "id", observe(&value)?]))?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        record(&output_events, json!(["output", "id", observe(&value)?]))?;
                        Ok(value)
                    })),
                }),
                ..Default::default()
            },
        );
    }
    let input_events = events.clone();
    let output_events = events.clone();
    let input_target = target.clone();
    let _ = fields.insert(
        "label".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async(move |value| {
                    let events = input_events.clone();
                    let target = input_target.clone();
                    async move {
                        record(&events, json!(["input", "label", observe(&value)?]))?;
                        if value.as_str() == Some("inner") && operation == "nested-failure" {
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
                    record(&output_events, json!(["output", "label", observe(&value)?]))?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let store = Arc::new(EphemeralStore::new(Arc::new(config)));
    target
        .set(Arc::downgrade(&store))
        .map_err(|_| AuthError::internal("Serial target already assigned"))?;
    if matches!(model, Model::Account) {
        let date = fixed_date("2030-01-02T03:04:05.000Z")?;
        let _ = store
            .create_user(CreateUser {
                name: Some("Account owner".into()).into(),
                email: Some("owner@record-serial.test".into()),
                email_verified: Some(false),
                image: None::<String>.into(),
                created_at: Some(date.clone()),
                updated_at: Some(date),
                ..Default::default()
            })
            .await?;
    }
    let before = raw_memory(&store)?;
    let (result, error) = match model.create(&store, "outer").await {
        Ok(result) => (result, JsonValue::Null),
        Err(AuthError::Internal(message)) => {
            (JsonValue::Null, json!({"name":"Error", "message":message}))
        }
        Err(error) => return Err(error),
    };
    let after = raw_memory(&store)?;
    let events = events
        .lock()
        .map_err(|_| AuthError::internal("Serial event lock poisoned"))?
        .clone();
    Ok(json!({
        "model":model.name(), "slot":slot, "operation":operation,
        "before":before, "events":events, "result":result, "error":error, "after":after,
    }))
}

#[tokio::test]
async fn serial_primary_creation_matches_all_twelve_upstream_cases() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/account-verification-serial-primary-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    let expected = required(fixture["cases"].as_array())?;
    assert_eq!(expected.len(), 14);
    let mut index = 0;
    for model in [Model::Account, Model::Verification] {
        for slot in ["implicit", "before-label"] {
            for operation in ["nested-success", "nested-failure", "outer-failure"] {
                assert_eq!(capture(model, slot, operation).await?, expected[index]);
                index += 1;
            }
        }
        // Generic adapter findOne(id) and findMany have no matching public Rust store methods.
        // Retain both lifecycle observations in the fixture and the upstream regression.
        assert_eq!(expected[index]["model"], model.name());
        assert_eq!(expected[index]["operation"], "lifecycle");
        index += 1;
    }
    assert_eq!(index, expected.len());
    Ok(())
}
