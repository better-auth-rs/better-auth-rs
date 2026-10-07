use super::*;
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::OnceLock;

type Events = Arc<Mutex<Vec<JsonValue>>>;

fn record(events: &Events, event: JsonValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Serial event lock poisoned"))?
        .push(event);
    Ok(())
}

fn input(label: &str) -> AuthResult<CreateUser> {
    let date = "2030-01-02T03:04:05.000Z"
        .parse::<DateTime<Utc>>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok(CreateUser {
        name: Some(
            if label == "outer" {
                "Outer owner"
            } else {
                "Inner owner"
            }
            .into(),
        )
        .into(),
        email: Some(format!("{label}@serial-order.test")),
        email_verified: Some(false),
        image: None::<String>.into(),
        created_at: Some(date.into()),
        updated_at: Some(date.into()),
        additional_fields: [("label".into(), label.into())].into(),
        ..Default::default()
    })
}

fn observation(user: &UserView, slot: &str) -> AuthResult<JsonValue> {
    let mut fields = FieldMap::new();
    for name in [
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
    ] {
        let _ = fields.insert(name.into(), required(user.native_field_value(name))?);
    }
    if slot == "before-label" {
        let _ = fields.insert("id".into(), user.id.field_value());
    }
    let _ = fields.insert(
        "label".into(),
        required(user.additional_fields.get("label"))?.clone(),
    );
    let _ = fields.insert("id".into(), user.id.field_value());
    Ok(JsonValue::Object(fields.json()?))
}

fn raw_rows(store: &EphemeralStore, slot: &str) -> AuthResult<Vec<JsonValue>> {
    store
        .lock()?
        .users
        .snapshot()?
        .iter()
        .map(|user| observation(user, slot))
        .collect()
}

async fn capture(slot: &'static str, operation: &'static str) -> AuthResult<JsonValue> {
    let events = Events::default();
    let target = Arc::new(OnceLock::<Weak<EphemeralStore>>::new());
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    if slot == "before-label" {
        let input_events = events.clone();
        let output_events = events.clone();
        let _ = config.user.fields_mut().insert(
            "id".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        record(&input_events, json!(["input", "id", value.json()?]))?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        record(&output_events, json!(["output", "id", value.json()?]))?;
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
    let _ = config.user.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async(move |value| {
                    let events = input_events.clone();
                    let target = input_target.clone();
                    async move {
                        record(&events, json!(["input", "label", value.json()?]))?;
                        if value.as_str() == Some("inner") && operation == "nested-failure" {
                            return Err(AuthError::internal("inner-field-failure"));
                        }
                        if value.as_str() == Some("outer") {
                            let store = required(target.get().and_then(Weak::upgrade))?;
                            let inner = store.create_user(input("inner")?).await?;
                            assert!(matches!(inner.id.field_value(), Value::String(_)));
                            record(
                                &events,
                                json!(["nested-created", observation(&inner, slot)?]),
                            )?;
                            if operation == "outer-failure" {
                                return Err(AuthError::internal("outer-field-failure"));
                            }
                        }
                        Ok(value)
                    }
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(&output_events, json!(["output", "label", value.json()?]))?;
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
    let before = raw_rows(&store, slot)?;
    let (result, error) = match store.create_user(input("outer")?).await {
        Ok(user) => {
            assert!(matches!(user.id.field_value(), Value::String(_)));
            (observation(&user, slot)?, JsonValue::Null)
        }
        Err(AuthError::Internal(message)) => {
            (JsonValue::Null, json!({"name":"Error", "message":message}))
        }
        Err(error) => return Err(error),
    };
    assert!(
        stored_ids(&store)?
            .iter()
            .all(|id| matches!(id, Value::Number(_)))
    );
    let after = raw_rows(&store, slot)?;
    let events = events
        .lock()
        .map_err(|_| AuthError::internal("Serial event lock poisoned"))?
        .clone();
    Ok(
        json!({"slot":slot, "operation":operation, "before":before, "events":events, "result":result, "error":error, "after":after}),
    )
}

#[tokio::test]
async fn memory_user_serial_create_order_matches_all_six_upstream_cases() -> AuthResult<()> {
    let expected: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/user-serial-create-order-1.7.6.json"
    )))?;
    let mut cases = Vec::new();
    for slot in ["implicit", "before-label"] {
        for operation in ["nested-success", "nested-failure", "outer-failure"] {
            cases.push(capture(slot, operation).await?);
        }
    }
    assert_eq!(cases.len(), 6);
    assert_eq!(json!({"version":"1.7.6", "cases":cases}), expected);
    Ok(())
}
