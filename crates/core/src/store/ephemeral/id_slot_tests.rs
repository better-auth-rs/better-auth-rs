use super::*;
use crate::id::{IdGeneration, IdGenerator};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

mod session_updates;
mod sessions;

const CREATED_AT: &str = "2030-01-02T03:04:05.000Z";
const EXPIRES_AT: &str = "2100-01-02T03:04:05.000Z";
type Events = Arc<Mutex<Vec<JsonValue>>>;
type Target = Arc<OnceLock<Weak<EphemeralStore>>>;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Missing ID slot test value"))
}

fn date(text: &str) -> AuthResult<crate::FieldDate> {
    text.parse::<DateTime<Utc>>()
        .map(Into::into)
        .map_err(|error| AuthError::internal(error.to_string()))
}

fn record(events: &Events, event: JsonValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("ID slot event lock poisoned"))?
        .push(event);
    Ok(())
}

fn events(events: &Events) -> AuthResult<Vec<JsonValue>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("ID slot event lock poisoned"))?
        .clone())
}

fn observe(fields: FieldMap, raw: bool) -> AuthResult<JsonValue> {
    let mut output = serde_json::Map::new();
    for (name, value) in fields {
        let value = match value {
            Value::Undefined if raw => continue,
            Value::Undefined => json!({"type":"undefined"}),
            Value::Date(value) => {
                json!({"type":"date", "value":required(Value::Date(value).json()?)?})
            }
            value => required(value.json()?)?,
        };
        let _ = output.insert(name, value);
    }
    Ok(JsonValue::Object(output))
}

fn user_fields(user: &UserView, slot: &str) -> AuthResult<FieldMap> {
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
    fields.extend(user.additional_fields.clone());
    let _ = fields.insert("id".into(), user.id.field_value());
    Ok(fields)
}

fn session_fields(session: &SessionView, slot: &str) -> FieldMap {
    let mut fields: FieldMap = session.clone().into();
    let _ = fields.shift_remove("id");
    let label = fields.shift_remove("label");
    if slot == "before-label" {
        let _ = fields.insert("id".into(), session.id.field_value());
    }
    if let Some(label) = label {
        let _ = fields.insert("label".into(), label);
    }
    let _ = fields.insert("id".into(), session.id.field_value());
    fields
}

fn memory(store: &EphemeralStore, slot: &str) -> AuthResult<JsonValue> {
    let state = store.lock()?;
    assert_eq!(state.accounts.len(), 0);
    assert_eq!(state.verifications.len(), 0);
    assert_eq!(state.jwks.len(), 0);
    assert_eq!(state.wallets.len(), 0);
    let users = state
        .users
        .snapshot()?
        .iter()
        .map(|row| observe(user_fields(row, slot)?, true))
        .collect::<AuthResult<Vec<_>>>()?;
    let sessions = state
        .sessions
        .snapshot()?
        .iter()
        .map(|row| observe(session_fields(row, slot), true))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(
        json!({"user":users, "account":[], "session":sessions, "verification":[], "jwks":[], "walletAddress":[]}),
    )
}

fn user_input(label: &str) -> AuthResult<CreateUser> {
    Ok(CreateUser {
        name: Some(format!("Record {label}")).into(),
        email: Some(format!("{label}@adapter-id-slot.test")),
        email_verified: Some(false),
        image: None::<String>.into(),
        created_at: Some(date(CREATED_AT)?),
        updated_at: Some(date(CREATED_AT)?),
        additional_fields: [("label".into(), label.into())].into(),
        ..Default::default()
    })
}

fn user_request(label: &str) -> JsonValue {
    json!({"model":"user", "data": {
        "name":format!("Record {label}"), "email":format!("{label}@adapter-id-slot.test"),
        "emailVerified":false, "image":null,
        "createdAt":{"type":"date", "value":CREATED_AT},
        "updatedAt":{"type":"date", "value":CREATED_AT}, "label":label,
    }})
}

fn id_policy() -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("configured-id-input-called"))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("configured-id-output-called"))
            })),
        }),
        ..Default::default()
    }
}

fn install_fields(
    fields: &mut IndexMap<String, UserFieldConfig>,
    slot: &str,
    label: UserFieldConfig,
) {
    if slot == "before-label" {
        let _ = fields.insert("id".into(), id_policy());
    }
    let _ = fields.insert("label".into(), label);
    if slot == "after-label" {
        let _ = fields.insert("id".into(), id_policy());
    }
}

fn generator(events: &Events, target: &Target, slot: &'static str) -> IdGeneration {
    let events = events.clone();
    let target = target.clone();
    let sequence = AtomicUsize::new(0);
    IdGeneration::Custom(IdGenerator::new(move |request| {
        let store = required(target.get().and_then(Weak::upgrade))?;
        let id = format!(
            "{}-generated-{}",
            request.model,
            sequence.fetch_add(1, Ordering::SeqCst) + 1
        );
        record(
            &events,
            json!(["generateId", {"model":request.model}, id, memory(&store, slot)?]),
        )?;
        Ok(Some(id))
    }))
}

async fn user_nested(slot: &'static str) -> AuthResult<JsonValue> {
    let trace = Events::default();
    let target = Target::default();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(generator(&trace, &target, slot));
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let input_target = target.clone();
    install_fields(
        config.user.fields_mut(),
        slot,
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async(move |value| {
                    let trace = input_trace.clone();
                    let target = input_target.clone();
                    async move {
                        record(&trace, json!(["input", "label", required(value.json()?)?]))?;
                        if value.as_str() == Some("outer") {
                            let store = required(target.get().and_then(Weak::upgrade))?;
                            record(
                                &trace,
                                json!([
                                    "nested-create",
                                    user_request("inner"),
                                    memory(&store, slot)?
                                ]),
                            )?;
                            let inner = store.create_user(user_input("inner")?).await?;
                            record(
                                &trace,
                                json!([
                                    "nested-created",
                                    observe(user_fields(&inner, slot)?, false)?,
                                    memory(&store, slot)?
                                ]),
                            )?;
                        }
                        Ok(value)
                    }
                })),
                output: Some(UserFieldTransform::new_async(move |value| {
                    let trace = output_trace.clone();
                    async move {
                        record(&trace, json!(["output", "label", required(value.json()?)?]))?;
                        Ok(value)
                    }
                })),
            }),
            ..Default::default()
        },
    );
    let store = Arc::new(EphemeralStore::new(Arc::new(config)));
    target
        .set(Arc::downgrade(&store))
        .map_err(|_| AuthError::internal("ID slot target already set"))?;
    let before = memory(&store, slot)?;
    let user = store.create_user(user_input("outer")?).await?;
    Ok(
        json!({"model":"user", "slot":slot, "operation":"nested-create", "idGeneration":"custom",
            "setup":[], "seedEvents":[], "before":before, "input":user_request("outer"),
            "events":events(&trace)?, "result":observe(user_fields(&user, slot)?, false)?, "error":null,
            "after":memory(&store, slot)?,
        }),
    )
}

#[tokio::test]
async fn memory_user_id_slot_nested_create_matches_complete_upstream_observations() -> AuthResult<()>
{
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-id-slot-1.7.6.json"
    )))?;
    let cases = required(fixture["cases"].as_array())?;
    for slot in ["before-label", "after-label"] {
        let expected = required(cases.iter().find(|case| {
            case["model"] == "user" && case["slot"] == slot && case["operation"] == "nested-create"
        }))?;
        assert_eq!(user_nested(slot).await?, *expected, "User ID slot {slot}");
    }
    Ok(())
}

#[tokio::test]
async fn memory_user_id_slot_reads_primary_key_at_its_position() -> AuthResult<()> {
    for slot in ["before-label", "after-label"] {
        let mut writer_config = AuthConfig::default();
        writer_config.advanced.database.generate_id = Some(IdGeneration::Serial);
        let _ = writer_config
            .user
            .fields_mut()
            .insert("label".into(), UserFieldConfig::default());
        let writer = EphemeralStore::new(Arc::new(writer_config));
        let _ = writer.create_user(user_input("selected")?).await?;
        let source = required(writer.lock()?.users.first_ref(|_| true)?)?;
        let before = source.read(|row| Ok(row.clone()))?;
        let target = source.clone();
        let mut config = (*writer.config).clone();
        config.user.additional_fields = None;
        install_fields(
            config.user.fields_mut(),
            slot,
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        target.write(|row| {
                            row.id = crate::SchemaValue::from_field(Value::Number(101.0));
                            Ok(())
                        })?;
                        Ok(format!("{}:out", required(value.as_str())?).into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let mut reader = EphemeralStore::new(Arc::new(config));
        reader.state = writer.state.clone();
        let output = required(reader.get_user_by_id("1").await?)?;
        let mut expected = before.clone();
        expected.id = if slot == "before-label" { "1" } else { "101" }.into();
        let _ = expected
            .additional_fields
            .insert("label".into(), "selected:out".into());
        assert_eq!(user_fields(&output, slot)?, user_fields(&expected, slot)?);
        let mut expected_raw = before;
        expected_raw.id = crate::SchemaValue::from_field(Value::Number(101.0));
        assert_eq!(source.read(|row| Ok(row.clone()))?, expected_raw);
    }
    Ok(())
}
