use super::*;
use crate::store::database_hooks::SessionUpdate;
use crate::user_fields::UserFieldReference;

const TOKEN: &str = "slot-undefined-alias";
const CHANGED_AT: &str = "2031-01-02T03:04:05.000Z";

fn observed_value(value: &Value) -> AuthResult<JsonValue> {
    match value {
        Value::Number(number) if number.is_nan() => Ok(json!({"type":"number", "value":"NaN"})),
        _ => required(value.json()?),
    }
}

fn observed_session(session: &SessionView, updated: bool, raw: bool) -> AuthResult<JsonValue> {
    let mut normalized = session.clone();
    // The Store owns token and creation time; compare those values before normalizing adapter observations.
    normalized.token = TOKEN.into();
    normalized.created_at = date(CREATED_AT)?.into();
    normalized.updated_at = date(if updated { CHANGED_AT } else { CREATED_AT })?.into();
    let mut value = observe(normalized.into(), raw)?;
    value["id"] = observed_value(&session.id.field_value())?;
    Ok(value)
}

#[tokio::test]
async fn memory_session_undefined_id_alias_matches_complete_upstream_observations() -> AuthResult<()>
{
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-id-slot-1.7.6.json"
    )))?;
    let expected = required(required(fixture["cases"].as_array())?.iter().find(|case| {
        case["model"] == "session"
            && case["slot"] == "after-alias"
            && case["operation"] == "update-undefined-id-alias"
            && case["idGeneration"] == "serial"
    }))?;
    let trace = Events::default();
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let _ = config.session.fields_mut().insert(
        "aliasId".into(),
        UserFieldConfig {
            field_name: Some("id".into()),
            references: Some(UserFieldReference {
                model: "session".into(),
                field: "id".into(),
                ..Default::default()
            }),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(
                        &input_trace,
                        json!(["input", "aliasId", observed_value(&value)?]),
                    )?;
                    Ok(Value::Undefined)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(
                        &output_trace,
                        json!(["output", "aliasId", observed_value(&value)?]),
                    )?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let store = EphemeralStore::new(Arc::new(config));
    let empty = memory(&store, "after-label")?;
    let create = CreateSession {
        inherited_fields: Default::default(),
        user_id: "001".into(),
        expires_at: date(EXPIRES_AT)?,
        ip_address: Some(String::new()),
        user_agent: Some(String::new()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: [("aliasId".into(), "seed".into())].into(),
    };
    let started = Utc::now().timestamp_millis() as f64;
    let created = store.create_session(create).await?;
    let ended = Utc::now().timestamp_millis() as f64;
    assert!((started..=ended).contains(&created.created_at.date_milliseconds().unwrap()));
    assert!((started..=ended).contains(&created.updated_at.date_milliseconds().unwrap()));
    assert_eq!(created.token.typed().unwrap().len(), 32);
    assert!(
        created
            .token
            .typed()
            .unwrap()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    );
    let rows = store.lock()?.sessions.snapshot()?;
    assert_eq!(rows.len(), 1);
    let stored = required(rows.first())?;
    let mut expected_stored = created.clone();
    expected_stored.id = crate::SchemaValue::from_field(Value::Number(1.0));
    expected_stored.user_id = crate::SchemaValue::from_field(Value::Number(1.0));
    expected_stored.additional_fields.clear();
    assert_eq!(*stored, expected_stored);
    let mut before = memory(&store, "after-label")?;
    before["session"] = json!([observed_session(stored, false, true)?]);
    let seed_events = events(&trace)?;
    trace
        .lock()
        .map_err(|_| AuthError::internal("ID slot event lock poisoned"))?
        .clear();
    let updated = required(
        store
            .update_session_with_writer(
                created.token.typed().unwrap(),
                SessionUpdate {
                    updated_at: Some(date(CHANGED_AT)?),
                    additional_fields: [("aliasId".into(), "clear".into())].into(),
                    ..Default::default()
                },
                None,
            )
            .await?,
    )?;
    assert_eq!(updated.token, created.token);
    assert_eq!(updated.created_at, created.created_at);
    assert_eq!(updated.updated_at, date(CHANGED_AT)?);
    let rows = store.lock()?.sessions.snapshot()?;
    assert_eq!(rows.len(), 1);
    let stored = required(rows.first())?;
    assert!(matches!(stored.id.field_value(), Value::Number(number) if number.is_nan()));
    let mut comparable = stored.clone();
    comparable.id = "NaN".into();
    expected_stored.id = "NaN".into();
    expected_stored.updated_at = date(CHANGED_AT)?.into();
    assert_eq!(comparable, expected_stored);
    let mut after = memory(&store, "after-label")?;
    after["session"] = json!([observed_session(stored, true, true)?]);
    let actual = json!({
        "model":"session", "slot":"after-alias", "operation":"update-undefined-id-alias", "idGeneration":"serial",
        "setup":[{
            "input":{"model":"session", "data":{
                "token":TOKEN, "userId":"001", "expiresAt":{"type":"date", "value":EXPIRES_AT},
                "createdAt":{"type":"date", "value":CREATED_AT}, "updatedAt":{"type":"date", "value":CREATED_AT},
                "ipAddress":"", "userAgent":"", "aliasId":"seed",
            }},
            "before":empty, "result":observed_session(&created, false, false)?, "after":before,
        }],
        "seedEvents":seed_events, "before":before,
        "input":{"model":"session", "where":[{"field":"token", "value":TOKEN}], "update":{
            "aliasId":"clear", "updatedAt":{"type":"date", "value":CHANGED_AT},
        }},
        "events":events(&trace)?, "result":observed_session(&updated, true, false)?, "error":null, "after":after,
    });
    assert_eq!(actual, *expected);
    Ok(())
}
