use super::contract::{Fields, Trace, adapter_value, config, input, policies, take};
use better_auth::{
    __private_core::{
        ApiKey, AuthError, AuthResult, AuthSchema, AuthStore, FieldDate, FieldValue,
        store::ApiKeyUsageWrite,
        user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicU8};

const UPDATED_AT: &str = "2031-02-03T04:05:05.000Z";
const OUTPUT_ERROR: &str = "ordinary live API Key output error";

#[expect(
    clippy::expect_used,
    reason = "The live contract requires the selected record and every callback event"
)]
async fn observe<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    fail_output: bool,
) -> AuthResult<Value> {
    let updated_at = UPDATED_AT
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect("fixed update timestamp");
    let failure = Arc::new(AtomicU8::new(0));
    let reader = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(policies(None, failure.clone())))
        .build()
        .await?;
    let mut data = input();
    let _ = data
        .additional_fields
        .insert("label".into(), "Default".into());
    let seed = reader.store().create_api_key(data).await?;
    let mut writer_policies = policies(None, failure.clone());
    writer_policies
        .fields_mut()
        .get_mut("label")
        .expect("declared label")
        .on_update = Some(Arc::new(|| Ok("Live".into())));
    let writer = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(writer_policies))
        .build()
        .await?;
    let writer = writer.store().clone();
    let events = Trace::default();
    let mut projection = policies(Some(events.clone()), failure);
    let name_events = events.clone();
    let id = seed.id.clone();
    let _ = projection.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let events = name_events.clone();
                    let writer = writer.clone();
                    let id = id.clone();
                    async move {
                        let name = value.as_str().expect("stored API Key name");
                        events
                            .lock()
                            .expect("trace lock")
                            .push(json!(["name", name]));
                        let row = writer
                            .write_api_key_usage(&id, ApiKeyUsageWrite::UpdatedAt(updated_at))
                            .await?
                            .expect("callback API Key exists");
                        let label = row.additional_fields.get("label").expect("stored label");
                        let revision = row
                            .additional_fields
                            .get("revision")
                            .expect("stored revision");
                        assert_eq!(label, &FieldValue::from("Live"));
                        assert_eq!(revision, &FieldValue::from(2.5));
                        assert_eq!(row.updated_at, FieldDate::from(updated_at));
                        events.lock().expect("trace lock").push(json!(["write", {
                            "label":label.json()?, "revision":revision.json()?,
                            "updatedAt":row.updated_at.field_value().json()?,
                        }]));
                        Ok(format!("{name}:out").into())
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    if fail_output {
        let label_events = events.clone();
        projection
            .fields_mut()
            .get_mut("label")
            .expect("declared label")
            .transform
            .as_mut()
            .expect("label transforms")
            .output = Some(UserFieldTransform::new(move |value| {
            label_events.lock().expect("trace lock").push(json!([
                "output",
                "label",
                value.json()?
            ]));
            Err(AuthError::internal(OUTPUT_ERROR))
        }));
    }
    let projected = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(Fields(projection))
        .build()
        .await?;
    let (row, error) = match projected.store().get_api_key_by_id(seed.id.typed()?).await {
        Ok(row) => (row, Value::Null),
        Err(AuthError::Internal(message)) if message == OUTPUT_ERROR => {
            (None, json!({"sameError":true, "message":message}))
        }
        Err(error) => return Err(error),
    };
    assert_eq!(!error.is_null(), fail_output);
    let stored = reader
        .store()
        .get_api_key_by_id(seed.id.typed()?)
        .await?
        .expect("stored API Key exists");
    assert_eq!(
        stored.additional_fields.get("label"),
        Some(&FieldValue::from("Live"))
    );
    assert_eq!(
        stored.additional_fields.get("revision"),
        Some(&FieldValue::from(2.5))
    );
    assert_eq!(stored.updated_at, FieldDate::from(updated_at));
    let visible = |row: &ApiKey| -> AuthResult<Value> {
        assert_eq!(row.id, seed.id);
        assert_eq!(row.created_at, seed.created_at);
        assert!(row.updated_at == seed.created_at || row.updated_at == FieldDate::from(updated_at));
        let mut value = adapter_value(row)?;
        *value.get_mut("id").expect("stored API Key id") = json!("<api-key-id>");
        *value
            .get_mut("createdAt")
            .expect("stored API Key creation date") = json!("<created-at>");
        if row.updated_at == seed.created_at {
            *value
                .get_mut("updatedAt")
                .expect("stored API Key update date") = json!("<created-at>");
        }
        Ok(value)
    };
    Ok(json!({
        "failOutput":fail_output, "events":take(&events), "result":row.as_ref().map(visible).transpose()?,
        "error":error, "stored":visible(&stored)?,
    }))
}

#[expect(
    clippy::expect_used,
    reason = "The pinned fixture must retain both backends and both output phases"
)]
pub(crate) async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    fail_output: bool,
) -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/api-key-live-fields-1.7.6.json"))?;
    assert_eq!(
        fixture.get("version").and_then(Value::as_str),
        Some("1.7.6")
    );
    let backends = fixture
        .get("backends")
        .and_then(Value::as_array)
        .expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case.get("backend").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let cases = backends
        .iter()
        .find(|case| case.get("backend").and_then(Value::as_str) == Some(backend))
        .expect("captured backend")
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured cases");
    assert_eq!(
        cases
            .iter()
            .map(|case| case.get("failOutput").and_then(Value::as_bool))
            .collect::<Vec<_>>(),
        [Some(false), Some(true)]
    );
    let expected = cases
        .iter()
        .find(|case| case.get("failOutput").and_then(Value::as_bool) == Some(fail_output))
        .expect("captured output phase");
    assert_eq!(&observe(raw, fail_output).await?, expected);
    Ok(())
}
