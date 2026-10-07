use super::{contract as fields, fixture};

use better_auth::{
    __private_core::{
        AuthResult, AuthSchema, AuthStore, FieldValue, UpdateDeviceCode,
        store::EphemeralStore,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

fn policies() -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [("label", "stored_label"), ("note", "unconfigured")]
                .into_iter()
                .map(|(name, storage)| {
                    (
                        name.into(),
                        UserFieldConfig {
                            field_name: Some(storage.into()),
                            required: Some(false),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

#[expect(
    clippy::expect_used,
    reason = "The point-read contract requires declared string fields, complete rows, callback traces, and a captured selector"
)]
async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, backend: &str) -> AuthResult<()> {
    let writer = BetterAuth::new(fields::config())
        .store_arc(raw.clone())
        .plugin(fields::Fields(policies()))
        .build()
        .await?;
    let mut input = fields::input("live-fields");
    input.additional_fields = [
        ("label".into(), FieldValue::from("label-before")),
        ("note".into(), FieldValue::from("note-before")),
    ]
    .into_iter()
    .collect();
    let created = writer.store().create_device_code(input).await?;
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let callback_writer = writer.store().clone();
    let callback_id = created.id.clone();
    let label_events = events.clone();
    let note_events = events.clone();
    let mut reader_fields = policies();
    reader_fields
        .fields_mut()
        .get_mut("label")
        .expect("declared label")
        .transform = Some(FieldTransforms {
        output: Some(UserFieldTransform::new_async(move |value| {
            let writer = callback_writer.clone();
            let id = callback_id.clone();
            let events = label_events.clone();
            async move {
                events
                    .lock()
                    .expect("ordinary trace lock")
                    .push(json!(["label", value]));
                let _ = writer
                    .update_device_code(
                        &id,
                        UpdateDeviceCode {
                            additional_fields: [("note".into(), FieldValue::from("note-after"))]
                                .into_iter()
                                .collect(),
                            ..Default::default()
                        },
                    )
                    .await?;
                events
                    .lock()
                    .expect("ordinary trace lock")
                    .push(json!(["note-write", "note-after"]));
                Ok(FieldValue::from(format!(
                    "{}:out",
                    value.as_str().expect("string label")
                )))
            }
        })),
        ..Default::default()
    });
    reader_fields
        .fields_mut()
        .get_mut("note")
        .expect("declared note")
        .transform = Some(FieldTransforms {
        output: Some(UserFieldTransform::new(move |value| {
            note_events
                .lock()
                .expect("ordinary trace lock")
                .push(json!(["note", value]));
            Ok(FieldValue::from(format!(
                "{}:out",
                value.as_str().expect("string note")
            )))
        })),
        ..Default::default()
    });
    let reader = BetterAuth::new(fields::config())
        .store_arc(raw)
        .plugin(fields::Fields(reader_fields))
        .build()
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/device-live-fields-1.7.6.json"))?;
    for selector in ["deviceCode", "userCode"] {
        let _ = writer
            .store()
            .update_device_code(
                &created.id,
                UpdateDeviceCode {
                    additional_fields: [("note".into(), FieldValue::from("note-before"))]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                },
            )
            .await?;
        events.lock().expect("ordinary trace lock").clear();
        let selected = if selector == "deviceCode" {
            reader
                .store()
                .get_device_code_by_device_code(&created.device_code)
                .await?
        } else {
            reader
                .store()
                .get_device_code_by_user_code(&created.user_code)
                .await?
        }
        .expect("ordinary record exists");
        let stored = writer
            .store()
            .get_device_code_by_device_code(&created.device_code)
            .await?
            .expect("ordinary record remains stored");
        let expected = fixture
            .get("cases")
            .and_then(Value::as_array)
            .expect("captured cases")
            .iter()
            .find(|case| {
                case.get("backend").and_then(Value::as_str) == Some(backend)
                    && case.get("selector").and_then(Value::as_str) == Some(selector)
            })
            .expect("captured point-read case");
        assert_eq!(
            json!({
                "backend": backend,
                "selector": selector,
                "events": *events.lock().expect("ordinary trace lock"),
                "result": selected.additional_fields,
                "stored": stored.additional_fields,
            }),
            *expected
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_point_reads_observe_later_display_writes() -> AuthResult<()> {
    contract(
        Arc::new(EphemeralStore::new(Arc::new(fields::config()))),
        "memory",
    )
    .await
}

#[tokio::test]
async fn sqlite_device_point_reads_keep_their_display_snapshot() -> AuthResult<()> {
    let (store, _) = fixture::sqlite(fields::config()).await;
    contract(Arc::new(store), "sqlite").await
}
