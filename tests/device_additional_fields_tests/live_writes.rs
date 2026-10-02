use super::{contract as fields, fixture};

use better_auth::{
    __private_core::{
        AuthError, AuthResult, AuthSchema, AuthStore, UpdateDeviceCode,
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
    reason = "The write-return contract requires declared string fields and complete callback traces"
)]
async fn observations<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
) -> AuthResult<Vec<Value>> {
    let writer = BetterAuth::new(fields::config())
        .store_arc(raw.clone())
        .plugin(fields::Fields(policies()))
        .build()
        .await?;
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let callback_writer = writer.store().clone();
    let label_events = events.clone();
    let note_events = events.clone();
    let mut output_fields = policies();
    output_fields
        .fields_mut()
        .get_mut("label")
        .expect("declared label")
        .transform = Some(FieldTransforms {
        output: Some(UserFieldTransform::new_async(move |value| {
            let writer = callback_writer.clone();
            let events = label_events.clone();
            async move {
                events
                    .lock()
                    .expect("ordinary trace lock")
                    .push(json!(["label", value]));
                let stored = writer
                    .get_device_code_by_device_code("ordinary-device:live-writes")
                    .await?
                    .ok_or_else(|| {
                        AuthError::internal(
                            "Expected the ordinary device row before its output callback",
                        )
                    })?;
                let _ = writer
                    .update_device_code(
                        &stored.id,
                        UpdateDeviceCode {
                            additional_fields: [("note".into(), json!("note-after"))]
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
                Ok(value
                    .map(|value| json!(format!("{}:out", value.as_str().expect("string label")))))
            }
        })),
        ..Default::default()
    });
    output_fields
        .fields_mut()
        .get_mut("note")
        .expect("declared note")
        .transform = Some(FieldTransforms {
        output: Some(UserFieldTransform::new(move |value| {
            note_events
                .lock()
                .expect("ordinary trace lock")
                .push(json!(["note", value]));
            Ok(value.map(|value| json!(format!("{}:out", value.as_str().expect("string note")))))
        })),
        ..Default::default()
    });
    let projecting = BetterAuth::new(fields::config())
        .store_arc(raw)
        .plugin(fields::Fields(output_fields))
        .build()
        .await?;
    let mut input = fields::input("live-writes");
    input.additional_fields = [
        ("label".into(), json!("label-before")),
        ("note".into(), json!("note-before")),
    ]
    .into_iter()
    .collect();
    let mut returned = projecting.store().create_device_code(input).await?;
    let mut cases = Vec::new();
    for operation in ["create", "update"] {
        if operation == "update" {
            events.lock().expect("ordinary trace lock").clear();
            returned = projecting
                .store()
                .update_device_code(
                    &returned.id,
                    UpdateDeviceCode {
                        additional_fields: [
                            ("label".into(), json!("label-updated")),
                            ("note".into(), json!("note-before")),
                        ]
                        .into_iter()
                        .collect(),
                        ..Default::default()
                    },
                )
                .await?;
        }
        let stored = writer
            .store()
            .get_device_code_by_device_code("ordinary-device:live-writes")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored ordinary device row"))?;
        cases.push(json!({
            "backend": backend,
            "operation": operation,
            "events": *events.lock().expect("ordinary trace lock"),
            "result": returned.additional_fields,
            "stored": stored.additional_fields,
        }));
    }
    Ok(cases)
}

#[expect(
    clippy::expect_used,
    reason = "The contract requires captured cases and compares every write-return observation for the selected backend"
)]
fn assert_pinned(actual: Vec<Value>, backend: &str) {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/device-live-writes-1.7.6.json"))
            .expect("captured Device write-return fixture");
    let expected = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured cases")
        .iter()
        .filter(|case| case.get("backend").and_then(Value::as_str) == Some(backend))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "The test must fail if the ordinary Memory write-return contract returns an error"
)]
async fn memory_device_write_results_observe_later_display_writes() {
    let actual = observations(
        Arc::new(EphemeralStore::new(Arc::new(fields::config()))),
        "memory",
    )
    .await
    .expect("ordinary Memory write-return observations");
    assert_pinned(actual, "memory");
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "The test must fail if the ordinary SQLite write-return contract returns an error"
)]
async fn sqlite_device_write_results_keep_their_display_snapshot() {
    let (store, _) = fixture::sqlite(fields::config()).await;
    let actual = observations(Arc::new(store), "sqlite")
        .await
        .expect("ordinary SQLite write-return observations");
    assert_pinned(actual, "sqlite");
}
