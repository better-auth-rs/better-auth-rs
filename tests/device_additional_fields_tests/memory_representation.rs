use super::contract as fields;
use better_auth::{
    __private_core::{
        AuthResult, AuthUser, CreateDeviceCode, CreateUser, DeviceCode, FieldMap, FieldValue,
        UpdateDeviceCode,
        id::{IdGeneration, IdGenerator},
        store::{DeviceCodeStore, EphemeralStore, transaction},
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
            UserFieldType,
        },
    },
    AuthConfig, BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Trace = Arc<Mutex<Vec<Value>>>;

const ALIASES: [(&str, &str); 6] = [
    ("settings", "stored_settings"),
    ("nullableSettings", "stored_nullable_settings"),
    ("tags", "stored_tags"),
    ("targets", "stored_targets"),
    ("targetNumbers", "stored_target_numbers"),
    ("targetDocument", "stored_target_document"),
];

fn config(serial: bool) -> AuthConfig {
    let mut config = fields::config();
    config.advanced.database.generate_id = Some(if serial {
        IdGeneration::Serial
    } else {
        let next_id = AtomicUsize::new(1);
        IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        }))
    });
    config
}

#[expect(
    clippy::expect_used,
    reason = "The contract requires an unpoisoned callback trace"
)]
fn policies(trace: Option<&Trace>) -> UserConfig {
    let types = [
        (UserFieldType::Json, false),
        (UserFieldType::Json, false),
        (UserFieldType::StringArray, false),
        (UserFieldType::StringArray, true),
        (UserFieldType::NumberArray, true),
        (UserFieldType::Json, true),
    ];
    UserConfig {
        additional_fields: Some(
            ALIASES
                .into_iter()
                .zip(types)
                .map(|((name, alias), (field_type, reference))| {
                    let transform = trace.map(|trace| {
                        let input_events = trace.clone();
                        let output_events = trace.clone();
                        FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                input_events
                                    .lock()
                                    .expect("ordinary Device input trace")
                                    .push(json!(["input", name, value.json()?]));
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                output_events
                                    .lock()
                                    .expect("ordinary Device output trace")
                                    .push(json!(["output", name, value.json()?]));
                                Ok(value)
                            })),
                        }
                    });
                    (
                        name.into(),
                        UserFieldConfig {
                            field_type: if trace.is_some() {
                                field_type
                            } else {
                                UserFieldType::String
                            },
                            field_name: Some(alias.into()),
                            required: Some(false),
                            references: (trace.is_some() && reference).then(|| {
                                UserFieldReference {
                                    model: "user".into(),
                                    field: "id".into(),
                                    ..Default::default()
                                }
                            }),
                            transform,
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

fn input(label: &str, targets: &[String]) -> CreateDeviceCode {
    let mut input = fields::input(label);
    input.additional_fields = [
        (
            "settings".into(),
            FieldValue::from(FieldMap::from([("theme".into(), FieldValue::from("dark"))])),
        ),
        ("nullableSettings".into(), FieldValue::Null),
        (
            "tags".into(),
            FieldValue::from(vec![FieldValue::from("alpha"), FieldValue::from("beta")]),
        ),
        (
            "targets".into(),
            FieldValue::from(
                targets
                    .iter()
                    .cloned()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "targetNumbers".into(),
            FieldValue::from(vec![FieldValue::from(1), FieldValue::from(2)]),
        ),
        (
            "targetDocument".into(),
            FieldValue::from(
                targets
                    .iter()
                    .cloned()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>(),
            ),
        ),
    ]
    .into_iter()
    .collect();
    input
}

fn update(theme: &str) -> UpdateDeviceCode {
    UpdateDeviceCode {
        additional_fields: [(
            "settings".into(),
            FieldValue::from(FieldMap::from([("theme".into(), FieldValue::from(theme))])),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

fn native(row: &DeviceCode) -> DeviceCode {
    let mut native = row.clone();
    native.additional_fields.clear();
    native
}

#[expect(
    clippy::expect_used,
    reason = "All declared physical fields must be present"
)]
fn stored_physical(row: &DeviceCode) -> FieldMap {
    ALIASES
        .into_iter()
        .map(|(name, alias)| {
            (
                alias.into(),
                row.additional_fields
                    .get(name)
                    .expect("ordinary stored field exists")
                    .clone(),
            )
        })
        .collect()
}

#[expect(
    clippy::expect_used,
    reason = "The contract requires an unpoisoned callback trace"
)]
fn take_events(trace: &Trace) -> Vec<Value> {
    std::mem::take(&mut *trace.lock().expect("ordinary Device callback trace"))
}

#[expect(
    clippy::expect_used,
    reason = "Each completed display operation must retain its row and complete native snapshot"
)]
async fn direct_observation(
    reader: &dyn DeviceCodeStore,
    name: &str,
    trace: &Trace,
    result: Value,
    expected_native: &DeviceCode,
) -> AuthResult<Value> {
    let stored = reader
        .get_device_code_by_device_code(expected_native.device_code.typed()?)
        .await?
        .expect("ordinary Device row exists");
    assert_eq!(native(&stored), *expected_native);
    Ok(json!({
        "name":name,
        "events":take_events(trace),
        "result":result,
        "storedPhysical":stored_physical(&stored).json()?,
        "nativeUnchanged":true,
    }))
}

#[expect(
    clippy::expect_used,
    reason = "The paired contract requires complete rows, stable fixture IDs, and unchanged native fields"
)]
async fn observations(serial: bool) -> AuthResult<Value> {
    let mode = if serial { "serial" } else { "custom" };
    let config = config(serial);
    let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let reader = BetterAuth::new(config.clone())
        .store_arc(raw.clone())
        .plugin(fields::Fields(policies(None)))
        .build()
        .await?;
    let mut targets = Vec::new();
    for index in 1..=2 {
        let mut input = CreateUser::new()
            .with_name(format!("Display target {index}"))
            .with_email(format!("target{index}@device-fields.test"));
        let fixed_date = fields::input("date").expires_at;
        input.created_at = Some(fixed_date.clone());
        input.updated_at = Some(fixed_date);
        let user = reader.store().create_user(input).await?;
        targets.push(user.id().typed()?.to_string());
    }
    assert_eq!(targets, ["1", "2"]);
    let trace = Trace::default();
    let writer = BetterAuth::new(config)
        .store_arc(raw)
        .plugin(fields::Fields(policies(Some(&trace))))
        .build()
        .await?;
    let store = writer.store();
    let label = format!("representation-{mode}");
    let created = store.create_device_code(input(&label, &targets)).await?;
    let expected_native = native(&created);
    let mut operations = vec![
        direct_observation(
            reader.store().as_ref(),
            "create",
            &trace,
            json!(created.additional_fields.json()?),
            &expected_native,
        )
        .await?,
    ];
    for name in [
        "read-device",
        "read-user",
        "update",
        "update-if-status",
        "read-after-status",
    ] {
        let result = if name == "update-if-status" {
            json!(
                store
                    .update_device_code_if_status(&created.id, "pending", update("guarded"))
                    .await?
            )
        } else {
            let row = match name {
                "read-user" => store
                    .get_device_code_by_user_code(created.user_code.typed()?)
                    .await?
                    .expect("ordinary Device row exists"),
                "update" => {
                    store
                        .update_device_code(&created.id, update("light"))
                        .await?
                }
                _ => store
                    .get_device_code_by_device_code(created.device_code.typed()?)
                    .await?
                    .expect("ordinary Device row exists"),
            };
            assert_eq!(native(&row), expected_native);
            json!(row.additional_fields.json()?)
        };
        operations.push(
            direct_observation(
                reader.store().as_ref(),
                name,
                &trace,
                result,
                &expected_native,
            )
            .await?,
        );
    }

    let transaction_trace = trace.clone();
    let transaction_label = format!("{label}-transaction");
    let (transaction_operations, transaction_native) = transaction(store.as_ref(), move |tx| {
        Box::pin(async move {
            let created = tx
                .create_device_code(input(&transaction_label, &targets))
                .await?;
            let expected_native = native(&created);
            let mut operations = vec![json!({
                "name":"create", "events":take_events(&transaction_trace),
                "result":created.additional_fields.json()?, "nativeUnchanged":true,
            })];
            let read = tx
                .get_device_code_by_device_code(created.device_code.typed()?)
                .await?
                .expect("transaction reads its Device row");
            assert_eq!(native(&read), expected_native);
            operations.push(json!({
                "name":"read-device", "events":take_events(&transaction_trace),
                "result":read.additional_fields.json()?, "nativeUnchanged":true,
            }));
            let updated = tx
                .update_device_code(&created.id, update("transaction"))
                .await?;
            assert_eq!(native(&updated), expected_native);
            operations.push(json!({
                "name":"update", "events":take_events(&transaction_trace),
                "result":updated.additional_fields.json()?, "nativeUnchanged":true,
            }));
            Ok((operations, expected_native))
        })
    })
    .await?;
    let committed = reader
        .store()
        .get_device_code_by_device_code(transaction_native.device_code.typed()?)
        .await?
        .expect("committed Device row exists");
    assert_eq!(native(&committed), transaction_native);
    assert!(take_events(&trace).is_empty());
    Ok(json!({
        "mode":mode,
        "operations":operations,
        "transaction":{
            "operations":transaction_operations,
            "storedPhysical":stored_physical(&committed).json()?,
            "nativeUnchanged":true,
        },
    }))
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The complete observation must equal the pinned fixture"
)]
async fn memory_device_field_representations_match_pinned_factory() -> AuthResult<()> {
    let actual = json!({
        "version":"1.7.6",
        "cases":[observations(false).await?, observations(true).await?],
    });
    let expected: Value = serde_json::from_str(include_str!(
        "../fixtures/device-memory-representation-1.7.6.json"
    ))?;
    assert_eq!(actual, expected);
    Ok(())
}
