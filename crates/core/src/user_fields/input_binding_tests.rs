use super::*;
use std::sync::Mutex;

type Trace = Arc<Mutex<Vec<(String, Value)>>>;

fn schema(trace: &Trace) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            ["reference", "omitted", "missing"]
                .into_iter()
                .map(|name| {
                    let trace = trace.clone();
                    (
                        name.to_owned(),
                        UserFieldConfig {
                            field_name: Some(format!("stored_{name}")),
                            references: (name == "reference").then(|| UserFieldReference {
                                model: "user".into(),
                                field: "id".into(),
                            }),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(move |value| {
                                    trace.lock().unwrap().push((name.into(), value));
                                    Ok(Value::Undefined)
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

fn input() -> FieldMap {
    [
        ("reference".into(), Value::from("clear")),
        ("omitted".into(), Value::from("clear")),
    ]
    .into()
}

#[tokio::test]
async fn callback_undefined_reaches_reference_binding_before_omission() {
    for boundary in ["fields", "record", "organization", "adapter-id"] {
        let trace = Trace::default();
        let schema = schema(&trace);
        let bind = |name: &str, field: &UserFieldConfig, value: Value| {
            trace
                .lock()
                .unwrap()
                .push((format!("bind:{name}"), value.clone()));
            if field.references_id() {
                crate::id::serial_reference_value(value)
            } else {
                Ok(value)
            }
        };
        let mut fields = match boundary {
            "fields" => {
                schema
                    .storage_fields_with_binding(input(), false, bind)
                    .await
            }
            "record" => {
                schema
                    .record_storage_fields_with_binding(input(), false, bind)
                    .await
            }
            "organization" => {
                schema
                    .organization_storage_fields_with_binding(FieldMap::new(), input(), false, bind)
                    .await
            }
            "adapter-id" => {
                schema
                    .update_adapter_storage_fields(input(), || Ok(None), bind)
                    .await
            }
            _ => unreachable!(),
        }
        .unwrap();
        assert!(
            matches!(fields.shift_remove("stored_reference"), Some(Value::Number(value)) if value.is_nan()),
            "{boundary} must bind callback Undefined as a Serial reference"
        );
        assert!(fields.is_empty(), "{boundary} must omit ordinary Undefined");
        assert_eq!(
            *trace.lock().unwrap(),
            [
                ("reference".into(), Value::from("clear")),
                ("bind:stored_reference".into(), Value::Undefined),
                ("omitted".into(), Value::from("clear")),
                ("bind:stored_omitted".into(), Value::Undefined),
            ],
            "{boundary} must bind each callback result once and skip absent update fields"
        );
    }
}

#[tokio::test]
async fn identity_storage_helpers_still_omit_callback_undefined() {
    for organization in [false, true] {
        let trace = Trace::default();
        let schema = schema(&trace);
        let fields = if organization {
            schema
                .organization_storage_fields(FieldMap::new(), input(), false)
                .await
        } else {
            schema.storage_fields(input(), false).await
        }
        .unwrap();
        assert!(fields.is_empty());
        assert_eq!(
            *trace.lock().unwrap(),
            [
                ("reference".into(), Value::from("clear")),
                ("omitted".into(), Value::from("clear")),
            ]
        );
    }
}

#[tokio::test]
async fn literal_undefined_default_skips_binding_but_default_factory_runs() {
    for factory in [false, true] {
        let schema = UserConfig {
            additional_fields: Some(
                [(
                    "reference".into(),
                    UserFieldConfig {
                        required: Some(true),
                        references: Some(UserFieldReference {
                            model: "user".into(),
                            field: "id".into(),
                        }),
                        default_value: Some(Value::Undefined),
                        default_value_fn: factory.then(|| {
                            Arc::new(|| Value::Undefined) as Arc<dyn Fn() -> Value + Send + Sync>
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        for null in [false, true] {
            let input = if null {
                [("reference".into(), Value::Null)].into()
            } else {
                FieldMap::new()
            };
            let fields = schema
                .storage_fields_with_binding(input, true, |_, _, value| {
                    assert!(factory || value.is_null());
                    crate::id::serial_reference_value(value)
                })
                .await
                .unwrap();
            if factory {
                assert_eq!(fields.len(), 1);
                assert!(matches!(fields["reference"], Value::Number(value) if value.is_nan()));
            } else if null {
                assert_eq!(fields, [("reference".into(), Value::Null)].into());
            } else {
                assert!(fields.is_empty());
            }
        }
    }
}
