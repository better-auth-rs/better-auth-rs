use super::*;
use crate::store::schema::EntityRole;
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use crate::{FieldMap, SchemaValue};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn enabled_callbacks_preserve_earlier_fields_and_read_later_live_fields() -> AuthResult<()> {
    for asynchronous in [false, true] {
        for fail_output in [false, true] {
            let mut store = EphemeralStore::default();
            let fields = UserConfig {
                additional_fields: Some(
                    [
                        (
                            "enabled".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Number,
                                required: Some(false),
                                ..Default::default()
                            },
                        ),
                        (
                            "marker".into(),
                            UserFieldConfig {
                                required: Some(false),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            };
            store
                .model_fields
                .register(EntityRole::ApiKey, fields.clone());
            let seed = store
                .create_api_key(CreateApiKey {
                    name: Some("before".into()).into(),
                    enabled: SchemaValue::from_field(5.25.into()),
                    additional_fields: [("marker".into(), "before".into())].into(),
                    ..input()
                })
                .await?;
            let writer = store.clone();
            let id = seed.id.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let mutate = move |value: FieldValue| {
                observed.fetch_add(1, Ordering::SeqCst);
                assert_eq!(value, FieldValue::Number(5.25));
                let source = writer
                    .lock()?
                    .api_keys
                    .first_ref(|row| row.get("id") == Some(&id.field_value()))?
                    .expect("live key");
                source.write(|row| {
                    row.extend([
                        ("name".into(), "after".into()),
                        ("enabled".into(), false.into()),
                        ("remaining".into(), 7.0.into()),
                        ("marker".into(), "after".into()),
                    ]);
                    Ok(())
                })?;
                if fail_output {
                    Err(AuthError::internal("live enabled output"))
                } else {
                    Ok(value)
                }
            };
            let output = if asynchronous {
                UserFieldTransform::new_async(move |value| std::future::ready(mutate(value)))
            } else {
                UserFieldTransform::new(mutate)
            };
            let mut projection = fields;
            projection
                .fields_mut()
                .get_mut("enabled")
                .expect("enabled declaration")
                .transform = Some(FieldTransforms {
                input: None,
                output: Some(output),
            });
            store.model_fields.register(EntityRole::ApiKey, projection);
            let result = store.get_api_key_by_id_value(&seed.id).await;
            if fail_output {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "live enabled output")
                );
            } else {
                let result = result?.expect("projected live key");
                assert_eq!(result.name, seed.name);
                assert_eq!(result.enabled, seed.enabled);
                assert_eq!(result.remaining, Some(7.0));
                assert_eq!(
                    result.additional_fields,
                    FieldMap::from_iter([("marker".into(), "after".into())])
                );
            }
            let stored = store
                .lock()?
                .api_keys
                .find(|row| row.get("id") == Some(&seed.id.field_value()))?
                .expect("stored live key");
            assert_eq!(stored.get("name"), Some(&FieldValue::from("after")));
            assert_eq!(stored.get("enabled"), Some(&FieldValue::Bool(false)));
            assert_eq!(stored.get("remaining"), Some(&FieldValue::Number(7.0)));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn enabled_replacements_preserve_nonboolean_input_storage_and_output() -> AuthResult<()> {
    let date = FieldDate::from_milliseconds(1_893_553_445_000.0);
    for (field_type, input_value, stored, projected) in [
        (
            UserFieldType::String,
            FieldValue::from(""),
            FieldValue::from(""),
            FieldValue::from(""),
        ),
        (
            UserFieldType::Date,
            date.clone().into(),
            date.clone().into(),
            date.into(),
        ),
        (
            UserFieldType::StringArray,
            vec!["enabled".into()].into(),
            vec!["enabled".into()].into(),
            vec!["enabled".into()].into(),
        ),
        (
            UserFieldType::Json,
            FieldMap::from_iter([("active".into(), true.into())]).into(),
            "{\"active\":true}".into(),
            FieldMap::from_iter([("active".into(), true.into())]).into(),
        ),
    ] {
        let mut store = EphemeralStore::default();
        store.model_fields.register(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "enabled".into(),
                        UserFieldConfig {
                            field_type,
                            required: Some(false),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        );
        let key = store
            .create_api_key(CreateApiKey {
                enabled: SchemaValue::from_field(input_value),
                ..input()
            })
            .await?;
        assert_eq!(key.enabled.field_value(), projected);
        assert_eq!(
            store
                .lock()?
                .api_keys
                .find(|row| row.get("id") == Some(&key.id.field_value()))?
                .expect("stored replacement")
                .get("enabled"),
            Some(&stored)
        );
    }
    Ok(())
}
