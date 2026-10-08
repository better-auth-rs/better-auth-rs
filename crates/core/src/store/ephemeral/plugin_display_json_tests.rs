use super::*;
use crate::plugin_runtime::ModelFields;
use crate::store::{ApiKeyStore, schema::EntityRole};
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    UserFieldType,
};
use crate::{CreateApiKey, SchemaValue, UpdatePasskeyAuthentication};

fn json_field() -> UserFieldConfig {
    UserFieldConfig {
        field_type: UserFieldType::Json,
        required: Some(false),
        ..Default::default()
    }
}

fn fields(fields: impl IntoIterator<Item = (&'static str, UserFieldConfig)>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            fields
                .into_iter()
                .map(|(name, field)| (name.to_owned(), field))
                .collect(),
        ),
    }
}

fn api_key(name: Value) -> CreateApiKey {
    CreateApiKey {
        additional_fields: FieldMap::new(),
        reference_id: "owner".into(),
        config_id: "default".into(),
        name: SchemaValue::from_field(name),
        prefix: None,
        key_hash: "stored-hash".into(),
        start: None,
        expires_at: None,
        remaining: None,
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
        refill_interval: None,
        refill_amount: None,
        permissions: None,
        metadata: None,
        enabled: true.into(),
    }
}

#[tokio::test]
async fn json_api_key_name_projects_after_reading_raw_storage() -> AuthResult<()> {
    let object: Value = FieldMap::from_iter([("desk".into(), 1.into())]).into();
    let array: Value = vec![2.into(), "desk".into()].into();
    let cases = [
        (object.clone(), r#"{"desk":1}"#.into(), object.clone()),
        (array.clone(), r#"[2,"desk"]"#.into(), array),
        (Value::Null, "null".into(), Value::Null),
        (
            " { \"desk\" : 1 } ".into(),
            " { \"desk\" : 1 } ".into(),
            object,
        ),
        ("invalid json".into(), "invalid json".into(), Value::Null),
        (2.into(), 2.into(), 2.into()),
        (true.into(), true.into(), true.into()),
        (Value::Undefined, Value::Undefined, Value::Undefined),
    ];
    for (supplied, stored, expected) in cases {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let output = observed.clone();
        let mut store = EphemeralStore::default();
        store.model_fields.register(
            EntityRole::ApiKey,
            fields([(
                "name",
                UserFieldConfig {
                    field_name: Some("stored_name".into()),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            output.lock().unwrap().push(value.clone());
                            Ok(value)
                        })),
                        ..Default::default()
                    }),
                    ..json_field()
                },
            )]),
        )?;
        let key = store.create_api_key(api_key(supplied)).await?;
        assert_eq!(key.name.field_value(), expected);
        assert_eq!(
            store
                .lock()?
                .api_keys
                .find(|row| row.get("id") == Some(&key.id.field_value()))?
                .unwrap()
                .get("stored_name")
                .cloned()
                .unwrap_or_default(),
            stored
        );
        let read = store.get_api_key_by_id_value(&key.id).await?.unwrap();
        assert_eq!(read.name.field_value(), expected);
        assert_eq!(*observed.lock().unwrap(), [stored.clone(), stored]);
        assert!(read.additional_fields.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn json_api_key_name_distinguishes_omission_from_explicit_null() -> AuthResult<()> {
    let default: Value = FieldMap::from_iter([("source".into(), "default".into())]).into();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let input = seen.clone();
    let mut store = EphemeralStore::default();
    store.model_fields.register(
        EntityRole::ApiKey,
        fields([(
            "name",
            UserFieldConfig {
                default_value: Some(default.clone()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        input.lock().unwrap().push(value.clone());
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..json_field()
            },
        )]),
    )?;
    let omitted = store.create_api_key(api_key(Value::Undefined)).await?;
    let explicit_null = store.create_api_key(api_key(Value::Null)).await?;
    assert_eq!(omitted.name.field_value(), default);
    assert_eq!(explicit_null.name.field_value(), Value::Null);
    assert_eq!(*seen.lock().unwrap(), [default, Value::Null]);
    assert_eq!(
        store
            .lock()?
            .api_keys
            .find(|row| row.get("id") == Some(&explicit_null.id.field_value()))?
            .unwrap()
            .get("name")
            .cloned()
            .unwrap_or_default(),
        Value::from("null")
    );
    Ok(())
}

#[tokio::test]
async fn json_api_key_name_failures_preserve_the_write_boundary() -> AuthResult<()> {
    for fail_input in [true, false] {
        let failure = UserFieldTransform::new(|_| Err(AuthError::internal("display failure")));
        let mut store = EphemeralStore::default();
        store.model_fields.register(
            EntityRole::ApiKey,
            fields([(
                "name",
                UserFieldConfig {
                    transform: Some(if fail_input {
                        FieldTransforms {
                            input: Some(failure),
                            output: None,
                        }
                    } else {
                        FieldTransforms {
                            input: None,
                            output: Some(failure),
                        }
                    }),
                    ..json_field()
                },
            )]),
        )?;
        let error = store
            .create_api_key(api_key(Value::Null))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("display failure"));
        let stored = store.lock()?.api_keys.snapshot()?;
        if fail_input {
            assert!(stored.is_empty());
        } else {
            assert_eq!(stored.len(), 1);
            assert_eq!(
                stored.first().unwrap().get("name"),
                Some(&Value::from("null"))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn json_api_key_name_callback_omission_does_not_become_null() -> AuthResult<()> {
    for omit_input in [true, false] {
        let omitted = UserFieldTransform::new(|_| Ok(Value::Undefined));
        let mut store = EphemeralStore::default();
        store.model_fields.register(
            EntityRole::ApiKey,
            fields([(
                "name",
                UserFieldConfig {
                    transform: Some(if omit_input {
                        FieldTransforms {
                            input: Some(omitted),
                            output: None,
                        }
                    } else {
                        FieldTransforms {
                            input: None,
                            output: Some(omitted),
                        }
                    }),
                    ..json_field()
                },
            )]),
        )?;
        let key = store.create_api_key(api_key(Value::Null)).await?;
        assert!(key.name.is_undefined());
        let raw = store
            .lock()?
            .api_keys
            .find(|row| row.get("id") == Some(&key.id.field_value()))?
            .unwrap();
        assert_eq!(
            raw.get("name").cloned(),
            if omit_input {
                None
            } else {
                Some(Value::from("null"))
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn json_passkey_display_updates_preserve_credential_state() -> AuthResult<()> {
    let mut store = EphemeralStore::default();
    let label = |value: Value| -> Value { FieldMap::from_iter([("label".into(), value)]).into() };
    store.model_fields.register(
        EntityRole::Passkey,
        fields([
            (
                "name",
                UserFieldConfig {
                    field_name: Some("stored_name".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |value| Ok(label(value)))),
                        ..Default::default()
                    }),
                    ..json_field()
                },
            ),
            (
                "aaguid",
                UserFieldConfig {
                    field_name: Some("stored_aaguid".into()),
                    on_update: Some(Arc::new(|| Ok(vec![2.into(), 3.into()].into()))),
                    ..json_field()
                },
            ),
        ]),
    )?;
    let original_aaguid: Value = FieldMap::from_iter([("device".into(), 1.into())]).into();
    let key = store
        .create_passkey(CreatePasskey {
            additional_fields: FieldMap::new(),
            user_id: "owner".into(),
            name: Some("initial".into()).into(),
            credential_id: "credential-id".into(),
            public_key: "public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            credential: "credential".into(),
            aaguid: SchemaValue::from_field(original_aaguid.clone()),
        })
        .await?;
    assert_eq!(key.name.field_value(), label("initial".into()));
    assert_eq!(key.aaguid.field_value(), original_aaguid);
    let renamed = store
        .update_passkey_name(key.id.typed()?, "updated")
        .await?;
    assert_eq!(renamed.name.field_value(), label("updated".into()));
    assert_eq!(
        renamed.aaguid.field_value(),
        Value::from(vec![2.into(), 3.into()])
    );
    assert_eq!(renamed.credential.typed()?, "credential");
    let authenticated = store
        .update_passkey_authentication(
            &key.id,
            UpdatePasskeyAuthentication::Legacy {
                credential: "updated-credential".into(),
                counter: 7,
                backed_up: true,
                device_type: "multiDevice".into(),
            },
        )
        .await?;
    assert_eq!(authenticated.name, renamed.name);
    assert_eq!(authenticated.aaguid, renamed.aaguid);
    assert_eq!(authenticated.counter, 7);
    assert_eq!(authenticated.credential.typed()?, "updated-credential");
    assert_eq!(authenticated.user_id.typed()?, "owner");
    assert_eq!(authenticated.credential_id, "credential-id");
    assert_eq!(authenticated.public_key, "public-key");
    let stored = store
        .lock()?
        .passkeys
        .find(|row| row.get("id") == Some(&key.id.field_value()))?
        .unwrap();
    assert_eq!(
        stored.get("stored_name"),
        Some(&Value::from(r#"{"label":"updated"}"#))
    );
    assert_eq!(stored.get("stored_aaguid"), Some(&Value::from("[2,3]")));
    Ok(())
}

#[test]
fn json_display_declarations_accept_references_and_shared_columns() {
    for (role, name, reserved) in [
        (EntityRole::ApiKey, "name", "referenceId"),
        (EntityRole::Passkey, "name", "credentialID"),
        (EntityRole::Passkey, "aaguid", "name"),
    ] {
        let mut models = ModelFields::default();
        let referenced = UserFieldConfig {
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            ..json_field()
        };
        assert!(models.register(role, fields([(name, referenced)])).is_ok());
        let replacement = UserFieldConfig {
            field_name: Some(reserved.into()),
            ..json_field()
        };
        assert!(models.register(role, fields([(name, replacement)])).is_ok());
        let mapped = UserFieldConfig {
            field_name: Some("stored_display".into()),
            ..json_field()
        };
        assert!(
            models
                .register(role, fields([(name, mapped.clone())]))
                .is_ok()
        );
        assert!(models.register(role, fields([("other", mapped)])).is_ok());
    }
}
