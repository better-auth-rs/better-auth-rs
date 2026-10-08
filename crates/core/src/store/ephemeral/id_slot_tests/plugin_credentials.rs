use super::*;
use crate::SchemaValue;
use crate::store::{ApiKeyStore, schema::EntityRole};
use crate::user_fields::UserConfig;

#[derive(Clone, Copy, Debug)]
enum Model {
    ApiKey,
    Passkey,
    TwoFactor,
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::ApiKey => EntityRole::ApiKey,
            Self::Passkey => EntityRole::Passkey,
            Self::TwoFactor => EntityRole::TwoFactor,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ApiKey => "apikey",
            Self::Passkey => "passkey",
            Self::TwoFactor => "twoFactor",
        }
    }

    fn field(self) -> &'static str {
        match self {
            Self::ApiKey | Self::Passkey => "name",
            Self::TwoFactor => "secret",
        }
    }

    async fn create(self, store: &EphemeralStore, input: FieldMap) -> AuthResult<FieldMap> {
        match self {
            Self::ApiKey => store.create_api_key_record(input).await,
            Self::Passkey => store.create_passkey_record(input).await,
            Self::TwoFactor => store.create_two_factor_record(input).await,
        }
    }

    async fn read(self, store: &EphemeralStore, id: Value) -> AuthResult<Option<FieldMap>> {
        let id = SchemaValue::from_field(id);
        match self {
            Self::ApiKey => store.get_api_key_record(&id).await,
            Self::Passkey => store.get_passkey_record(&id).await,
            Self::TwoFactor => store.get_two_factor_record(&id).await,
        }
    }

    async fn update(
        self,
        store: &EphemeralStore,
        id: Value,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let id = SchemaValue::from_field(id);
        match self {
            Self::ApiKey => store.update_api_key_record(&id, input).await,
            Self::Passkey => store.update_passkey_record(&id, input).await,
            Self::TwoFactor => store.update_two_factor_record(&id, input).await,
        }
    }

    fn source(self, store: &EphemeralStore) -> AuthResult<super::super::rows::RowRef<FieldMap>> {
        let state = store.lock()?;
        required(match self {
            Self::ApiKey => state.api_keys.first_ref(|_| true)?,
            Self::Passkey => state.passkeys.first_ref(|_| true)?,
            Self::TwoFactor => state.two_factors.first_ref(|_| true)?,
        })
    }

    async fn typed_fields(self, store: &EphemeralStore, id: &str) -> AuthResult<FieldMap> {
        match self {
            Self::ApiKey => required(store.get_api_key_by_id(id).await?)?.field_values(),
            Self::Passkey => required(store.get_passkey_by_id(id).await?)?.field_values(),
            Self::TwoFactor => {
                required(store.get_two_factor_by_user_id("selected-owner").await?)?.field_values()
            }
        }
    }
}

// These regressions reuse source-derived ID invariants; the ID fixture has no credential models.
#[tokio::test]
async fn memory_plugin_id_slot_reads_primary_key_at_its_position() -> AuthResult<()> {
    for model in [Model::ApiKey, Model::Passkey, Model::TwoFactor] {
        for slot in ["before-label", "after-label"] {
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
            let mut writer = EphemeralStore::new(Arc::new(config));
            writer.model_fields.register(
                model.role(),
                UserConfig {
                    additional_fields: Some([("label".into(), UserFieldConfig::default())].into()),
                },
            )?;
            let mut expected = model
                .create(&writer, [("label".into(), "selected".into())].into())
                .await?;
            let source = model.source(&writer)?;
            let mut expected_raw = source.read(|row| Ok(row.clone()))?;
            let target = source.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let output_calls = calls.clone();
            let mut fields = UserConfig::default();
            install_fields(
                fields.fields_mut(),
                slot,
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            let _ = output_calls.fetch_add(1, Ordering::SeqCst);
                            target.write(|row| {
                                let _ = row.insert("id".into(), Value::Number(101.0));
                                Ok(())
                            })?;
                            Ok(format!("{}:out", required(value.as_str())?).into())
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let mut reader = EphemeralStore::new(writer.config.clone());
            reader.state = writer.state.clone();
            reader.model_fields.register(model.role(), fields)?;
            let output = required(model.read(&reader, "1".into()).await?)?;
            let _ = expected.insert(
                "id".into(),
                if slot == "before-label" { "1" } else { "101" }.into(),
            );
            let _ = expected.insert("label".into(), "selected:out".into());
            let _ = expected_raw.insert("id".into(), Value::Number(101.0));
            assert_eq!(output, expected, "{model:?} {slot}");
            assert_eq!(source.read(|row| Ok(row.clone()))?, expected_raw);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_plugin_supplied_ids_preserve_defaults_presence_and_query_types() -> AuthResult<()> {
    for model in [Model::ApiKey, Model::Passkey, Model::TwoFactor] {
        for (supplied, stored_id, output_id, generated) in [
            (
                None,
                Some("generated-id".into()),
                "generated-id".into(),
                true,
            ),
            (
                Some(Value::Undefined),
                Some("generated-id".into()),
                "generated-id".into(),
                true,
            ),
            (
                Some(Value::Null),
                Some("generated-id".into()),
                "generated-id".into(),
                true,
            ),
            (Some(false.into()), None, Value::Undefined, false),
            (Some(0.into()), None, Value::Undefined, false),
            (Some("".into()), None, Value::Undefined, false),
            (Some(true.into()), Some(true.into()), "true".into(), false),
            (Some(42.into()), Some(42.into()), "42".into(), false),
            (
                Some("forced-id".into()),
                Some("forced-id".into()),
                "forced-id".into(),
                false,
            ),
        ] {
            let trace = Events::default();
            let generator_trace = trace.clone();
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id =
                Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                    record(&generator_trace, json!(["generate", request.model]))?;
                    Ok(Some("generated-id".into()))
                })));
            let store = EphemeralStore::new(Arc::new(config));
            let mut input = FieldMap::from([(model.field().into(), "selected".into())]);
            if let Some(supplied) = supplied {
                let _ = input.insert("id".into(), supplied);
            }
            let mut output = model.create(&store, input).await?;
            assert_eq!(output.get("id"), Some(&output_id));
            let before = store.plugin_storage_rows(model.role())?;
            assert_eq!(before.len(), 1);
            assert_eq!(required(before.first())?.get("id"), stored_id.as_ref());
            let query_id = stored_id.clone().unwrap_or_default();
            assert_eq!(
                required(model.read(&store, query_id.clone()).await?)?,
                output
            );
            if stored_id.is_none() {
                assert_eq!(required(model.read(&store, Value::Null).await?)?, output);
            } else if !query_id.is_string() {
                assert!(model.read(&store, output_id).await?.is_none());
            }
            assert_eq!(store.plugin_storage_rows(model.role())?, before);
            let patch = FieldMap::from([(model.field().into(), "updated".into())]);
            let updated = required(model.update(&store, query_id, patch).await?)?;
            let _ = output.insert(model.field().into(), "updated".into());
            assert_eq!(updated, output);
            let mut expected_raw = required(before.first())?.clone();
            let _ = expected_raw.insert(model.field().into(), "updated".into());
            assert_eq!(store.plugin_storage_rows(model.role())?, [expected_raw]);
            assert_eq!(
                events(&trace)?,
                if generated {
                    vec![json!(["generate", model.name()])]
                } else {
                    Vec::new()
                }
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_plugin_primary_id_filters_distinguish_null_from_undefined() -> AuthResult<()> {
    for model in [Model::ApiKey, Model::Passkey, Model::TwoFactor] {
        for (stored_id, output_id, matches) in [
            (None, Value::Undefined, [true, true, false, false]),
            (
                Some(Value::Undefined),
                Value::Undefined,
                [true, true, false, false],
            ),
            (Some(Value::Null), Value::Null, [false, true, false, false]),
            (Some(42.into()), "42".into(), [false, false, true, false]),
        ] {
            let store = EphemeralStore::default();
            let mut expected = model
                .create(
                    &store,
                    [
                        ("id".into(), "selected".into()),
                        (model.field().into(), "stored-name".into()),
                    ]
                    .into(),
                )
                .await?;
            let source = model.source(&store)?;
            source.write(|row| {
                let _ = row.shift_remove("id");
                if let Some(id) = stored_id {
                    let _ = row.insert("id".into(), id);
                }
                Ok(())
            })?;
            let before = store.plugin_storage_rows(model.role())?;
            let _ = expected.insert("id".into(), output_id);
            for (query, matched) in [Value::Undefined, Value::Null, 42.into(), "42".into()]
                .into_iter()
                .zip(matches)
            {
                assert_eq!(
                    model.read(&store, query).await?,
                    matched.then(|| expected.clone())
                );
            }
            assert_eq!(store.plugin_storage_rows(model.role())?, before);
            let query = if matches[2] { 42.into() } else { Value::Null };
            let updated = required(
                model
                    .update(
                        &store,
                        query,
                        [(model.field().into(), "updated".into())].into(),
                    )
                    .await?,
            )?;
            let _ = expected.insert(model.field().into(), "updated".into());
            assert_eq!(updated, expected);
            let mut expected_raw = required(before.first())?.clone();
            let _ = expected_raw.insert(model.field().into(), "updated".into());
            assert_eq!(store.plugin_storage_rows(model.role())?, [expected_raw]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_plugin_typed_reads_preserve_raw_output_values_and_presence() -> AuthResult<()> {
    for model in [Model::ApiKey, Model::Passkey, Model::TwoFactor] {
        for output_value in [
            Value::Undefined,
            Value::Null,
            FieldMap::from([("native".into(), true.into())]).into(),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let output_calls = calls.clone();
            let expected_value = output_value.clone();
            let mut store = EphemeralStore::default();
            store.model_fields.register(
                model.role(),
                UserConfig {
                    additional_fields: Some(
                        [(
                            model.field().into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    output: Some(UserFieldTransform::new(move |_| {
                                        let _ = output_calls.fetch_add(1, Ordering::SeqCst);
                                        Ok(output_value.clone())
                                    })),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
            )?;
            let mut input = FieldMap::from([
                ("id".into(), "selected".into()),
                (model.field().into(), "stored-name".into()),
            ]);
            if matches!(model, Model::TwoFactor) {
                let _ = input.insert("userId".into(), "selected-owner".into());
            }
            let created = model.create(&store, input).await?;
            let before = store.plugin_storage_rows(model.role())?;
            let raw = required(model.read(&store, "selected".into()).await?)?;
            assert_eq!(raw, created);
            assert_eq!(raw.get(model.field()), Some(&expected_value));
            let mut typed = model.typed_fields(&store, "selected").await?;
            if matches!(model, Model::Passkey) {
                for internal in ["credential", "updatedAt"] {
                    assert!(!raw.contains_key(internal));
                    assert_eq!(typed.shift_remove(internal), Some(Value::Undefined));
                }
            }
            if matches!(model, Model::TwoFactor) {
                for internal in ["createdAt", "updatedAt"] {
                    assert!(!raw.contains_key(internal));
                    assert_eq!(typed.shift_remove(internal), Some(Value::Undefined));
                }
            }
            assert_eq!(typed, raw, "{model:?}");
            assert_eq!(store.plugin_storage_rows(model.role())?, before);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }
    }
    Ok(())
}
