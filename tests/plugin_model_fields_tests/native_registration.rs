use super::*;
use better_auth::plugins::{api_key::ApiKeyPlugin, passkey::PasskeyPlugin};
use better_auth_core::{SchemaValue, id::IdGeneration};

#[derive(Clone, Copy, Debug)]
enum Model {
    ApiKey,
    Passkey,
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::ApiKey => EntityRole::ApiKey,
            Self::Passkey => EntityRole::Passkey,
        }
    }

    fn field(self) -> &'static str {
        match self {
            Self::ApiKey => "enabled",
            Self::Passkey => "userId",
        }
    }

    fn native_names(self) -> AuthResult<Vec<String>> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../fixtures/native-plugin-replacements-memory-1.7.6.json"
        ))?;
        let target = match self {
            Self::ApiKey => "api-key-enabled-number",
            Self::Passkey => "passkey-backup-boolean",
        };
        let target = required(
            required(fixture["targets"].as_array(), "Expected captured targets")?
                .iter()
                .find(|value| value["name"] == target),
            "Expected captured native declaration",
        )?;
        let mut names = required(
            target["declaration"]["fields"].as_array(),
            "Expected captured declaration order",
        )?
        .iter()
        .map(|name| required(name.as_str(), "Expected captured field name").map(str::to_owned))
        .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(names.pop().as_deref(), Some("marker"));
        Ok(names)
    }

    async fn create(self, store: &dyn AuthStore<StatelessSchema>) -> AuthResult<FieldMap> {
        let mut input = FieldMap::from([("marker".into(), "created".into())]);
        if matches!(self, Self::Passkey) {
            let _ = input.insert("userId".into(), 7.25.into());
        }
        match self {
            Self::ApiKey => store.create_api_key_record(input).await,
            Self::Passkey => store.create_passkey_record(input).await,
        }
    }

    async fn update(self, store: &dyn AuthStore<StatelessSchema>) -> AuthResult<FieldMap> {
        let id: SchemaValue<String> = "1".to_owned().into();
        let input = [("marker".into(), "updated".into())].into();
        required(
            match self {
                Self::ApiKey => store.update_api_key_record(&id, input).await?,
                Self::Passkey => store.update_passkey_record(&id, input).await?,
            },
            "Expected updated native registration row",
        )
    }

    async fn read(self, store: &dyn AuthStore<StatelessSchema>) -> AuthResult<FieldMap> {
        let id: SchemaValue<String> = "1".to_owned().into();
        required(
            match self {
                Self::ApiKey => store.get_api_key_record(&id).await?,
                Self::Passkey => store.get_passkey_record(&id).await?,
            },
            "Expected native registration row",
        )
    }
}

type Events = Arc<Mutex<Vec<Value>>>;

fn callback(events: &Events, phase: &'static str, field: &'static str) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        trace_lock(&events)?.push(json!([phase, field, value.json()?]));
        Ok(value)
    })
}

fn declarations(model: Model, events: &Events) -> UserConfig {
    let factory = |phase: &'static str, value: f64| {
        let events = events.clone();
        Arc::new(move || {
            trace_lock(&events)?.push(json!([phase, model.field()]));
            Ok(value.into())
        }) as better_auth_core::user_fields::UserFieldFactory
    };
    UserConfig {
        additional_fields: Some(
            [
                (
                    "id".into(),
                    UserFieldConfig {
                        field_name: Some("ignored_id_alias".into()),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(|_| {
                                Err(AuthError::internal("Application ID input must be replaced"))
                            })),
                            output: Some(UserFieldTransform::new(|_| {
                                Err(AuthError::internal(
                                    "Application ID output must be replaced",
                                ))
                            })),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "marker".into(),
                    UserFieldConfig {
                        field_name: Some("stored_marker".into()),
                        transform: Some(FieldTransforms {
                            input: Some(callback(events, "input", "marker")),
                            output: Some(callback(events, "output", "marker")),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    model.field().into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        required: Some(false),
                        field_name: Some("stored_replacement".into()),
                        default_value_fn: Some(factory("default", 5.25)),
                        on_update: Some(factory("onUpdate", 6.25)),
                        transform: Some(FieldTransforms {
                            input: Some(callback(events, "input", model.field())),
                            output: Some(callback(events, "output", model.field())),
                        }),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    }
}

fn expected(model: Model, custom_first: bool, updated: bool) -> AuthResult<(FieldMap, FieldMap)> {
    let native = model.native_names()?;
    let names = if custom_first {
        ["id", "marker", model.field()]
            .map(str::to_owned)
            .into_iter()
            .chain(native.into_iter().filter(|name| name != model.field()))
            .collect::<Vec<_>>()
    } else {
        native
            .into_iter()
            .chain(["id".into(), "marker".into()])
            .collect()
    };
    let mut values: FieldMap = if matches!(model, Model::ApiKey) {
        [
            ("configId".into(), "default".into()),
            ("enabled".into(), true.into()),
            ("rateLimitEnabled".into(), true.into()),
            ("rateLimitTimeWindow".into(), 86_400_000.0.into()),
            ("rateLimitMax".into(), 10.0.into()),
            ("requestCount".into(), 0.0.into()),
        ]
        .into()
    } else {
        [("userId".into(), 7.25.into())].into()
    };
    if !custom_first {
        let _ = values.insert(
            model.field().into(),
            if updated {
                6.25
            } else if matches!(model, Model::ApiKey) {
                5.25
            } else {
                7.25
            }
            .into(),
        );
    }
    let _ = values.insert("id".into(), 1.0.into());
    let _ = values.insert(
        "marker".into(),
        if updated { "updated" } else { "created" }.into(),
    );
    let stored = names
        .iter()
        .filter_map(|name| {
            values.get(name).map(|value| {
                let column = if name == "marker" {
                    "stored_marker"
                } else if !custom_first && name == model.field() {
                    "stored_replacement"
                } else {
                    name
                };
                (column.to_owned(), value.clone())
            })
        })
        .collect();
    let _ = values.insert("id".into(), "1".into());
    if matches!(model, Model::ApiKey) {
        let _ = values.insert("metadata".into(), FieldValue::Null);
    } else if custom_first {
        let _ = values.insert("userId".into(), "7.25".into());
    }
    let output = names
        .into_iter()
        .map(|name| {
            let value = values.get(&name).cloned().unwrap_or_default();
            (name, value)
        })
        .collect();
    Ok((output, stored))
}

fn expected_events(model: Model, custom_first: bool, stage: &str) -> Vec<Value> {
    let marker = if stage == "create" {
        "created"
    } else {
        "updated"
    };
    let mut events = Vec::new();
    if !custom_first {
        if stage == "update" {
            events.push(json!(["onUpdate", model.field()]));
        } else if stage == "create" && matches!(model, Model::ApiKey) {
            events.push(json!(["default", model.field()]));
        }
        let value = if stage == "create" {
            if matches!(model, Model::ApiKey) {
                5.25
            } else {
                7.25
            }
        } else {
            6.25
        };
        if stage != "read" {
            events.push(json!(["input", model.field(), value]));
            events.push(json!(["input", "marker", marker]));
        }
        events.push(json!(["output", model.field(), value]));
    } else if stage != "read" {
        events.push(json!(["input", "marker", marker]));
    }
    events.push(json!(["output", "marker", marker]));
    events
}

// The pinned get-tables merge keeps first insertion positions and replaces complete declarations.
#[tokio::test]
async fn native_plugin_registration_replaces_policies_without_moving_extension_or_id_slots()
-> AuthResult<()> {
    for model in [Model::ApiKey, Model::Passkey] {
        for custom_first in [true, false] {
            let events = Events::default();
            let mut config = config();
            config.telemetry.enabled = false;
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
            let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
            let custom = Fields(vec![(model.role(), declarations(model, &events))]);
            let builder = BetterAuth::new(config).store_arc(raw.clone());
            let builder = match (model, custom_first) {
                (Model::ApiKey, true) => builder
                    .plugin(custom)
                    .plugin(ApiKeyPlugin::builder().build()),
                (Model::ApiKey, false) => builder
                    .plugin(ApiKeyPlugin::builder().build())
                    .plugin(custom),
                (Model::Passkey, true) => builder.plugin(custom).plugin(PasskeyPlugin::new()),
                (Model::Passkey, false) => builder.plugin(PasskeyPlugin::new()).plugin(custom),
            };
            let auth = builder.build().await?;
            for stage in ["create", "update", "read"] {
                let output = match stage {
                    "create" => model.create(auth.store().as_ref()).await?,
                    "update" => model.update(auth.store().as_ref()).await?,
                    _ => model.read(auth.store().as_ref()).await?,
                };
                let (expected_output, expected_storage) =
                    expected(model, custom_first, stage != "create")?;
                assert_eq!(
                    output, expected_output,
                    "{model:?} custom_first={custom_first} {stage}"
                );
                assert_eq!(
                    output.keys().collect::<Vec<_>>(),
                    expected_output.keys().collect::<Vec<_>>()
                );
                let stored = raw.plugin_storage_rows(model.role())?;
                assert_eq!(stored, [expected_storage.clone()]);
                assert_eq!(
                    required(stored.first(), "Expected physical row")?
                        .keys()
                        .collect::<Vec<_>>(),
                    expected_storage.keys().collect::<Vec<_>>()
                );
                assert_eq!(
                    *trace_lock(&events)?,
                    expected_events(model, custom_first, stage)
                );
                trace_lock(&events)?.clear();
            }
        }
    }
    Ok(())
}
