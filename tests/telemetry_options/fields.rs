use super::core::{
    FieldMap, FieldValue,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
        UserFieldType,
    },
};
use super::*;
use better_auth::plugins::last_login_method::{LastLoginMethodConfig, LastLoginMethodPlugin};
use std::sync::atomic::{AtomicUsize, Ordering};

fn configured_fields(name: &str, calls: &Arc<AtomicUsize>) -> UserConfig {
    let mut fields = UserConfig::default();
    match name {
        "empty" => {
            let _ = fields.fields_mut();
        }
        "types" => {
            for (index, field_type) in [
                UserFieldType::String,
                UserFieldType::Number,
                UserFieldType::Boolean,
                UserFieldType::Date,
                UserFieldType::Json,
                UserFieldType::StringArray,
                UserFieldType::NumberArray,
                UserFieldType::Enum(vec!["bronze".into(), "silver".into()]),
            ]
            .into_iter()
            .enumerate()
            {
                let _ = fields.fields_mut().insert(
                    format!("field{index}"),
                    UserFieldConfig {
                        field_type,
                        ..Default::default()
                    },
                );
            }
        }
        "flags" => {
            for (name, flag) in [
                ("omitted", None),
                ("enabled", Some(true)),
                ("disabled", Some(false)),
            ] {
                let _ = fields.fields_mut().insert(
                    name.into(),
                    UserFieldConfig {
                        required: flag,
                        input: flag,
                        returned: flag,
                        ..Default::default()
                    },
                );
            }
        }
        "declaration" => {
            for (name, field) in [
                (
                    "label",
                    UserFieldConfig {
                        field_name: Some("display_label".into()),
                        default_value: Some("hello".into()),
                        ..Default::default()
                    },
                ),
                (
                    "count",
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        default_value: Some(7.0.into()),
                        ..Default::default()
                    },
                ),
                (
                    "settings",
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        default_value: Some(
                            FieldMap::from([
                                ("theme".into(), "light".into()),
                                ("tags".into(), vec!["ordinary".into()].into()),
                            ])
                            .into(),
                        ),
                        ..Default::default()
                    },
                ),
                (
                    "reference",
                    UserFieldConfig {
                        references: Some(UserFieldReference {
                            model: "user".into(),
                            field: "id".into(),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "nothing",
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        default_value: Some(FieldValue::Null),
                        ..Default::default()
                    },
                ),
            ] {
                let _ = fields.fields_mut().insert(name.into(), field);
            }
        }
        "transforms" => {
            let count = calls.clone();
            let sync = UserFieldTransform::new(move |value| {
                let _ = count.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            });
            let count = calls.clone();
            let asynchronous = UserFieldTransform::new_async(move |value| {
                let count = count.clone();
                async move {
                    let _ = count.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                }
            });
            for (name, transform) in [
                ("omitted", None),
                ("empty", Some(FieldTransforms::default())),
                (
                    "input",
                    Some(FieldTransforms {
                        input: Some(sync.clone()),
                        ..Default::default()
                    }),
                ),
                (
                    "output",
                    Some(FieldTransforms {
                        output: Some(sync.clone()),
                        ..Default::default()
                    }),
                ),
                (
                    "both",
                    Some(FieldTransforms {
                        input: Some(sync.clone()),
                        output: Some(sync),
                    }),
                ),
                (
                    "asynchronous",
                    Some(FieldTransforms {
                        input: Some(asynchronous.clone()),
                        output: Some(asynchronous),
                    }),
                ),
            ] {
                let _ = fields.fields_mut().insert(
                    name.into(),
                    UserFieldConfig {
                        transform,
                        ..Default::default()
                    },
                );
            }
        }
        "factories" => {
            let count = calls.clone();
            let default_value_fn: Arc<dyn Fn() -> FieldValue + Send + Sync> = Arc::new(move || {
                let _ = count.fetch_add(1, Ordering::SeqCst);
                "hello".into()
            });
            let count = calls.clone();
            let on_update: Arc<dyn Fn() -> FieldValue + Send + Sync> = Arc::new(move || {
                let _ = count.fetch_add(1, Ordering::SeqCst);
                "updated".into()
            });
            let _ = fields.fields_mut().insert(
                "label".into(),
                UserFieldConfig {
                    default_value_fn: Some(default_value_fn),
                    on_update: Some(on_update),
                    ..Default::default()
                },
            );
        }
        _ => {}
    }
    fields
}

#[tokio::test]
async fn additional_field_metadata_matches_real_initialization() -> AuthResult<()> {
    let expected: Value =
        serde_json::from_str(include_str!("../fixtures/telemetry-fields-init-1.7.6.json"))?;
    let calls = Arc::new(AtomicUsize::new(0));
    for name in [
        "omitted",
        "empty",
        "types",
        "flags",
        "declaration",
        "transforms",
        "factories",
        "plugin",
    ] {
        let (mut config, reports) = configuration();
        config.user = configured_fields(name, &calls);
        config.session.additional_fields = config.user.additional_fields.clone();
        let mut builder = BetterAuth::stateless(config);
        if name == "plugin" {
            builder = builder.plugin(LastLoginMethodPlugin::new(LastLoginMethodConfig {
                store_in_database: true,
                ..Default::default()
            }));
        }
        let auth = builder.build().await?;
        if name != "plugin" {
            assert_eq!(
                auth.context().config.user.additional_fields.is_some(),
                name != "omitted"
            );
        }
        assert_eq!(
            auth.context().config.session.additional_fields.is_some(),
            !matches!(name, "omitted" | "plugin")
        );
        for model in ["user", "session"] {
            assert_eq!(
                reports.config()?[model].get("additionalFields"),
                expected[name][model].get("additionalFields"),
                "{name}/{model}"
            );
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "initialization must not invoke field callbacks"
    );
    Ok(())
}
