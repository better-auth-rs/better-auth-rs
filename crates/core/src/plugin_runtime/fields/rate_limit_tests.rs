use super::*;
use crate::store::schema::SchemaConfiguration;
use crate::user_fields::{
    AdapterRecord, FieldOutputCapabilities, FieldTransforms, UserFieldConfig, UserFieldTransform,
};

fn replacement() -> UserConfig {
    UserConfig {
        additional_fields: Some(
            ["id", "count", "key", "label"]
                .into_iter()
                .map(|name| {
                    (
                        name.into(),
                        UserFieldConfig {
                            field_name: Some(format!("plugin_{name}")),
                            required: Some(false),
                            returned: Some(false),
                            unique: Some(false),
                            default_value_fn: Some(crate::user_fields::UserFieldFactory::new(
                                || Err(AuthError::internal("Discarded RateLimit default ran")),
                            )),
                            on_update: Some(crate::user_fields::UserFieldFactory::new(|| {
                                Err(AuthError::internal("Discarded RateLimit update ran"))
                            })),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(|_| {
                                    Err(AuthError::internal("Discarded RateLimit input ran"))
                                })),
                                output: Some(UserFieldTransform::new(|_| {
                                    Err(AuthError::internal("Discarded RateLimit output ran"))
                                })),
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract propagates setup errors and asserts complete declaration replacement"
)]
async fn database_rate_limit_replaces_the_complete_declaration_without_resetting_history()
-> AuthResult<()> {
    for database_rate_limit in [false, true] {
        for mapping in ["native", "mapped", "empty"] {
            let name = |logical: &str| {
                if mapping == "mapped" {
                    format!("physical_{logical}")
                } else {
                    logical.to_owned()
                }
            };
            let rate_limit = crate::middleware::RateLimitConfig {
                storage: database_rate_limit
                    .then_some(crate::middleware::RateLimitStorageKind::Database),
                model_name: match mapping {
                    "mapped" => Some("mapped_counter".into()),
                    "empty" => Some(String::new()),
                    _ => None,
                },
                fields: (mapping != "native").then(|| {
                    ["key", "count", "lastRequest", "id", "extra"]
                        .into_iter()
                        .map(|logical| {
                            (
                                logical.into(),
                                if mapping == "empty" {
                                    String::new()
                                } else {
                                    name(logical)
                                },
                            )
                        })
                        .collect()
                }),
                ..Default::default()
            };
            let mut fields = ModelFields::default();
            fields.register_custom_model("before", Some("shared"), UserConfig::default())?;
            fields.register(EntityRole::RateLimit, replacement());
            fields.set_model_name(EntityRole::RateLimit, Some("plugin_counter"))?;
            fields.register_custom_model("after", Some("shared"), UserConfig::default())?;
            let history = AdapterIdInput {
                force_allow_id: true,
                supports_native_uuid: true,
            };
            fields.begin_id_input(EntityRole::RateLimit, history)?;
            fields.set_schema_configuration(&SchemaConfiguration {
                config: Arc::new(AuthConfig::default()),
                plugins: Vec::new(),
                metadata: Default::default(),
                secondary_storage: false,
                rate_limit,
            });
            assert!(
                matches!(fields.declarations.get_index(0), Some((ModelKey::Custom(name), _)) if name == "before")
            );
            assert!(matches!(
                fields.declarations.get_index(1),
                Some((ModelKey::Native(EntityRole::RateLimit), _))
            ));
            assert!(
                matches!(fields.declarations.get_index(2), Some((ModelKey::Custom(name), _)) if name == "after")
            );
            let active = fields.id_input_policy(EntityRole::RateLimit)?;
            assert!(
                active.is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
            );
            let schema = fields.plugin_fields(EntityRole::RateLimit);
            if !database_rate_limit {
                assert_eq!(
                    schema
                        .fields()
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    ["id", "count", "key", "label"]
                );
                assert_eq!(
                    fields.storage_model_name(EntityRole::RateLimit, "configured_counter"),
                    "plugin_counter"
                );
                for name in ["rateLimit", "plugin_counter"] {
                    assert_eq!(fields.resolve_model_name(name, &|_, _| false)?, "rateLimit");
                }
                assert!(
                    schema
                        .fields()
                        .get("id")
                        .ok_or_else(|| AuthError::internal("Missing declared RateLimit ID"))?
                        .transform
                        .is_some()
                );
                continue;
            }
            assert_eq!(
                schema
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["key", "count", "lastRequest"]
            );
            assert_eq!(
                fields.storage_model_name(EntityRole::RateLimit, "configured_counter"),
                match mapping {
                    "mapped" => "mapped_counter",
                    "empty" => "rateLimit",
                    _ => "configured_counter",
                }
            );
            let aliases = |role, name: &str| role == EntityRole::RateLimit && name == "shared";
            assert_eq!(fields.resolve_model_name("shared", &aliases)?, "before");
            assert_eq!(
                fields.resolve_model_name("rateLimit", &aliases)?,
                "rateLimit"
            );
            assert!(
                fields
                    .resolve_model_name("plugin_counter", &aliases)
                    .is_err()
            );
            assert_eq!(
                fields.resolve_model_name(
                    match mapping {
                        "mapped" => "mapped_counter",
                        "empty" => "rateLimit",
                        _ => "configured_counter",
                    },
                    &|role, name| role == EntityRole::RateLimit && name == "configured_counter",
                )?,
                "rateLimit"
            );
            for (logical, field) in schema.fields() {
                assert_eq!(field.required, Some(true));
                assert_eq!(field.field_name, Some(name(logical)));
                assert_eq!(field.returned, None);
                assert_eq!(field.unique, (logical == "key").then_some(true));
                assert_eq!(field.bigint, (logical == "lastRequest").then_some(true));
                assert!(field.default_value.is_none());
                assert_eq!(field.default_value_fn.is_some(), logical == "lastRequest");
                assert!(field.on_update.is_none());
                assert!(field.transform.is_none());
            }
            for name in ["key", "count", "lastRequest"] {
                let field = schema.fields().get(name).ok_or_else(|| {
                    AuthError::internal(format!("Missing native RateLimit {name}"))
                })?;
                assert!(matches!(
                    (name, &field.field_type),
                    ("key", UserFieldType::String)
                        | ("count" | "lastRequest", UserFieldType::Number)
                ));
            }
            let input: FieldMap = [
                ("key".into(), "bucket".into()),
                ("count".into(), 1.into()),
                ("lastRequest".into(), 100.into()),
            ]
            .into();
            let schema = schema.adapter_fields(&[]);
            let stored = schema
                .storage_fields_with_bound_id(
                    input.clone(),
                    true,
                    || Ok(Some("counter".into())),
                    |_, _, value| Ok(value),
                )
                .await?;
            let mut expected: FieldMap = input
                .iter()
                .map(|(logical, value)| (name(logical), value.clone()))
                .collect();
            let _ = expected.insert("id".into(), "counter".into());
            assert_eq!(stored, expected);
            assert_eq!(
                stored.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>()
            );
            let mut projected = input;
            let _ = projected.insert("id".into(), "counter".into());
            let capabilities = FieldOutputCapabilities::json_only(true);
            let actual = schema
                .project_adapter_records_with_capabilities(
                    vec![AdapterRecord::from_storage_object(
                        stored.clone().into(),
                        capabilities,
                    )],
                    capabilities,
                )
                .await?;
            assert_eq!(actual, [projected.clone()]);
            assert_eq!(
                actual.first().map(|row| row.keys().collect::<Vec<_>>()),
                Some(projected.keys().collect::<Vec<_>>())
            );
            let update: FieldMap = [("count".into(), 2.into())].into();
            assert_eq!(
                schema
                    .storage_fields_with_bound_id(
                        update.clone(),
                        false,
                        || Ok(None),
                        |_, _, value| Ok(value)
                    )
                    .await?,
                FieldMap::from([(name("count"), 2.into())])
            );
            assert!(
                fields
                    .id_input_policy(EntityRole::RateLimit)?
                    .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
            );
        }
    }
    Ok(())
}
