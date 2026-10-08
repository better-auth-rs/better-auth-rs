use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth_core::{AuthConfig, AuthInitContext};
use sea_orm::Database;
use std::sync::Arc;

#[tokio::test]
async fn id_sort_uses_the_primary_key_despite_an_application_field_name() -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let at = Utc::now();
    for (id, name) in [("a-key", "Zulu"), ("z-key", "Alpha")] {
        let _ = store
            .create_api_key_record(FieldMap::from([
                ("id".into(), id.into()),
                ("name".into(), name.into()),
                ("referenceId".into(), "owner".into()),
                ("key".into(), format!("hash:{id}").into()),
                ("createdAt".into(), at.into()),
                ("updatedAt".into(), at.into()),
            ]))
            .await?;
    }
    for field_name in ["name", "column-that-does-not-exist"] {
        let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
        init.register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "id".into(),
                        UserFieldConfig {
                            field_name: Some(field_name.into()),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )?;
        store.model_fields = init.into_parts().plugin_fields;
        store
            .validate_plugin_fields::<super::super::entities::api_key::Model>(EntityRole::ApiKey)?;
        for (direction, expected) in [("asc", ["a-key", "z-key"]), ("desc", ["z-key", "a-key"])] {
            let rows = store
                .find_api_keys_by_reference("owner", Some(("id", direction)))
                .await?;
            let ids = rows
                .iter()
                .map(|row| row.id.typed().map(String::as_str))
                .collect::<AuthResult<Vec<_>>>()?;
            assert_eq!(ids, expected, "configured id fieldName: {field_name}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn usage_null_guards_distinguish_json_null_from_sql_null() -> AuthResult<()> {
    for json_null in [true, false] {
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(map_db_err)?;
        run_migrations(&database).await.map_err(map_db_err)?;
        let mut store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("a-secret-that-is-at-least-32-characters"),
            database,
        );
        let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
        init.register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    ["lastRefillAt", "lastRequest"]
                        .into_iter()
                        .map(|name| {
                            (
                                name.into(),
                                UserFieldConfig {
                                    field_type: UserFieldType::Json,
                                    required: Some(false),
                                    ..Default::default()
                                },
                            )
                        })
                        .collect(),
                ),
            },
        )?;
        store.model_fields = init.into_parts().plugin_fields;
        let at = Utc::now();
        let mut input = FieldMap::from([
            ("id".into(), "json-null-guard".into()),
            ("referenceId".into(), "owner".into()),
            ("key".into(), "json-null-guard-key".into()),
            ("createdAt".into(), at.into()),
            ("updatedAt".into(), at.into()),
            ("remaining".into(), 2.0.into()),
        ]);
        if json_null {
            input.extend([
                ("lastRefillAt".into(), FieldValue::Null),
                ("lastRequest".into(), FieldValue::Null),
            ]);
        }
        let created = store
            .create_api_key_record(input)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the nullable-counter API Key"))?;
        assert_eq!(created.get("lastRefillAt"), Some(&FieldValue::Null));
        assert_eq!(created.get("lastRequest"), Some(&FieldValue::Null));
        let id = "json-null-guard".to_owned().into();
        for write in [
            ApiKeyUsageWrite::Refill {
                previous: FieldValue::Null,
                remaining: 7.0,
                at,
            },
            ApiKeyUsageWrite::StartWindow {
                previous_before: None,
                at,
            },
        ] {
            assert_eq!(
                store
                    .write_api_key_usage(&id, write.clone())
                    .await?
                    .is_some(),
                json_null,
                "JSON null must match its encoded storage value"
            );
            assert!(store.write_api_key_usage(&id, write).await?.is_none());
        }
        let persisted = store
            .get_api_key_by_id("json-null-guard")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the guarded API Key"))?;
        assert_eq!(persisted.remaining, Some(if json_null { 7.0 } else { 2.0 }));
        assert_eq!(
            persisted.request_count,
            Some(if json_null { 1.0 } else { 0.0 })
        );
    }
    Ok(())
}

#[tokio::test]
async fn undefined_refill_snapshot_does_not_match_a_null_timestamp() -> AuthResult<()> {
    use better_auth_core::store::ConsumeApiKeyResult;
    use better_auth_core::user_fields::{FieldTransforms, UserFieldTransform};

    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let at = Utc::now() - chrono::Duration::hours(1);
    let _ = store
        .create_api_key_record(FieldMap::from([
            ("id".into(), "undefined-refill".into()),
            ("referenceId".into(), "owner".into()),
            ("key".into(), "undefined-refill-key".into()),
            ("createdAt".into(), at.into()),
            ("updatedAt".into(), at.into()),
            ("remaining".into(), 0.0.into()),
            ("refillInterval".into(), 1000.0.into()),
            ("refillAmount".into(), 8.0.into()),
        ]))
        .await?;
    let reader = store.clone();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [(
                    "lastRefillAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        required: Some(false),
                        transform: Some(FieldTransforms {
                            output: Some(UserFieldTransform::new(|_| Ok(FieldValue::Undefined))),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    let snapshot = store
        .get_api_key_by_id("undefined-refill")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the API Key refill snapshot"))?;
    assert!(snapshot.last_refill_at.is_undefined());
    assert!(matches!(
        store.consume_api_key_usage(&snapshot, false).await?,
        ConsumeApiKeyResult::UsageExhausted
    ));
    let persisted = reader
        .get_api_key_by_id("undefined-refill")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the unchanged API Key"))?;
    assert_eq!(persisted.remaining, Some(0.0));
    assert_eq!(persisted.last_refill_at, None);
    let refilled = store
        .write_api_key_usage(
            &snapshot.id,
            ApiKeyUsageWrite::Refill {
                previous: FieldValue::Null,
                remaining: 7.0,
                at: Utc::now(),
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected a null snapshot to match the refill guard"))?;
    assert_eq!(refilled.remaining, Some(7.0));
    Ok(())
}

// Source-derived: a failed nested input changes the runtime ID policy before the outer ID slot.
#[tokio::test]
async fn nested_create_without_id_leaves_an_unforced_uuid_policy() -> AuthResult<()> {
    use better_auth_core::id::IdGeneration;
    use better_auth_core::user_fields::{FieldTransforms, UserFieldTransform};
    use std::sync::{Mutex, OnceLock, Weak};

    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
    config.advanced.database.generate_id = Some(IdGeneration::Uuid);
    let mut store = SeaOrmStore::<BundledSchema>::new(config, database);
    let nested: Arc<OnceLock<Weak<SeaOrmStore<BundledSchema>>>> = Arc::default();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let callback_store = nested.clone();
    let callback_calls = calls.clone();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [(
                    "name".into(),
                    UserFieldConfig {
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new_async(move |value| {
                                let nested = callback_store.clone();
                                let calls = callback_calls.clone();
                                async move {
                                    calls.lock().unwrap().push(value.clone());
                                    if value.strict_equals(&"inner".into()) {
                                        return Err(AuthError::internal("nested input failure"));
                                    }
                                    let error = nested
                                        .get()
                                        .unwrap()
                                        .upgrade()
                                        .unwrap()
                                        .create_api_key_record(
                                            [("name".into(), "inner".into())].into(),
                                        )
                                        .await
                                        .expect_err("nested input must fail before storing a row");
                                    assert_eq!(
                                        error.instrumentation_message(),
                                        "nested input failure"
                                    );
                                    Ok(value)
                                }
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
    store.model_fields = init.into_parts().plugin_fields;
    let store = Arc::new(store);
    assert!(nested.set(Arc::downgrade(&store)).is_ok());
    let at = Utc::now();
    let created = store
        .create_api_key_record(
            [
                ("id".into(), "not-a-uuid".into()),
                ("name".into(), "outer".into()),
                ("referenceId".into(), "owner".into()),
                ("key".into(), "nested-uuid-key".into()),
                ("createdAt".into(), at.into()),
                ("updatedAt".into(), at.into()),
            ]
            .into(),
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected the outer API Key record"))?;
    assert_eq!(created.get("id"), Some(&"not-a-uuid".into()));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[FieldValue::from("outer"), "inner".into()]
    );
    assert_eq!(
        store.get_api_key_record(&"not-a-uuid".into()).await?,
        Some(created)
    );
    assert_eq!(store.count_api_keys_by_reference("owner").await?, 1);
    Ok(())
}
