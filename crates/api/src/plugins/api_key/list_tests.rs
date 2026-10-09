use super::*;
use serde_json::json;

async fn check_list_default_limit(ctx: &AuthContext<impl better_auth_core::AuthSchema>) {
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig::default());
    let mut keys = Vec::new();
    for (index, name) in ["D", "A", "E", "C", "B"].into_iter().enumerate() {
        let key = ctx
            .database
            .create_api_key(better_auth_core::CreateApiKey {
                additional_fields: Default::default(),
                reference_id: "list-owner".into(),
                config_id: "default".into(),
                name: Some(name.into()).into(),
                key_hash: format!("stored-{index}"),
                prefix: None,
                start: None,
                expires_at: None,
                remaining: None,
                enabled: true.into(),
                rate_limit_enabled: false,
                rate_limit_time_window: None,
                rate_limit_max: None,
                refill_interval: None,
                refill_amount: None,
                permissions: None.into(),
                metadata: None,
            })
            .await
            .unwrap();
        keys.push(key);
    }
    assert_eq!(
        ctx.database
            .count_api_keys_by_reference("list-owner")
            .await
            .unwrap(),
        5
    );
    let query = types::ListKeysQuery {
        sort_by: Some("name".into()),
        sort_direction: Some("desc".into()),
        limit: Some(1),
        offset: Some(1),
        ..Default::default()
    };
    let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
        .await
        .unwrap();
    assert_eq!(result.total, 2);
    assert_eq!(
        result
            .api_keys
            .iter()
            .map(|key| key.name.typed().unwrap().as_deref())
            .collect::<Vec<_>>(),
        [Some("D")]
    );
    assert_eq!((result.limit, result.offset), (Some(1), Some(1)));

    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    for key in &keys {
        storage::put(cache.as_ref(), key, false).await.unwrap();
    }
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache),
        ..Default::default()
    });
    let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
        .await
        .unwrap();
    assert_eq!(result.total, 5);
    assert_eq!(
        result
            .api_keys
            .iter()
            .map(|key| key.name.typed().unwrap().as_deref())
            .collect::<Vec<_>>(),
        [Some("D")]
    );

    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache),
        fallback_to_database: true,
        ..Default::default()
    });
    for _ in 0..2 {
        let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
            .await
            .unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(
            result
                .api_keys
                .iter()
                .map(|key| key.name.typed().unwrap().as_deref())
                .collect::<Vec<_>>(),
            [Some("D")]
        );
    }
    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    for ((mut key, name), remaining) in keys
        .iter()
        .cloned()
        .zip([
            Some("\u{e000}"),
            Some("\u{10000}"),
            Some("a"),
            None,
            Some("A"),
        ])
        .zip([Some(0.0), Some(-0.0), Some(1.0), Some(-1.0), None])
    {
        key.name = name.map(str::to_owned).into();
        key.remaining = remaining.into();
        storage::put(cache.as_ref(), &key, false).await.unwrap();
    }
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache),
        ..Default::default()
    });
    for direction in ["asc", "desc"] {
        let query = types::ListKeysQuery {
            sort_by: Some("name".into()),
            sort_direction: Some(direction.into()),
            ..Default::default()
        };
        let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
            .await
            .unwrap();
        let mut expected = [
            None,
            Some("A"),
            Some("a"),
            Some("\u{10000}"),
            Some("\u{e000}"),
        ];
        if direction == "desc" {
            expected.reverse();
        }
        assert_eq!(
            result
                .api_keys
                .iter()
                .map(|key| key.name.typed().unwrap().as_deref())
                .collect::<Vec<_>>(),
            expected
        );
    }
    for (direction, expected) in [
        (
            "asc",
            [
                Some("A"),
                None,
                Some("\u{e000}"),
                Some("\u{10000}"),
                Some("a"),
            ],
        ),
        (
            "desc",
            [
                Some("a"),
                Some("\u{e000}"),
                Some("\u{10000}"),
                None,
                Some("A"),
            ],
        ),
    ] {
        let query = types::ListKeysQuery {
            sort_by: Some("remaining".into()),
            sort_direction: Some(direction.into()),
            ..Default::default()
        };
        let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
            .await
            .unwrap();
        assert_eq!(
            result
                .api_keys
                .iter()
                .map(|key| key.name.typed().unwrap().as_deref())
                .collect::<Vec<_>>(),
            expected
        );
    }
    for (names, ascending, descending) in [
        (vec![Some(json!(42))], vec![0], vec![0]),
        (
            vec![Some(json!(10)), Some(json!(2))],
            vec![1, 0],
            vec![0, 1],
        ),
        (
            vec![Some(json!(2)), Some(json!("2")), Some(json!("10"))],
            vec![0, 2, 1],
            vec![0, 1, 2],
        ),
        (
            vec![Some(json!(2)), Some(json!("word")), Some(json!(1))],
            vec![0, 1, 2],
            vec![0, 1, 2],
        ),
        (
            vec![
                Some(json!(10)),
                Some(json!("2")),
                Some(json!(2)),
                Some(serde_json::Value::Null),
                None,
                Some(serde_json::Value::Null),
                Some(json!(10)),
            ],
            vec![3, 4, 5, 1, 2, 0, 6],
            vec![0, 6, 1, 2, 3, 4, 5],
        ),
        (
            vec![
                Some(json!({})),
                Some(json!({"valueOf": null})),
                Some(json!({"nested": {"toString": null}})),
                Some(json!({"__proto__": {"toString": null}})),
            ],
            vec![0, 1, 2, 3],
            vec![0, 1, 2, 3],
        ),
        (
            vec![
                Some(json!([{"valueOf": null}])),
                Some(json!("[object Object]")),
            ],
            vec![0, 1],
            vec![0, 1],
        ),
        (vec![Some(json!({"toString": null}))], vec![0], vec![0]),
        (
            vec![Some(json!({"toString": null})), Some(json!(null))],
            vec![1, 0],
            vec![0, 1],
        ),
        (
            vec![Some(json!({"toString": null})), None],
            vec![1, 0],
            vec![0, 1],
        ),
    ] {
        let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
        for (index, name) in names.iter().enumerate() {
            let mut key = keys[0].clone();
            key.id = format!("dynamic-{index}").into();
            key.key_hash = format!("dynamic-secret-{index}").into();
            key.name = better_auth_core::SchemaValue::from_json(name.clone()).unwrap();
            storage::put(cache.as_ref(), &key, false).await.unwrap();
        }
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(cache),
            ..Default::default()
        });
        for (direction, expected) in [("asc", ascending), ("desc", descending)] {
            let result = handlers::list_keys_core(
                "list-owner",
                &types::ListKeysQuery {
                    sort_by: Some("name".into()),
                    sort_direction: Some(direction.into()),
                    ..Default::default()
                },
                &plugin,
                ctx,
            )
            .await
            .unwrap();
            assert_eq!(result.total, names.len());
            assert_eq!(
                result
                    .api_keys
                    .iter()
                    .map(|key| (key.id.typed().unwrap().clone(), key.name.json().unwrap()))
                    .collect::<Vec<_>>(),
                expected
                    .into_iter()
                    .map(|index| (format!("dynamic-{index}"), names[index].clone()))
                    .collect::<Vec<_>>()
            );
        }
    }
    for field in [
        "createdAt",
        "updatedAt",
        "expiresAt",
        "lastRequest",
        "lastRefillAt",
    ] {
        let dates = [
            "2099-10-02T00:00:00.000Z",
            "invalid-date",
            "2099-10-01T00:00:00.000Z",
        ];
        let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
        for (index, date) in dates.iter().enumerate() {
            let mut key = keys[0].clone();
            key.id = format!("date-{index}").into();
            key.key_hash = format!("date-secret-{index}").into();
            storage::put(cache.as_ref(), &key, false).await.unwrap();
            let mut row = serde_json::to_value(&key).unwrap();
            row[field] = json!(date);
            better_auth_core::store::SecondaryStorage::set(
                cache.as_ref(),
                &format!("api-key:by-id:date-{index}"),
                &row.to_string(),
                None,
            )
            .await
            .unwrap();
        }
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(cache),
            ..Default::default()
        });
        for direction in ["asc", "desc"] {
            let result = handlers::list_keys_core(
                "list-owner",
                &types::ListKeysQuery {
                    sort_by: Some(field.into()),
                    sort_direction: Some(direction.into()),
                    ..Default::default()
                },
                &plugin,
                ctx,
            )
            .await
            .unwrap();
            assert_eq!(result.total, dates.len());
            assert_eq!(
                result
                    .api_keys
                    .iter()
                    .map(|key| {
                        (
                            key.id.typed().unwrap().clone(),
                            serde_json::to_value(key).unwrap()[field].clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![
                    ("date-0".into(), json!(dates[0])),
                    ("date-1".into(), serde_json::Value::Null),
                    ("date-2".into(), json!(dates[2])),
                ]
            );
        }
    }
    check_cached_object_conversion_errors(ctx, &keys[0]).await;
}

async fn check_cached_object_conversion_errors(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    template: &better_auth_core::ApiKey,
) {
    use better_auth_core::store::SecondaryStorage;

    for value in [
        json!({"toString": null}),
        json!({"toString": false}),
        json!({"toString": 0}),
        json!({"toString": ""}),
        json!({"toString": []}),
        json!({"toString": {}}),
        json!([{"toString": null}]),
    ] {
        for names in [[value.clone(), json!("x")], [json!("x"), value]] {
            let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
            for (index, name) in names.iter().enumerate() {
                let mut key = template.clone();
                key.id = format!("object-{index}").into();
                key.key_hash = format!("object-secret-{index}").into();
                key.name = better_auth_core::SchemaValue::from_json(Some(name.clone())).unwrap();
                storage::put(cache.as_ref(), &key, false).await.unwrap();
            }
            let mut stored = Vec::new();
            for key in [
                "api-key:object-secret-0",
                "api-key:by-id:object-0",
                "api-key:object-secret-1",
                "api-key:by-id:object-1",
                "api-key:by-ref:list-owner",
            ] {
                let value = SecondaryStorage::get(cache.as_ref(), key).await.unwrap();
                assert!(value.is_some());
                stored.push((key, value));
            }
            let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
                storage: ApiKeyStorage::SecondaryStorage,
                custom_storage: Some(cache.clone()),
                ..Default::default()
            });
            for direction in ["asc", "desc"] {
                let error = handlers::list_keys_core(
                    "list-owner",
                    &types::ListKeysQuery {
                        sort_by: Some("name".into()),
                        sort_direction: Some(direction.into()),
                        ..Default::default()
                    },
                    &plugin,
                    ctx,
                )
                .await
                .unwrap_err();
                assert!(matches!(error, AuthError::TypeError(message)
                    if message == "No default value"));
                for (key, expected) in &stored {
                    assert_eq!(
                        SecondaryStorage::get(cache.as_ref(), key).await.unwrap(),
                        *expected
                    );
                }
            }
            let unsorted = handlers::list_keys_core(
                "list-owner",
                &types::ListKeysQuery::default(),
                &plugin,
                ctx,
            )
            .await
            .unwrap();
            assert_eq!(unsorted.total, names.len());
            assert_eq!(
                unsorted
                    .api_keys
                    .iter()
                    .map(|key| (key.id.typed().unwrap().clone(), key.name.json().unwrap()))
                    .collect::<Vec<_>>(),
                names
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| (format!("object-{index}"), Some(name)))
                    .collect::<Vec<_>>()
            );
            for (key, expected) in &stored {
                assert_eq!(
                    SecondaryStorage::get(cache.as_ref(), key).await.unwrap(),
                    *expected
                );
            }
        }
    }
}

#[tokio::test]
async fn list_memory_applies_adapter_default_before_public_pagination() {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.advanced.database.default_find_many_limit = Some(2.0);
    let config = Arc::new(config);
    let store = Arc::new(better_auth_core::store::EphemeralStore::new(config.clone()));
    let ctx = AuthContext::new(config, store);
    check_list_default_limit(&ctx).await;
}

#[tokio::test]
async fn list_sqlite_applies_adapter_default_before_public_pagination() {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.advanced.database.default_find_many_limit = Some(2.0);
    let config = Arc::new(config);
    let db = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let store = Arc::new(better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
        config.clone(),
        db,
    ));
    let ctx = AuthContext::new(config, store);
    check_list_default_limit(&ctx).await;
}
