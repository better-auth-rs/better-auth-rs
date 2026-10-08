use super::*;

#[path = "verification_permissions_tests.rs"]
mod permissions;

#[tokio::test]
async fn cached_json_null_uses_database_fallback_or_rejects_without_consuming_usage() {
    use better_auth_core::store::{MemoryCacheAdapter, SecondaryStorage};

    for fallback_to_database in [false, true] {
        let cache = Arc::new(MemoryCacheAdapter::new());
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(cache.clone()),
            fallback_to_database,
            defer_updates: false,
            ..Default::default()
        });
        let (ctx, _, session) = create_test_context_with_user().await;
        let (id, key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({"name":"null-cache"}),
        )
        .await;
        let config = plugin.resolve_configuration(None).unwrap();
        let hash = ApiKeyPlugin::hash_key(&key);
        let cache_key = format!("api-key:{hash}");
        let id_key = format!("api-key:by-id:{id}");
        let alias = cache.get(&id_key).await.unwrap();
        cache.set(&cache_key, "null", None).await.unwrap();
        let result = plugin
            .verify_api_key(
                &VerifyApiKey {
                    key: &key,
                    config_id: None,
                    permissions: None,
                },
                &ctx,
            )
            .await;
        if fallback_to_database {
            let verified = result.unwrap();
            assert_eq!(verified.id, id);
            assert_eq!(verified.request_count, Some(1.0));
            let restored = storage::get_by_hash(config, &ctx, &hash)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(restored.id, id);
            assert_eq!(restored.request_count, verified.request_count);
            assert_eq!(
                cache.get(&cache_key).await.unwrap(),
                cache.get(&id_key).await.unwrap()
            );
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .request_count,
                verified.request_count
            );
        } else {
            assert!(matches!(
                result,
                Err(ApiKeyVerificationError::Validation(ApiKeyValidationError {
                    code: ApiKeyErrorCode::InvalidApiKey,
                    ..
                }))
            ));
            assert_eq!(
                cache.get(&cache_key).await.unwrap(),
                Some(serde_json::Value::String("null".into()))
            );
            assert_eq!(cache.get(&id_key).await.unwrap(), alias);
            assert!(ctx.database.get_api_key_by_id(&id).await.unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn cached_dynamic_enabled_values_control_verification_before_consuming_usage() {
    use better_auth_core::{
        FieldValue, SchemaValue,
        store::{MemoryCacheAdapter, SecondaryStorage},
    };
    let cache = Arc::new(MemoryCacheAdapter::new());
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache.clone()),
        defer_updates: false,
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    let (ctx, _, session) = create_test_context_with_user().await;
    let (id, key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({"name":"dynamic-enabled"}),
    )
    .await;
    let configuration = plugin.resolve_configuration(None).unwrap();
    let seed = storage::get_by_hash(configuration, &ctx, &ApiKeyPlugin::hash_key(&key))
        .await
        .unwrap()
        .unwrap();
    let cache_key = format!("api-key:{}", seed.key_hash.display_string().unwrap());
    for (value, enabled) in [
        (FieldValue::Undefined, true),
        (FieldValue::Null, true),
        (false.into(), false),
        (true.into(), true),
        (0.0.into(), true),
        (5.25.into(), true),
        ("".into(), true),
        ("0".into(), true),
        (FieldValue::from_json(serde_json::json!({})).unwrap(), true),
        (FieldValue::from_json(serde_json::json!([])).unwrap(), true),
    ] {
        let mut row = seed.clone();
        row.enabled = SchemaValue::from_field(value.clone());
        row.remaining = Some(2.0).into();
        storage::put(cache.as_ref(), &row, false).await.unwrap();
        let before = cache.get(&cache_key).await.unwrap();
        let result = plugin
            .verify_api_key(
                &VerifyApiKey {
                    key: &key,
                    config_id: None,
                    permissions: None,
                },
                &ctx,
            )
            .await;
        if enabled {
            let verified = result.unwrap();
            assert_eq!(verified.enabled.field_value(), value);
            assert_eq!(verified.remaining, Some(1.0));
        } else {
            assert!(matches!(
                result,
                Err(ApiKeyVerificationError::Validation(ApiKeyValidationError {
                    code: ApiKeyErrorCode::KeyDisabled,
                    ..
                }))
            ));
            assert_eq!(
                cache.get(&cache_key).await.unwrap(),
                before,
                "Disabled keys must not consume quota or change cache state"
            );
        }
        let restored = storage::get_by_hash(configuration, &ctx, seed.key_hash.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.enabled.field_value(), value);
        assert_eq!(restored.remaining, Some(if enabled { 1.0 } else { 2.0 }));
        let encoded = cache.get(&cache_key).await.unwrap().unwrap();
        let encoded: serde_json::Value = serde_json::from_str(encoded.as_str().unwrap()).unwrap();
        assert_eq!(encoded.get("enabled"), value.json().unwrap().as_ref());
    }
    assert!(ctx.database.get_api_key_by_id(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn scoped_verification_uses_the_configuration_hashing_and_rejects_other_configs() {
    let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
        config_id: "machines".to_owned(),
        disable_key_hashing: true,
        ..Default::default()
    });
    let (ctx, _, session) = create_test_context_with_user().await;
    let (id, key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "configId": "machines", "name": "machine" }),
    )
    .await;
    let scoped = VerifyApiKey {
        key: &key,
        config_id: Some("machines"),
        permissions: None,
    };
    let verified = plugin.verify_api_key(&scoped, &ctx).await.unwrap();
    assert_eq!(verified.id, id);
    assert_eq!(verified.config_id, "machines");
    let serialized = serde_json::to_value(verified).unwrap();
    assert!(serialized.get("key").is_none());
    assert!(serialized.get("keyHash").is_none());

    for config_id in [None, Some("default"), Some("unknown")] {
        let error = plugin
            .verify_api_key(
                &VerifyApiKey {
                    config_id,
                    ..scoped
                },
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ApiKeyVerificationError::Validation(ApiKeyValidationError {
                code: ApiKeyErrorCode::InvalidApiKey,
                ..
            })
        ));
    }
    assert_eq!(
        ctx.database
            .get_api_key_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .request_count,
        Some(1.0)
    );
}

#[tokio::test]
async fn unscoped_verification_uses_the_issuing_configuration_limits() {
    let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
        config_id: "machines".to_owned(),
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    let (ctx, _, session) = create_test_context_with_user().await;
    let (id, key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "configId": "machines" }),
    )
    .await;
    ctx.database
        .update_api_key(
            &id.clone().into(),
            UpdateApiKey {
                rate_limit_enabled: Some(true),
                rate_limit_max: Some(1.0),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let input = VerifyApiKey {
        key: &key,
        config_id: None,
        permissions: None,
    };
    for _ in 0..3 {
        assert_eq!(plugin.verify_api_key(&input, &ctx).await.unwrap().id, id);
    }
    let error = plugin
        .verify_api_key(
            &VerifyApiKey {
                config_id: Some("default"),
                ..input
            },
            &ctx,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ApiKeyVerificationError::Validation(ApiKeyValidationError {
            code: ApiKeyErrorCode::InvalidApiKey,
            ..
        })
    ));
    assert_eq!(
        ctx.database
            .get_api_key_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .request_count,
        Some(0.0)
    );
}

#[tokio::test]
async fn permissions_failure_preserves_usage_and_rate_limit_reports_retry_time() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _, session) = create_test_context_with_user().await;
    let (id, key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({}),
        UpdateApiKey {
            remaining: Some(3.0),
            permissions: Some(serde_json::json!({ "nodes": ["read"] }).to_string()),
            rate_limit_max: Some(1.0),
            rate_limit_time_window: Some(60_000.0),
            ..Default::default()
        },
    )
    .await;
    let denied = serde_json::json!({ "nodes": ["delete"] });
    let allowed = serde_json::json!({ "nodes": ["read"] });
    let input = VerifyApiKey {
        key: &key,
        config_id: None,
        permissions: Some(&denied),
    };
    let error = plugin.verify_api_key(&input, &ctx).await.unwrap_err();
    assert!(matches!(
        error,
        ApiKeyVerificationError::Validation(ApiKeyValidationError {
            code: ApiKeyErrorCode::KeyNotFound,
            ..
        })
    ));
    assert_eq!(
        ctx.database
            .get_api_key_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        Some(3.0)
    );
    let input = VerifyApiKey {
        permissions: Some(&allowed),
        ..input
    };
    assert_eq!(
        plugin.verify_api_key(&input, &ctx).await.unwrap().remaining,
        Some(2.0)
    );
    let error = plugin.verify_api_key(&input, &ctx).await.unwrap_err();
    let ApiKeyVerificationError::Validation(error) = error else {
        panic!("Expected rate limit rejection")
    };
    assert_eq!(error.code, ApiKeyErrorCode::RateLimited);
    let retry = error.details.unwrap().try_again_in;
    assert!(retry > 0.0 && retry <= 60_000.0);
    assert_eq!(
        ctx.database
            .get_api_key_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        Some(1.0)
    );
}

#[tokio::test]
async fn session_header_selects_a_named_config_without_a_default() {
    let plugin = ApiKeyPlugin::builder()
        .config_id("machines".to_owned())
        .api_key_headers(vec![
            "x-machine-key".to_owned(),
            "x-alternate-key".to_owned(),
        ])
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, user, session) = create_test_context_with_user().await;
    let (_, key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "configId": "machines" }),
    )
    .await;
    let mut request = create_auth_request(HttpMethod::Get, "/get-session", None, None, None);
    request
        .headers
        .insert("x-alternate-key".to_owned(), key.clone());
    let result = plugin
        .before_request(&request, &ctx)
        .await
        .unwrap()
        .unwrap();
    let BeforeRequestAction::Respond(response) = result else {
        panic!("Expected virtual session")
    };
    assert_eq!(response.status, 200);
    let body = json_body(&response);
    assert_eq!(body["session"]["token"], key);
    assert_eq!(body["session"]["userId"], user.id.typed().unwrap().as_str());
    assert_eq!(body["user"]["emailVerified"], false);
    assert!(body["session"]["createdAt"].is_string());
    assert!(body["session"]["expiresAt"].is_string());
}

#[tokio::test]
async fn session_header_cannot_authenticate_a_different_configuration() {
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build()
        .configuration(ApiKeyConfig {
            config_id: "machines".to_owned(),
            api_key_headers: vec!["x-machine-key".to_owned()],
            enable_session_for_api_keys: true,
            ..Default::default()
        });
    let (ctx, _, session) = create_test_context_with_user().await;
    let (id, key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "configId": "machines" }),
    )
    .await;
    let mut request = create_auth_request(HttpMethod::Get, "/get-session", None, None, None);
    request.headers.insert("x-api-key".to_owned(), key);
    let result = plugin
        .before_request(&request, &ctx)
        .await
        .unwrap()
        .unwrap();
    let BeforeRequestAction::Respond(response) = result else {
        panic!("Expected credential rejection")
    };
    assert_eq!(response.status, 401);
    assert_eq!(json_body(&response)["code"], "INVALID_API_KEY");
    assert_eq!(
        ctx.database
            .get_api_key_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .request_count,
        Some(0.0)
    );
}

#[tokio::test]
async fn organization_key_verifies_without_emulating_a_user_session() {
    let plugin = ApiKeyPlugin::builder()
        .references(ApiKeyReferences::Organization)
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, user, _) = create_test_context_with_user().await;
    let (key, key_hash) = ApiKeyPlugin::generate_key(&ApiKeyConfig::default(), None);
    let start = better_auth_core::ApiKeyStart::prefix(
        &key,
        ApiKeyConfig::default().starting_characters_length,
    );
    ctx.database
        .create_api_key(better_auth_core::CreateApiKey {
            additional_fields: Default::default(),
            // A colliding user ID must not turn an organization key into a user session.
            reference_id: user.id.typed().unwrap().clone(),
            config_id: "default".to_owned(),
            key_hash,
            start: Some(start),
            enabled: true.into(),
            name: None.into(),
            prefix: None,
            expires_at: None,
            remaining: None,
            rate_limit_enabled: false,
            rate_limit_time_window: None,
            rate_limit_max: None,
            refill_interval: None,
            refill_amount: None,
            permissions: None,
            metadata: None,
        })
        .await
        .unwrap();
    plugin
        .verify_api_key(
            &VerifyApiKey {
                key: &key,
                config_id: None,
                permissions: None,
            },
            &ctx,
        )
        .await
        .unwrap();
    let mut request = create_auth_request(HttpMethod::Get, "/get-session", None, None, None);
    request.headers.insert("x-api-key".to_owned(), key);
    let result = plugin
        .before_request(&request, &ctx)
        .await
        .unwrap()
        .unwrap();
    let BeforeRequestAction::Respond(response) = result else {
        panic!("Expected organization rejection")
    };
    assert_eq!(response.status, 401);
    assert_eq!(
        json_body(&response)["code"],
        "INVALID_REFERENCE_ID_FROM_API_KEY"
    );
}

#[tokio::test]
async fn api_key_initialization_rejects_ambiguous_configurations() {
    let (ctx, _, _) = create_test_context_with_user().await;
    for config_id in ["", "default"] {
        let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
            config_id: config_id.to_owned(),
            ..Default::default()
        });
        let mut init =
            better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
        assert!(matches!(
            plugin.on_init(&mut init).await,
            Err(AuthError::Config(_))
        ));
    }
}

#[tokio::test]
async fn verification_preserves_database_failures() {
    let connection = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    connection.clone().close().await.unwrap();
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let database = Arc::new(better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
        config.clone(),
        connection,
    ));
    let ctx = AuthContext::new(config, database);
    let plugin = ApiKeyPlugin::builder().build();
    let error = plugin
        .verify_api_key(
            &VerifyApiKey {
                key: "not-looked-up",
                config_id: None,
                permissions: None,
            },
            &ctx,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ApiKeyVerificationError::Internal(AuthError::Database(_))
    ));
}

#[tokio::test]
async fn verified_session_authenticates_a_protected_plugin_route_without_a_database_session() {
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, user, session) = create_test_context_with_user().await;
    let (id, key) =
        create_key_and_get_raw(&plugin, &ctx, &session.token, serde_json::json!({})).await;
    let mut request = create_auth_request(HttpMethod::Get, "/api-key/list", None, None, None);
    request.headers.insert("x-api-key".to_owned(), key.clone());
    let action = plugin
        .before_request(&request, &ctx)
        .await
        .unwrap()
        .unwrap();
    let BeforeRequestAction::InjectSession { session } = action else {
        panic!("Expected virtual session")
    };
    assert_eq!(session.token, key);
    request.set_virtual_session(*session);
    let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(json_body(&response)["apiKeys"][0]["id"], id);
    assert_eq!(
        ctx.database
            .get_user_sessions(user.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn secondary_usage_retains_dynamic_counter_arithmetic_and_strict_rate_limit_flags() {
    use better_auth_core::{FieldValue, SchemaValue, store::MemoryCacheAdapter};
    let cache = Arc::new(MemoryCacheAdapter::new());
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache.clone()),
        defer_updates: false,
        ..Default::default()
    });
    let (ctx, _, session) = create_test_context_with_user().await;
    let (_, raw_key) =
        create_key_and_get_raw(&plugin, &ctx, &session.token, serde_json::json!({})).await;
    let config = plugin.resolve_configuration(None).unwrap();
    let seed = storage::get_by_hash(config, &ctx, &ApiKeyPlugin::hash_key(&raw_key))
        .await
        .unwrap()
        .unwrap();
    for (flag, limited) in [
        (FieldValue::Bool(false), false),
        (FieldValue::Null, true),
        (FieldValue::Undefined, true),
        (0.0.into(), true),
    ] {
        let mut key = seed.clone();
        key.rate_limit_enabled = SchemaValue::from_field(flag);
        key.remaining = SchemaValue::from_field("2".into());
        key.request_count = SchemaValue::from_field("1".into());
        key.rate_limit_max = SchemaValue::from_field("0".into());
        key.rate_limit_time_window = Some(1_000_000.0).into();
        key.last_request = Some(chrono::Utc::now().into()).into();
        storage::put(cache.as_ref(), &key, false).await.unwrap();
        let input = VerifyApiKey {
            key: &raw_key,
            config_id: None,
            permissions: None,
        };
        let result = plugin.verify_api_key(&input, &ctx).await;
        if limited {
            assert!(matches!(
                result,
                Err(ApiKeyVerificationError::Validation(ApiKeyValidationError {
                    code: ApiKeyErrorCode::RateLimited,
                    ..
                }))
            ));
            let stored = storage::get_by_hash(config, &ctx, seed.key_hash.typed().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.remaining.field_value(), "2".into());
        } else {
            let verified = result.unwrap();
            assert_eq!(verified.remaining, Some(1.0));
            assert_eq!(verified.request_count.field_value(), "1".into());
        }
    }
    let mut key = seed;
    key.rate_limit_enabled = SchemaValue::from_field(FieldValue::Null);
    key.remaining = SchemaValue::from_field("2".into());
    key.request_count = SchemaValue::from_field("1".into());
    key.rate_limit_max = SchemaValue::from_field("3".into());
    key.rate_limit_time_window = Some(1_000_000.0).into();
    key.last_request = Some(chrono::Utc::now().into()).into();
    storage::put(cache.as_ref(), &key, false).await.unwrap();
    let verified = plugin
        .verify_api_key(
            &VerifyApiKey {
                key: &raw_key,
                config_id: None,
                permissions: None,
            },
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(verified.remaining, Some(1.0));
    assert_eq!(verified.request_count.field_value(), "11".into());
}
