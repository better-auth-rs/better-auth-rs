use better_auth::{
    __private_core::{
        AuthError, AuthResult, CreateUser, FieldValue,
        store::{ApiKeyStore, EphemeralStore, MemoryCacheAdapter, SecondaryStorage, UserStore},
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    BetterAuth,
    plugins::api_key::{
        ApiKeyConfig, ApiKeyErrorCode, ApiKeyPlugin, ApiKeyStorage, ApiKeyValidationError,
        ApiKeyVerificationError,
    },
    server_api::{CreateKeyOptions, VerifyKeyOptions},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn enabled_policies_reach_database_and_fallback_authentication_without_cache_reprojection()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for mode in ["database", "secondary", "fallback"] {
        for projected in [
            FieldValue::Undefined,
            FieldValue::Null,
            FieldValue::Bool(false),
            0.0.into(),
            5.25.into(),
            "0".into(),
        ] {
            let config = super::contract::config();
            let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
            let cache = Arc::new(MemoryCacheAdapter::new());
            let output_count = Arc::new(AtomicUsize::new(0));
            let count = output_count.clone();
            let output = projected.clone();
            let fields = UserConfig {
                additional_fields: Some(
                    [(
                        "enabled".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            required: Some(false),
                            field_name: Some("stored_enabled".into()),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(|value| {
                                    assert_eq!(value, FieldValue::Bool(true));
                                    Ok(5.25.into())
                                })),
                                output: Some(UserFieldTransform::new(move |value| {
                                    assert_eq!(value, FieldValue::Number(5.25));
                                    count.fetch_add(1, Ordering::SeqCst);
                                    Ok(output.clone())
                                })),
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            };
            let auth = BetterAuth::new(config)
                .store_arc(raw.clone())
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    storage: if mode == "database" {
                        ApiKeyStorage::Database
                    } else {
                        ApiKeyStorage::SecondaryStorage
                    },
                    custom_storage: Some(cache.clone()),
                    fallback_to_database: mode == "fallback",
                    defer_updates: false,
                    ..Default::default()
                }))
                .plugin(super::contract::Fields(fields))
                .build()
                .await?;
            let owner = raw
                .create_user(
                    CreateUser::new()
                        .with_name("Enabled owner")
                        .with_email("owner@enabled.test"),
                )
                .await?;
            let created = auth
                .api_keys()?
                .create(
                    owner.id.typed()?,
                    CreateKeyOptions {
                        remaining: Some(2.0),
                        ..Default::default()
                    },
                )
                .await?;
            let expected = if mode == "secondary" {
                FieldValue::Bool(true)
            } else {
                projected
            };
            assert_eq!(created.api_key.enabled.field_value(), expected);
            let before_calls = output_count.load(Ordering::SeqCst);
            assert_eq!(before_calls, usize::from(mode != "secondary"));
            let cache_key = format!("api-key:by-id:{}", created.api_key.id.display_string()?);
            let cached = cache.get(&cache_key).await?;
            if mode != "database" {
                let cached: serde_json::Value = serde_json::from_str(
                    cached
                        .as_ref()
                        .and_then(serde_json::Value::as_str)
                        .ok_or("Missing cached key")?,
                )?;
                assert_eq!(cached.get("enabled"), expected.json()?.as_ref());
                assert!(cached.get("stored_enabled").is_none());
            }
            let result = auth
                .api_keys()?
                .verify(&created.key, VerifyKeyOptions::default())
                .await;
            let enabled = !created
                .api_key
                .enabled
                .field_value()
                .strict_equals(&false.into());
            if enabled {
                let verified = result?;
                assert_eq!(verified.enabled.field_value(), expected);
                assert_eq!(verified.remaining, Some(1.0));
            } else {
                assert!(matches!(
                    result,
                    Err(ApiKeyVerificationError::Validation(ApiKeyValidationError {
                        code: ApiKeyErrorCode::KeyDisabled,
                        ..
                    }))
                ));
                assert_eq!(cache.get(&cache_key).await?, cached);
                assert_eq!(
                    output_count.load(Ordering::SeqCst) - before_calls,
                    usize::from(mode == "database")
                );
            }
            let stored = raw.get_api_key_by_id(created.api_key.id.typed()?).await?;
            if mode == "secondary" {
                assert!(stored.is_none());
                assert_eq!(output_count.load(Ordering::SeqCst), 0);
            } else {
                let stored = stored.ok_or("Missing stored enabled key")?;
                assert_eq!(stored.enabled.field_value(), FieldValue::Number(5.25));
                assert_eq!(stored.remaining, Some(if enabled { 1.0 } else { 2.0 }));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn enabled_declarations_reject_native_and_physical_column_collisions() -> AuthResult<()> {
    for (enabled_column, other_name, other_column) in [
        ("key", "marker", "stored_marker"),
        ("stored_enabled", "marker", "stored_enabled"),
        ("stored_enabled", "stored_enabled", "stored_marker"),
        ("stored_enabled", "name", "stored_enabled"),
    ] {
        let result = BetterAuth::new(super::contract::config())
            .store(EphemeralStore::default())
            .plugin(super::contract::Fields(UserConfig {
                additional_fields: Some(
                    [
                        (
                            "enabled".into(),
                            UserFieldConfig {
                                field_name: Some(enabled_column.into()),
                                ..Default::default()
                            },
                        ),
                        (
                            other_name.into(),
                            UserFieldConfig {
                                field_name: Some(other_column.into()),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            }))
            .build()
            .await;
        assert!(matches!(result, Err(AuthError::Config(_))));
    }
    Ok(())
}
