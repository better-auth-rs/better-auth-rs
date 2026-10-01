//! Public Rust API key operations preserve the plugin's authorization and update semantics.
#![allow(
    clippy::panic_in_result_fn,
    reason = "Test assertions fail the test; Result propagates setup and API errors."
)]

use std::collections::HashMap;

use better_auth::plugins::api_key::{
    ApiKeyConfig, ApiKeyErrorCode, ApiKeyPlugin, ApiKeyVerificationError,
};
use better_auth::prelude::CreateUser;
use better_auth::server_api::{CreateKeyOptions, FieldUpdate, UpdateKeyOptions, VerifyKeyOptions};
use better_auth::{AuthConfig, AuthError, BetterAuth};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::json;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn build_auth(
    plugin: Option<ApiKeyPlugin>,
) -> Result<(BetterAuth<TestSchema>, String), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long");
    let store = SeaOrmStore::<TestSchema>::new(config.clone(), database);
    let mut builder = BetterAuth::<TestSchema>::new(config).store(store);
    if let Some(plugin) = plugin {
        builder = builder.plugin(plugin);
    }
    let auth = builder.build().await?;
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("worker@example.com"))
        .await?;
    Ok((auth, user.id.typed().unwrap().clone()))
}

fn required(actions: Vec<String>) -> VerifyKeyOptions {
    VerifyKeyOptions {
        config_id: Some("machine".into()),
        permissions: Some(HashMap::from([("nodes".into(), actions)])),
    }
}

#[tokio::test]
async fn zero_key_length_never_authenticates_the_public_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let zero = ApiKeyConfig {
        key_length: 0,
        prefix: Some("node_".into()),
        ..Default::default()
    };
    let named = ApiKeyConfig {
        config_id: "machine".into(),
        ..zero.clone()
    };
    for (plugin, config_id) in [
        (
            ApiKeyPlugin::builder()
                .key_length(0)
                .prefix("node_".into())
                .build(),
            None,
        ),
        (ApiKeyPlugin::with_config(zero), None),
        (
            ApiKeyPlugin::builder().build().configuration(named),
            Some("machine".to_string()),
        ),
    ] {
        let (auth, user_id) = build_auth(Some(plugin)).await?;
        let keys = auth.api_keys()?;
        let issued = keys
            .create(
                &user_id,
                CreateKeyOptions {
                    config_id: config_id.clone(),
                    rate_limit_enabled: Some(false),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(issued.key.len(), "node_".len() + 64);
        let options = VerifyKeyOptions {
            config_id: config_id.clone(),
            ..Default::default()
        };
        let verified = keys.verify(&issued.key, options).await?;
        assert_eq!(verified.reference_id, user_id);
        assert!(matches!(
            keys.verify(
                "node_",
                VerifyKeyOptions {
                    config_id,
                    ..Default::default()
                }
            )
            .await,
            Err(ApiKeyVerificationError::Validation(_))
        ));
    }
    Ok(())
}

// Rust-specific surface: the facade uses the registered plugin and its initialized context.
#[tokio::test]
async fn issue_verify_and_revoke_machine_credential() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
        config_id: "machine".into(),
        prefix: Some("node_".into()),
        ..Default::default()
    });
    let (auth, user_id) = build_auth(Some(plugin)).await?;
    let api_keys = auth.api_keys()?;
    let issued = api_keys
        .create(
            &user_id,
            CreateKeyOptions {
                config_id: Some("machine".into()),
                remaining: Some(3.5),
                rate_limit_enabled: Some(false),
                permissions: Some(HashMap::from([(
                    "nodes".into(),
                    vec!["read".into(), "heartbeat".into()],
                )])),
                ..Default::default()
            },
        )
        .await?;
    assert!(issued.key.starts_with("node_"));
    assert_eq!(issued.api_key.reference_id, user_id);

    let denied = api_keys
        .verify(
            &issued.key,
            required(vec!["heartbeat".into(), "delete".into()]),
        )
        .await;
    assert!(
        matches!(denied, Err(ApiKeyVerificationError::Validation(error)) if error.code == ApiKeyErrorCode::KeyNotFound)
    );

    let verified = api_keys
        .verify(
            &issued.key,
            required(vec!["read".into(), "heartbeat".into()]),
        )
        .await?;
    assert_eq!(verified.remaining, Some(2.5));
    assert_eq!(verified.config_id, "machine");

    let verified = api_keys
        .verify(&issued.key, required(vec!["heartbeat".into()]))
        .await?;
    assert_eq!(verified.remaining, Some(1.5));

    let revoked = api_keys
        .update(
            &user_id,
            issued.api_key.id.typed().unwrap(),
            UpdateKeyOptions {
                config_id: Some("machine".into()),
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert!(!revoked.enabled);
    let rejected = api_keys
        .verify(&issued.key, required(vec!["heartbeat".into()]))
        .await;
    assert!(
        matches!(rejected, Err(ApiKeyVerificationError::Validation(error)) if error.code == ApiKeyErrorCode::KeyDisabled)
    );
    Ok(())
}

// Rust-specific surface: explicit update states map to upstream omission, value, and null semantics.
#[tokio::test]
async fn updates_preserve_replace_and_clear_nullable_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let plugin = ApiKeyPlugin::builder().enable_metadata(true).build();
    let (auth, user_id) = build_auth(Some(plugin)).await?;
    let api_keys = auth.api_keys()?;
    let issued = api_keys
        .create(
            &user_id,
            CreateKeyOptions {
                expires_in: Some(86400.25),
                permissions: Some(HashMap::from([("nodes".into(), vec!["read".into()])])),
                metadata: Some(json!({"region": "one"})),
                ..Default::default()
            },
        )
        .await?;

    let preserved = api_keys
        .update(
            &user_id,
            issued.api_key.id.typed().unwrap(),
            UpdateKeyOptions {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(preserved.expires_at, issued.api_key.expires_at);
    assert_eq!(preserved.permissions, issued.api_key.permissions);
    assert_eq!(preserved.metadata, issued.api_key.metadata);

    let replaced = api_keys
        .update(
            &user_id,
            issued.api_key.id.typed().unwrap(),
            UpdateKeyOptions {
                expires_in: FieldUpdate::Set(172800.25),
                permissions: FieldUpdate::Set(HashMap::from([(
                    "nodes".into(),
                    vec!["heartbeat".into()],
                )])),
                metadata: FieldUpdate::Set(json!({"region": "two"})),
                remaining: Some(4.5),
                ..Default::default()
            },
        )
        .await?;
    assert_ne!(replaced.expires_at, preserved.expires_at);
    assert_eq!(replaced.permissions, Some(json!({"nodes": ["heartbeat"]})));
    assert_eq!(replaced.metadata, Some(json!({"region": "two"})));
    assert_eq!(replaced.remaining, Some(4.5));

    let cleared = api_keys
        .update(
            &user_id,
            issued.api_key.id.typed().unwrap(),
            UpdateKeyOptions {
                expires_in: FieldUpdate::Clear,
                permissions: FieldUpdate::Clear,
                metadata: FieldUpdate::Clear,
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(cleared.expires_at, None);
    assert_eq!(cleared.permissions, Some(serde_json::Value::Null));
    assert_eq!(cleared.metadata, Some(serde_json::Value::Null));
    Ok(())
}

#[tokio::test]
async fn missing_api_key_plugin_is_a_configuration_error() -> Result<(), Box<dyn std::error::Error>>
{
    let (auth, _) = build_auth(None).await?;
    assert!(
        matches!(auth.api_keys(), Err(AuthError::Config(message)) if message == "ApiKeyPlugin is not registered")
    );
    Ok(())
}
