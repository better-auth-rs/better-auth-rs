use super::*;
use better_auth::plugins::api_key::{ApiKeyDefaultPermissions, ApiKeyGenerator, ApiKeyPermissions};
use better_auth::server_api::{CreateKeyOptions, VerifyKeyOptions};

#[derive(Default)]
struct Callbacks(Mutex<Vec<&'static str>>);

fn object(value: &FieldValue) -> AuthResult<&FieldObject> {
    value
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected permission contract object"))
}

fn permissions(actions: &[&str]) -> ApiKeyPermissions {
    HashMap::from([(
        "nodes".into(),
        actions.iter().map(|action| (*action).into()).collect(),
    )])
}

#[async_trait]
impl ApiKeyGenerator for Callbacks {
    async fn generate(&self, _: usize, _: Option<&str>) -> AuthResult<String> {
        lock(&self.0)?.push("generator");
        Ok("x".repeat(64))
    }
}

#[async_trait]
impl ApiKeyDefaultPermissions for Callbacks {
    async fn permissions(
        &self,
        reference_id: &FieldValue,
        endpoint: ApiKeyEndpoint<'_>,
    ) -> AuthResult<ApiKeyPermissions> {
        lock(&self.0)?.push("permissions");
        assert_eq!(reference_id, &FieldValue::from("owner"));
        let captured = endpoint.body.model_property("permissions")?;
        object(&captured)?.set("nodes", json!(["read", "write"]).into())?;
        let _ =
            object(endpoint.body)?.set("permissions", json!({"nodes": ["replacement"]}).into())?;
        Ok(permissions(&["default"]))
    }
}

#[async_trait]
impl ApiKeyValidator for Callbacks {
    async fn validate(&self, key: &str, endpoint: ApiKeyEndpoint<'_>) -> AuthResult<bool> {
        lock(&self.0)?.push("validator");
        assert_eq!(key, "x".repeat(64));
        let scoped = !endpoint.body.model_property("configId")?.is_undefined();
        let captured = endpoint.body.model_property("permissions")?;
        object(&captured)?.set(
            "nodes",
            json!([if scoped { "read" } else { "write" }]).into(),
        )?;
        object(endpoint.body)?.set(
            "permissions",
            json!({"nodes": [if scoped { "write" } else { "read" }]}).into(),
        )?;
        Ok(true)
    }
}

#[tokio::test]
async fn create_consumes_captured_permissions_after_callback_mutation() -> AuthResult<()> {
    let callbacks = Arc::new(Callbacks::default());
    let config = AuthConfig::new("native-body-context-secret-at-least-32-characters");
    let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let auth = BetterAuth::new(config)
        .store_arc(store.clone())
        .plugin(
            ApiKeyPlugin::builder()
                .disable_key_hashing(true)
                .store_starting_characters(false)
                .custom_key_generator(callbacks.clone())
                .default_permissions_callback(callbacks.clone())
                .build(),
        )
        .build()
        .await?;
    let started = chrono::Utc::now().timestamp_millis() as f64;
    let created = auth
        .api_keys()?
        .create(
            "owner",
            CreateKeyOptions {
                permissions: Some(permissions(&["read"])),
                ..Default::default()
            },
        )
        .await?;
    let ended = chrono::Utc::now().timestamp_millis() as f64;
    let expected = json!({
        "id": created.api_key.id, "key": "x".repeat(64), "configId": "default",
        "createdAt": created.api_key.created_at, "updatedAt": created.api_key.updated_at,
        "name": null, "prefix": null, "start": null, "enabled": true, "expiresAt": null,
        "referenceId": "owner", "lastRefillAt": null, "lastRequest": null, "metadata": null,
        "rateLimitMax": 10, "rateLimitTimeWindow": 86_400_000, "remaining": null,
        "refillAmount": null, "refillInterval": null, "rateLimitEnabled": true,
        "requestCount": 0, "permissions": {"nodes": ["read", "write"]},
    });
    assert_eq!(serde_json::to_value(&created)?, expected);
    assert!(!created.api_key.id.typed()?.is_empty());
    for date in [&created.api_key.created_at, &created.api_key.updated_at] {
        assert!((started..=ended).contains(&date.typed()?.milliseconds()));
    }
    let rows = store.storage_rows(EntityRole::ApiKey)?;
    assert_eq!(rows.len(), 1);
    let stored = rows
        .first()
        .ok_or_else(|| AuthError::internal("Expected the created API Key storage row"))?;
    for field in ["createdAt", "updatedAt"] {
        assert!(
            stored
                .get(field)
                .is_some_and(|value| value.as_date().is_some())
        );
    }
    let mut expected_storage = expected;
    for (field, value) in [
        ("metadata", json!("null")),
        ("permissions", json!("{\"nodes\":[\"read\",\"write\"]}")),
    ] {
        *expected_storage.get_mut(field).ok_or_else(|| {
            AuthError::internal(format!("Expected the {field} API Key storage field"))
        })? = value;
    }
    assert_eq!(
        FieldValue::from(stored.clone()).json()?,
        Some(expected_storage)
    );
    for role in [
        EntityRole::User,
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
    ] {
        assert!(store.storage_rows(role)?.is_empty());
    }
    assert_eq!(*lock(&callbacks.0)?, ["generator", "permissions"]);
    Ok(())
}

#[tokio::test]
async fn verify_reads_permissions_at_the_upstream_validator_boundary() -> AuthResult<()> {
    for scoped in [false, true] {
        let callbacks = Arc::new(Callbacks::default());
        let mut config = AuthConfig::new("native-body-context-secret-at-least-32-characters");
        {
            let better_auth_core::LoggerSource::Config(logger_options) = &mut config.logger else {
                return Err(AuthError::internal(
                    "fixture requires authored logger options",
                ));
            };
            logger_options.disabled = Some(true);
        }
        let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
        let auth = BetterAuth::new(config)
            .store_arc(store.clone())
            .plugin(
                ApiKeyPlugin::builder()
                    .disable_key_hashing(true)
                    .store_starting_characters(false)
                    .custom_key_generator(callbacks.clone())
                    .custom_api_key_validator(callbacks.clone())
                    .build(),
            )
            .build()
            .await?;
        let created = auth
            .api_keys()?
            .create(
                "owner",
                CreateKeyOptions {
                    remaining: Some(3.0),
                    permissions: Some(permissions(&["read"])),
                    ..Default::default()
                },
            )
            .await?;
        let roles = [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
            EntityRole::ApiKey,
        ];
        let before: Vec<_> = roles
            .iter()
            .map(|role| store.storage_rows(*role))
            .collect::<AuthResult<_>>()?;
        let error = auth
            .api_keys()?
            .verify(
                &created.key,
                VerifyKeyOptions {
                    config_id: scoped.then(|| "default".into()),
                    permissions: Some(permissions(&["read"])),
                },
            )
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Changed permissions must reject verification"))?;
        let response = error.into_response()?;
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body.bytes()?)?,
            json!({
                "valid": false, "key": null,
                "error": {"code": "KEY_NOT_FOUND", "message": "API Key not found"},
            })
        );
        let after: Vec<_> = roles
            .iter()
            .map(|role| store.storage_rows(*role))
            .collect::<AuthResult<_>>()?;
        assert_eq!(
            after, before,
            "scoped={scoped}: rejected permissions must preserve all storage"
        );
        assert_eq!(*lock(&callbacks.0)?, ["generator", "validator"]);
    }
    Ok(())
}
