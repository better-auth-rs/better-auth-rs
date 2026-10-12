use super::*;
use better_auth::plugins::api_key::{
    ApiKeyDefaultPermissions, ApiKeyGenerator, ApiKeyPermissions, ApiKeyVerificationError,
};
use better_auth::server_api::CreateKeyOptions;

struct Mutate {
    field: &'static str,
    calls: Mutex<usize>,
}

impl ApiKeyGetter for Mutate {
    fn get(&self, endpoint: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>> {
        *lock(&self.calls)? += 1;
        endpoint
            .body
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected API Key body object"))?
            .set(self.field, 7.into())?;
        Ok(None)
    }
}

#[tokio::test]
async fn getter_mutations_reach_typed_facade_validation() -> AuthResult<()> {
    for field in ["name", "keyId", "key"] {
        let getter = Arc::new(Mutate {
            field,
            calls: Mutex::new(0),
        });
        let config = AuthConfig::new("native-body-context-secret-at-least-32-characters");
        let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
        let auth = BetterAuth::new(config)
            .store_arc(store.clone())
            .plugin(
                ApiKeyPlugin::builder()
                    .enable_session_for_api_keys(true)
                    .custom_api_key_getter(getter.clone())
                    .build(),
            )
            .build()
            .await?;
        let api = auth.api_keys()?;
        let result = match field {
            "name" => api
                .create(
                    "owner",
                    CreateKeyOptions {
                        name: Some("original".into()),
                        ..Default::default()
                    },
                )
                .await
                .map(|_| ()),
            "keyId" => api
                .update("owner", "original", Default::default())
                .await
                .map(|_| ()),
            _ => api
                .verify("original", Default::default())
                .await
                .map(|_| ())
                .map_err(|error| match error {
                    ApiKeyVerificationError::Endpoint(error) => error,
                    other => {
                        AuthError::internal(format!("Expected endpoint validation error: {other}"))
                    }
                }),
        };
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Mutated API Key input must fail"))?;
        assert!(error.is_api_error_instance(better_auth_core::ApiErrorClass::BetterCall));
        assert!(!error.is_api_error_instance(better_auth_core::ApiErrorClass::BetterAuth));
        assert_eq!(error.status_value()?, 400.into());
        assert_eq!(error.status_code()?, 400);
        assert_eq!(
            error
                .body_value()?
                .enumerable_fields()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["message", "code"]
        );
        assert_eq!(
            error.body_value()?.json()?,
            Some(json!({
                "code": "VALIDATION_ERROR",
                "message": format!("[body.{field}] Invalid input: expected string, received number"),
            }))
        );
        assert_eq!(*lock(&getter.calls)?, 1);
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
            EntityRole::ApiKey,
        ] {
            assert!(store.storage_rows(role)?.is_empty());
        }
    }
    Ok(())
}

struct Metadata(Contract);

impl ApiKeyGetter for Metadata {
    fn get(&self, endpoint: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>> {
        self.0.record("getter")?;
        lock(&self.0.observed)?.body = endpoint.body.clone();
        endpoint
            .body
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected API Key body object"))?
            .set("metadata", self.0.shared.clone())?;
        Ok(None)
    }
}

#[async_trait]
impl ApiKeyGenerator for Metadata {
    async fn generate(&self, _: usize, _: Option<&str>) -> AuthResult<String> {
        self.0.record("generator")?;
        Ok("x".repeat(64))
    }
}

#[async_trait]
impl ApiKeyDefaultPermissions for Metadata {
    async fn permissions(
        &self,
        reference_id: &FieldValue,
        endpoint: ApiKeyEndpoint<'_>,
    ) -> AuthResult<ApiKeyPermissions> {
        self.0.record("permissions")?;
        assert_eq!(reference_id, &FieldValue::from("owner"));
        assert!(!endpoint.body.strict_equals(&lock(&self.0.observed)?.body));
        let metadata = endpoint.body.model_property("metadata")?;
        assert!(metadata.strict_equals(&self.0.shared));
        assert!(
            metadata
                .as_object()
                .ok_or_else(|| AuthError::internal("Expected metadata object"))?
                .has_property("ownUndefined")?
        );
        assert!(metadata.model_property("ownUndefined")?.is_undefined());
        assert!(metadata.model_property("date")?.strict_equals(&self.0.date));
        assert_eq!(
            endpoint
                .body
                .as_object()
                .ok_or_else(|| AuthError::internal("Expected validated body object"))?
                .enumerable_keys()?,
            ["expiresIn", "remaining", "metadata", "userId"]
        );
        Err(AuthError::from_thrown(self.0.failure.clone()))
    }
}

#[tokio::test]
async fn schema_retains_native_metadata_until_permission_callback() -> AuthResult<()> {
    let callbacks = Arc::new(Metadata(Contract::new(None, "metadata observed", false)?));
    let config = AuthConfig::new("native-body-context-secret-at-least-32-characters");
    let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let auth = BetterAuth::new(config)
        .store_arc(store.clone())
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .enable_metadata(true)
                .custom_api_key_getter(callbacks.clone())
                .custom_key_generator(callbacks.clone())
                .default_permissions_callback(callbacks.clone())
                .build(),
        )
        .build()
        .await?;
    let error = auth
        .api_keys()?
        .create("owner", Default::default())
        .await
        .err()
        .ok_or_else(|| AuthError::internal("Metadata callback must reject"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&callbacks.0.failure))
    );
    assert_eq!(
        lock(&callbacks.0.observed)?.events,
        ["getter", "generator", "permissions"]
    );
    for role in [
        EntityRole::User,
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
        EntityRole::ApiKey,
    ] {
        assert!(store.storage_rows(role)?.is_empty());
    }
    Ok(())
}
