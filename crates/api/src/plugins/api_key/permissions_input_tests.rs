use super::*;
use better_auth_core::{
    AuthInitContext, AuthSchema,
    store::{EphemeralStore, MemoryCacheAdapter, SecondaryStorage, schema::EntityRole},
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};

async fn check_permissions<S: AuthSchema>(
    ctx: AuthContext<S>,
    mode: &str,
    declaration: bool,
    sqlite: bool,
) -> AuthResult<()> {
    let permissions = json!({"machine": ["read"]});
    let cache = Arc::new(MemoryCacheAdapter::new());
    let plugin = ApiKeyPlugin::builder()
        .storage(if mode == "database" {
            ApiKeyStorage::Database
        } else {
            ApiKeyStorage::SecondaryStorage
        })
        .fallback_to_database(mode == "fallback")
        .custom_storage(cache.clone())
        .disable_key_hashing(true)
        .store_starting_characters(false)
        .build();
    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut init).await?;
    if declaration {
        init.register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "permissions".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some(permissions.to_string().into()),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )?;
    }
    let store = ctx.database.with_runtime(
        ctx.config.clone(),
        Vec::new(),
        init.into_parts().plugin_fields,
    )?;
    let ctx = AuthContext::new(ctx.config, store);
    let created = plugin
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some("permissions-owner".into()),
                ..Default::default()
            },
        )
        .await?;
    let applied_default = declaration && mode != "secondary";
    let expected = json!({
        "id": created.api_key.id, "key": created.key, "configId": "default",
        "name": null, "prefix": null, "start": null, "enabled": true, "expiresAt": null,
        "referenceId": "permissions-owner", "lastRefillAt": null, "lastRequest": null,
        "metadata": null, "rateLimitMax": 10, "rateLimitTimeWindow": 86_400_000,
        "remaining": null, "refillAmount": null, "refillInterval": null, "rateLimitEnabled": true,
        "requestCount": 0, "createdAt": created.api_key.created_at, "updatedAt": created.api_key.updated_at,
        "permissions": if applied_default { permissions.clone() } else { Value::Null },
    });
    assert_eq!(
        serde_json::to_value(&created)?,
        expected,
        "{mode}/{declaration}"
    );
    let cached = cache
        .get(&format!("api-key:by-id:{}", created.api_key.id.typed()?))
        .await?;
    if mode == "database" {
        assert!(cached.is_none());
    } else {
        let mut stored = expected;
        if applied_default {
            stored["permissions"] = permissions.to_string().into();
        } else if mode == "secondary" || !sqlite {
            let _ = stored.as_object_mut().unwrap().remove("permissions");
        }
        assert_eq!(
            serde_json::from_str::<Value>(cached.unwrap().as_str().unwrap())?,
            stored,
            "{mode}/{declaration}"
        );
        let index = cache.get("api-key:by-ref:permissions-owner").await?;
        if mode == "fallback" {
            assert!(index.is_none());
        } else {
            assert_eq!(
                serde_json::from_str::<Value>(index.unwrap().as_str().unwrap())?,
                json!([created.api_key.id])
            );
        }
    }
    assert_eq!(
        ctx.database
            .count_api_keys_by_reference("permissions-owner")
            .await?,
        u64::from(mode != "secondary")
    );
    Ok(())
}

#[tokio::test]
async fn memory_omitted_permissions_preserve_defaults_and_complete_cache_records() -> AuthResult<()>
{
    for mode in ["database", "secondary", "fallback"] {
        for declaration in [false, true] {
            let config = Arc::new(crate::plugins::test_helpers::create_test_config());
            let ctx = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
            check_permissions(ctx, mode, declaration, false).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_omitted_permissions_preserve_defaults_and_complete_cache_records() -> AuthResult<()>
{
    for mode in ["database", "secondary", "fallback"] {
        for declaration in [false, true] {
            check_permissions(
                crate::plugins::test_helpers::create_test_context().await,
                mode,
                declaration,
                true,
            )
            .await?;
        }
    }
    Ok(())
}
