use super::*;
use better_auth::plugins::api_key::{ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage};
use better_auth::server_api::{CreateKeyOptions, EndpointInput, UpdateKeyOptions};
use better_auth_core::{
    HttpMethod,
    entity::AuthSession,
    store::{MemoryCacheAdapter, SecondaryStorage},
};

#[path = "../support/api_key_fields.rs"]
mod mapped_fixture;

async fn read<S: AuthSchema>(
    auth: &BetterAuth<S>,
    token: &str,
    path: &str,
    query: Option<Value>,
) -> AuthResult<Value> {
    let response = auth
        .call_endpoint(
            HttpMethod::Get,
            path,
            EndpointInput {
                headers: Some([("authorization".into(), format!("Bearer {token}"))].into()),
                query,
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(response.status, 200);
    Ok(serde_json::from_slice(&response.body.bytes()?)?)
}

async fn cached_name(cache: &dyn SecondaryStorage, id: &str, expected: &str) -> AuthResult<()> {
    let Some(Value::String(stored)) = cache.get(&format!("api-key:by-id:{id}")).await? else {
        return Err(AuthError::internal(
            "API Key cache must contain a serialized record",
        ));
    };
    let value: Value = serde_json::from_str(&stored)?;
    assert_eq!(value.get("name"), Some(&json!(expected)));
    assert!(value.get("stored_name").is_none());
    assert_eq!(value.get("id"), Some(&json!(id)));
    Ok(())
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    column: Option<&str>,
) -> AuthResult<()> {
    for mode in ["database", "secondary", "fallback"] {
        let cache = Arc::new(MemoryCacheAdapter::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut cfg = config();
        cfg.session.bearer = Some(Default::default());
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: if mode == "database" {
                ApiKeyStorage::Database
            } else {
                ApiKeyStorage::SecondaryStorage
            },
            custom_storage: Some(cache.clone()),
            fallback_to_database: mode == "fallback",
            defer_updates: false,
            ..Default::default()
        });
        let mut policy = super::api_key::policy(events.clone());
        policy.field_name = column.map(str::to_owned);
        let mut stored_policy = policy.clone();
        stored_policy.transform = None;
        let reader = BetterAuth::new(cfg.clone())
            .store_arc(raw.clone())
            .plugin(Fields(vec![(
                EntityRole::ApiKey,
                fields("name", stored_policy),
            )]))
            .build()
            .await?;
        let auth = BetterAuth::new(cfg)
            .store_arc(raw.clone())
            .plugin(plugin)
            .plugin(Fields(vec![(EntityRole::ApiKey, fields("name", policy))]))
            .build()
            .await?;
        let owner = owner(raw.as_ref(), &format!("cache-{mode}")).await?;
        let session = auth
            .store()
            .create_session(CreateSession {
                user_id: owner.clone().into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: Default::default(),
            })
            .await?;
        let token = session.token();
        let created = auth
            .api_keys()?
            .create(
                &owner,
                CreateKeyOptions {
                    name: Some("  Desk  ".into()),
                    ..Default::default()
                },
            )
            .await?;
        let id = created.api_key.id.typed()?;
        let cached_only = mode == "secondary";
        let expected = if cached_only { "  Desk  " } else { "Desk:out" };
        if column.is_some() && mode != "database" {
            cached_name(cache.as_ref(), id, expected).await?;
        }
        assert_eq!(created.api_key.name.typed()?.as_deref(), Some(expected));
        if cached_only {
            assert!(trace_lock(&events)?.is_empty());
            assert!(reader.store().get_api_key_by_id(id).await?.is_none());
        } else {
            assert_eq!(
                *trace_lock(&events)?,
                ["input:\"  Desk  \"", "output:\"Desk\""]
            );
            assert_eq!(
                required(
                    reader.store().get_api_key_by_id(id).await?,
                    "Database API Key must remain stored"
                )?
                .name
                .typed()?
                .as_deref(),
                Some("Desk")
            );
        }
        trace_lock(&events)?.clear();
        let found = read(&auth, token, "/api-key/get", Some(json!({"id":id}))).await?;
        assert_eq!(found.get("name"), Some(&json!(expected)));
        assert_eq!(
            *trace_lock(&events)?,
            if mode == "database" {
                vec!["output:\"Desk\"".to_owned()]
            } else {
                vec![]
            }
        );
        for turn in 0..2 {
            trace_lock(&events)?.clear();
            let listed = read(&auth, token, "/api-key/list", None).await?;
            assert_eq!(
                listed
                    .get("apiKeys")
                    .and_then(|rows| rows.get(0))
                    .and_then(|row| row.get("name")),
                Some(&json!(expected))
            );
            let database = mode == "database" || mode == "fallback" && turn == 0;
            assert_eq!(
                *trace_lock(&events)?,
                if database {
                    vec!["output:\"Desk\"".to_owned()]
                } else {
                    vec![]
                }
            );
        }
        trace_lock(&events)?.clear();
        let updated = auth
            .api_keys()?
            .update(
                &owner,
                id,
                UpdateKeyOptions {
                    name: Some("  Mobile  ".into()),
                    ..Default::default()
                },
            )
            .await?;
        let expected = if cached_only {
            "  Mobile  "
        } else {
            "Mobile:out"
        };
        assert_eq!(updated.name.typed()?.as_deref(), Some(expected));
        if column.is_some() && mode != "database" {
            cached_name(cache.as_ref(), id, expected).await?;
        }
        let expected_events: Vec<String> = match mode {
            "database" => vec![
                "output:\"Desk\"",
                "input:\"  Mobile  \"",
                "output:\"Mobile\"",
            ],
            "fallback" => vec!["input:\"  Mobile  \"", "output:\"Mobile\""],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(*trace_lock(&events)?, expected_events);
        if mode == "fallback" {
            for cached_value in [None, Some("null")] {
                trace_lock(&events)?.clear();
                let cache_key = format!("api-key:by-id:{id}");
                match cached_value {
                    Some(value) => cache.set(&cache_key, value, None).await?,
                    None => cache.delete(&cache_key).await?,
                }
                let found = read(&auth, token, "/api-key/get", Some(json!({"id":id}))).await?;
                assert_eq!(found.get("name"), Some(&json!(expected)));
                assert_eq!(*trace_lock(&events)?, ["output:\"Mobile\""]);
                if column.is_some() {
                    cached_name(cache.as_ref(), id, expected).await?;
                }
                trace_lock(&events)?.clear();
                let found = read(&auth, token, "/api-key/get", Some(json!({"id":id}))).await?;
                assert_eq!(found.get("name"), Some(&json!(expected)));
                assert!(trace_lock(&events)?.is_empty());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_cache_paths_only_transform_database_operations() -> AuthResult<()> {
    contract(memory(), None).await
}
#[tokio::test]
async fn sqlite_api_key_cache_paths_only_transform_database_operations() -> AuthResult<()> {
    contract(sqlite().await?, None).await
}

#[tokio::test]
async fn memory_mapped_api_key_names_keep_cache_hits_untransformed() -> AuthResult<()> {
    for column in ["", "stored_name"] {
        contract(memory(), Some(column)).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_mapped_api_key_names_keep_cache_hits_untransformed()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (store, database) = mapped_fixture::sqlite(config()).await;
    contract(Arc::new(store), Some("")).await?;
    database.close().await?;
    let (store, database) =
        mapped_fixture::sqlite_for::<mapped_fixture::renamed::Model>(config()).await;
    contract(Arc::new(store), Some("stored_name")).await?;
    database.close().await?;
    Ok(())
}
