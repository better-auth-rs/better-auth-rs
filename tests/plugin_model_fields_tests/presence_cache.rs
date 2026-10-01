use super::presence::{assert_display, describe, read, token};
use super::*;
use better_auth::plugins::api_key::{ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage};
use better_auth::server_api::CreateKeyOptions;
use better_auth_core::store::{CacheAdapter, MemoryCacheAdapter, SecondaryStorage};

async fn cache_name(
    cache: &MemoryCacheAdapter,
    key: &str,
    expected: Option<Value>,
) -> AuthResult<()> {
    let value = SecondaryStorage::get(cache, key).await?.unwrap();
    let row: Value = serde_json::from_str(value.as_str().unwrap())?;
    assert_display(&row, "name", expected);
    Ok(())
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    for mode in ["database", "fallback", "secondary"] {
        for null in [false, true]
            .into_iter()
            .filter(|null| mode != "secondary" || *null)
        {
            let expected = if null || mode == "secondary" {
                Some(Value::Null)
            } else {
                None
            };
            let trace = Arc::new(Mutex::new(Vec::new()));
            let input_trace = trace.clone();
            let output_trace = trace.clone();
            let projected = expected.clone();
            let cache = Arc::new(MemoryCacheAdapter::new());
            let mut cfg = config();
            cfg.session.bearer = Some(Default::default());
            let auth = BetterAuth::new(cfg)
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
                .plugin(Fields(vec![(
                    EntityRole::ApiKey,
                    fields(
                        "name",
                        UserFieldConfig {
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(move |value| {
                                    input_trace
                                        .lock()
                                        .unwrap()
                                        .push(format!("input:name:{}", describe(&value)));
                                    Ok(value)
                                })),
                                output: Some(UserFieldTransform::new(move |value| {
                                    output_trace
                                        .lock()
                                        .unwrap()
                                        .push(format!("output:name:{}", describe(&value)));
                                    Ok(projected.clone())
                                })),
                            }),
                            ..Default::default()
                        },
                    ),
                )]))
                .build()
                .await?;
            let owner = owner(raw.as_ref(), &format!("display-key-{mode}-{null}")).await?;
            let token = token(&auth, &owner).await?;
            let created = auth
                .api_keys()?
                .create(
                    &owner,
                    CreateKeyOptions {
                        name: (mode != "secondary").then(|| "Desk".into()),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(created.api_key.name.json()?, expected);
            assert_display(
                &serde_json::to_value(&created.api_key)?,
                "name",
                expected.clone(),
            );
            assert_eq!(
                *trace.lock().unwrap(),
                if mode == "secondary" {
                    Vec::<String>::new()
                } else {
                    vec!["input:name:\"Desk\"".into(), "output:name:\"Desk\"".into()]
                }
            );
            trace.lock().unwrap().clear();
            let id = created.api_key.id.typed()?;
            let by_id = format!("api-key:by-id:{id}");
            let body = read(&auth, &token, "/api-key/get", Some(json!({"id":id}))).await?;
            assert_display(&body, "name", expected.clone());
            assert_eq!(
                *trace.lock().unwrap(),
                if mode == "database" {
                    vec!["output:name:\"Desk\""]
                } else {
                    vec![]
                }
            );
            trace.lock().unwrap().clear();
            if mode != "database" {
                cache_name(cache.as_ref(), &by_id, expected.clone()).await?;
            }
            if mode == "fallback" {
                CacheAdapter::clear(cache.as_ref()).await?;
                let body = read(&auth, &token, "/api-key/get", Some(json!({"id":id}))).await?;
                assert_display(&body, "name", expected.clone());
                assert_eq!(*trace.lock().unwrap(), ["output:name:\"Desk\""]);
                trace.lock().unwrap().clear();
                cache_name(cache.as_ref(), &by_id, expected.clone()).await?;
                let body = read(&auth, &token, "/api-key/get", Some(json!({"id":id}))).await?;
                assert_display(&body, "name", expected.clone());
                assert!(trace.lock().unwrap().is_empty());
                CacheAdapter::clear(cache.as_ref()).await?;
            }
            let listed = read(&auth, &token, "/api-key/list", None).await?;
            assert_eq!(listed["total"], 1);
            assert_eq!(listed["apiKeys"].as_array().unwrap().len(), 1);
            assert_display(&listed["apiKeys"][0], "name", expected.clone());
            assert_eq!(
                *trace.lock().unwrap(),
                if mode == "secondary" {
                    vec![]
                } else {
                    vec!["output:name:\"Desk\""]
                }
            );
            trace.lock().unwrap().clear();
            if mode == "fallback" {
                cache_name(cache.as_ref(), &by_id, expected.clone()).await?;
                let listed = read(&auth, &token, "/api-key/list", None).await?;
                assert_display(&listed["apiKeys"][0], "name", expected.clone());
                assert!(trace.lock().unwrap().is_empty());
            }
            let stored = raw.get_api_key_by_id(id).await?;
            if mode == "secondary" {
                assert!(stored.is_none());
            } else {
                assert_eq!(stored.unwrap().name, Some("Desk".into()));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_display_presence_survives_cache_and_adapter_reads() -> AuthResult<()> {
    contract(memory()).await
}

#[tokio::test]
async fn sqlite_api_key_display_presence_survives_cache_and_adapter_reads() -> AuthResult<()> {
    contract(sqlite().await?).await
}
