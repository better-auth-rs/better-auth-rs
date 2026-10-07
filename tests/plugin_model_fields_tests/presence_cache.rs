use super::presence::{assert_display, describe, read, token};
use super::*;
use better_auth::plugins::api_key::{ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage};
use better_auth::server_api::CreateKeyOptions;
use better_auth_core::store::{CacheAdapter, MemoryCacheAdapter, SecondaryStorage};
use better_auth_core::wire::ApiKeyView;

async fn cache_name(
    cache: &MemoryCacheAdapter,
    key: &str,
    expected: Option<Value>,
) -> AuthResult<()> {
    let value = required(
        SecondaryStorage::get(cache, key).await?,
        "API Key cache record must exist",
    )?;
    let row: Value = serde_json::from_str(required(
        value.as_str(),
        "API Key cache record must contain serialized JSON",
    )?)?;
    assert_display(&row, "name", expected);
    Ok(())
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    for mode in ["database", "fallback", "secondary"] {
        for (presence, expected) in [
            ("undefined", None),
            ("null", Some(Value::Null)),
            ("number", Some(json!(42))),
        ]
        .into_iter()
        .filter(|(presence, _)| mode != "secondary" || *presence == "null")
        {
            let trace = Arc::new(Mutex::new(Vec::new()));
            let input_trace = trace.clone();
            let output_trace = trace.clone();
            let projected = expected
                .clone()
                .map(FieldValue::from_json)
                .transpose()?
                .unwrap_or(FieldValue::Undefined);
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
                                    trace_lock(&input_trace)?
                                        .push(format!("input:name:{}", describe(&value.json()?)));
                                    Ok(value)
                                })),
                                output: Some(UserFieldTransform::new(move |value| {
                                    trace_lock(&output_trace)?
                                        .push(format!("output:name:{}", describe(&value.json()?)));
                                    Ok(projected.clone())
                                })),
                            }),
                            ..Default::default()
                        },
                    ),
                )]))
                .build()
                .await?;
            let owner = owner(raw.as_ref(), &format!("display-key-{mode}-{presence}")).await?;
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
                *trace_lock(&trace)?,
                if mode == "secondary" {
                    Vec::<String>::new()
                } else {
                    vec!["input:name:\"Desk\"".into(), "output:name:\"Desk\"".into()]
                }
            );
            trace_lock(&trace)?.clear();
            let id = created.api_key.id.typed()?;
            let by_id = format!("api-key:by-id:{id}");
            let body = read(&auth, &token, "/api-key/get", Some(json!({"id":id}))).await?;
            assert_display(&body, "name", expected.clone());
            let decoded: ApiKeyView = serde_json::from_value(body)?;
            assert_eq!(decoded.name.json()?, expected);
            assert_eq!(
                *trace_lock(&trace)?,
                if mode == "database" {
                    vec!["output:name:\"Desk\""]
                } else {
                    vec![]
                }
            );
            trace_lock(&trace)?.clear();
            if mode != "database" {
                cache_name(cache.as_ref(), &by_id, expected.clone()).await?;
            }
            if mode == "fallback" {
                CacheAdapter::clear(cache.as_ref()).await?;
                let body = read(&auth, &token, "/api-key/get", Some(json!({"id":id}))).await?;
                assert_display(&body, "name", expected.clone());
                assert_eq!(*trace_lock(&trace)?, ["output:name:\"Desk\""]);
                trace_lock(&trace)?.clear();
                cache_name(cache.as_ref(), &by_id, expected.clone()).await?;
                let body = read(&auth, &token, "/api-key/get", Some(json!({"id":id}))).await?;
                assert_display(&body, "name", expected.clone());
                assert!(trace_lock(&trace)?.is_empty());
                CacheAdapter::clear(cache.as_ref()).await?;
            }
            let listed = read(&auth, &token, "/api-key/list", None).await?;
            assert_eq!(listed.get("total"), Some(&json!(1)));
            let keys = required(
                listed.get("apiKeys").and_then(Value::as_array),
                "API Key response must contain an array",
            )?;
            assert_eq!(keys.len(), 1);
            assert_display(
                required(
                    keys.first(),
                    "API Key response must contain the created key",
                )?,
                "name",
                expected.clone(),
            );
            assert_eq!(
                *trace_lock(&trace)?,
                if mode == "secondary" {
                    vec![]
                } else {
                    vec!["output:name:\"Desk\""]
                }
            );
            trace_lock(&trace)?.clear();
            if mode == "fallback" {
                cache_name(cache.as_ref(), &by_id, expected.clone()).await?;
                let listed = read(&auth, &token, "/api-key/list", None).await?;
                assert_display(
                    required(
                        listed.get("apiKeys").and_then(|rows| rows.get(0)),
                        "Cached API Key response must contain the created key",
                    )?,
                    "name",
                    expected.clone(),
                );
                assert!(trace_lock(&trace)?.is_empty());
            }
            let stored = raw.get_api_key_by_id(id).await?;
            if mode == "secondary" {
                assert!(stored.is_none());
            } else {
                assert_eq!(
                    required(stored, "Database API Key must remain stored")?.name,
                    Some("Desk".into())
                );
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
