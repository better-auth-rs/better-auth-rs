use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use better_auth_core::store::SecondaryStorage;
use better_auth_core::{ApiKey, AuthContext, AuthError, AuthResult, CreateApiKey, UpdateApiKey};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::{StreamExt, TryFutureExt, future, stream};
use serde_json::Value;
use tokio::sync::Mutex;

use super::ApiKeyConfig;

const STORAGE_CONCURRENCY: usize = 10;

mod usage;
pub(super) use usage::consume;
#[cfg(test)]
mod batch_tests;

/// Persistence used by an API Key configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApiKeyStorage {
    #[default]
    Database,
    SecondaryStorage,
}

pub(super) fn backend<'a>(
    config: &'a ApiKeyConfig,
    ctx: &'a AuthContext<impl better_auth_core::AuthSchema>,
) -> Option<&'a Arc<dyn SecondaryStorage>> {
    config
        .custom_storage
        .as_ref()
        .or(ctx.secondary_storage.as_ref())
}

pub(super) fn group(config: &ApiKeyConfig) -> String {
    if config.storage == ApiKeyStorage::Database {
        "database".into()
    } else if config.custom_storage.is_some() {
        format!("custom:{}", config.config_id)
    } else if config.fallback_to_database {
        "secondary-storage-with-fallback".into()
    } else {
        "secondary-storage".into()
    }
}

fn required_backend<'a>(
    config: &'a ApiKeyConfig,
    ctx: &'a AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<&'a Arc<dyn SecondaryStorage>> {
    backend(config, ctx).ok_or_else(|| {
        AuthError::internal(
            "Secondary storage is required when storage mode is 'secondary-storage'",
        )
    })
}

pub(super) fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(super) fn timestamp(value: &str) -> AuthResult<i64> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.timestamp_millis())
        .map_err(|error| AuthError::internal(format!("Invalid stored API key timestamp: {error}")))
}

fn ttl(key: &ApiKey) -> AuthResult<Option<u64>> {
    key.expires_at
        .as_deref()
        .map(|expires| {
            let seconds = (timestamp(expires)? - Utc::now().timestamp_millis()).div_euclid(1000);
            Ok(u64::try_from(seconds).ok().filter(|seconds| *seconds > 0))
        })
        .transpose()
        .map(Option::flatten)
}

fn serialize(key: &ApiKey) -> AuthResult<String> {
    let mut value: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(&serde_json::to_string(key)?)?;
    // Upstream stores metadata as JSON, but the typed database boundary uses JSON text.
    let metadata = key
        .metadata
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or(Value::Null);
    let _ = value.insert(
        "metadata".into(),
        serde_json::value::to_raw_value(&metadata)?,
    );
    Ok(serde_json::to_string(&value)?)
}

fn deserialize(value: Option<Value>) -> Option<ApiKey> {
    let Value::String(value) = value? else {
        return None;
    };
    // Upstream treats malformed serialized cache entries as a cache miss.
    let mut object: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(&value).ok()?;
    if let Some(metadata) = object.get_mut("metadata") {
        let decoded: Value = serde_json::from_str(metadata.get()).ok()?;
        if !decoded.is_null() {
            *metadata = serde_json::value::to_raw_value(&decoded.to_string()).ok()?;
        }
    }
    if object
        .get("configId")
        .is_none_or(|value| value.get() == "null")
    {
        let _ = object.insert("configId".into(), serde_json::value::to_raw_value("").ok()?);
    }
    serde_json::from_str(&serde_json::to_string(&object).ok()?).ok()
}

async fn cached(storage: &dyn SecondaryStorage, key: &str) -> AuthResult<Option<ApiKey>> {
    Ok(deserialize(storage.get(key).await?))
}

fn reference_ids(value: Option<Value>) -> Vec<better_auth_core::SchemaValue<String>> {
    let value = match value {
        Some(Value::String(value)) => serde_json::from_str(&value).ok(),
        value => value,
    };
    value
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

async fn modify_reference(
    storage: &dyn SecondaryStorage,
    key: &ApiKey,
    insert: bool,
) -> AuthResult<()> {
    // The upstream reference-list lock only coordinates writers in this process.
    // Cache-only quota remains non-atomic; database fallback provides guarded quota.
    let index = format!("api-key:by-ref:{}", key.reference_id);
    static LOCKS: OnceLock<std::sync::Mutex<HashMap<String, Weak<Mutex<()>>>>> = OnceLock::new();
    let lock = {
        let mut locks = LOCKS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| AuthError::internal("API key reference-list lock poisoned"))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        match locks.get(&index).and_then(Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(Mutex::new(()));
                let _ = locks.insert(index.clone(), Arc::downgrade(&lock));
                lock
            }
        }
    };
    let _guard = lock.lock().await;
    let mut ids = reference_ids(storage.get(&index).await?);
    if insert {
        if !ids.contains(&key.id) {
            ids.push(key.id.clone());
        }
    } else {
        ids.retain(|id| id != &key.id);
    }
    if ids.is_empty() {
        storage.delete(&index).await
    } else {
        storage
            .set(&index, &serde_json::to_string(&ids)?, None)
            .await
    }
}

pub(super) async fn put(
    storage: &dyn SecondaryStorage,
    key: &ApiKey,
    fallback: bool,
) -> AuthResult<()> {
    put_with_failure_flag(storage, key, fallback, None).await
}

async fn put_with_failure_flag(
    storage: &dyn SecondaryStorage,
    key: &ApiKey,
    fallback: bool,
    failed: Option<&AtomicBool>,
) -> AuthResult<()> {
    let value = serialize(key)?;
    let ttl = ttl(key)?;
    let hashed = format!("api-key:{}", key.key_hash);
    let id = format!("api-key:by-id:{}", key.id.display_string()?);
    let reference = format!("api-key:by-ref:{}", key.reference_id);
    if fallback {
        // Stop a list refill when an IO fails, even while another write for this key is pending.
        let stop_batch = |_: &AuthError| {
            if let Some(failed) = failed {
                failed.store(true, Ordering::Relaxed);
            }
        };
        let (hashed, id, reference) = tokio::join!(
            storage.set(&hashed, &value, ttl).inspect_err(stop_batch),
            storage.set(&id, &value, ttl).inspect_err(stop_batch),
            storage.delete(&reference).inspect_err(stop_batch)
        );
        hashed?;
        id?;
        reference
    } else {
        let (hashed, id) = tokio::join!(
            storage.set(&hashed, &value, ttl),
            storage.set(&id, &value, ttl)
        );
        hashed?;
        id?;
        modify_reference(storage, key, true).await
    }
}

async fn remove_cached(
    storage: &dyn SecondaryStorage,
    key: &ApiKey,
    fallback: bool,
) -> AuthResult<()> {
    let hashed = format!("api-key:{}", key.key_hash);
    let id = format!("api-key:by-id:{}", key.id.display_string()?);
    let reference = format!("api-key:by-ref:{}", key.reference_id);
    if fallback {
        let (hashed, id, reference) = tokio::join!(
            storage.delete(&hashed),
            storage.delete(&id),
            storage.delete(&reference)
        );
        hashed?;
        id?;
        reference
    } else {
        let (hashed, id, reference) = tokio::join!(
            storage.delete(&hashed),
            storage.delete(&id),
            modify_reference(storage, key, false)
        );
        hashed?;
        id?;
        reference
    }
}

pub(crate) async fn get_by_id(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    id: &str,
) -> AuthResult<Option<ApiKey>> {
    get(config, ctx, id, false).await
}

pub(super) async fn get_by_hash(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    hash: &str,
) -> AuthResult<Option<ApiKey>> {
    get(config, ctx, hash, true).await
}

async fn get(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    value: &str,
    hash: bool,
) -> AuthResult<Option<ApiKey>> {
    let storage = backend(config, ctx);
    if config.storage == ApiKeyStorage::SecondaryStorage {
        if let Some(storage) = storage {
            let key = if hash {
                format!("api-key:{value}")
            } else {
                format!("api-key:by-id:{value}")
            };
            if let Some(key) = cached(storage.as_ref(), &key).await? {
                return Ok(Some(key));
            }
        }
        if !config.fallback_to_database {
            return Ok(None);
        }
    }
    let key = if hash {
        ctx.database.get_api_key_by_hash(value).await?
    } else {
        ctx.database.get_api_key_by_id(value).await?
    };
    if config.storage == ApiKeyStorage::SecondaryStorage
        && let (Some(storage), Some(key)) = (storage, key.as_ref())
    {
        put(storage.as_ref(), key, config.fallback_to_database).await?;
    }
    Ok(key)
}

pub(super) async fn create(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    input: CreateApiKey,
) -> AuthResult<ApiKey> {
    let key = if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
        ctx.database.create_api_key(input).await?
    } else {
        let created_at = now();
        ApiKey {
            id: ctx
                .config
                .advanced
                .generate_id("apikey", None)?
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| better_auth_core::id::random_id(None))
                .into(),
            name: input.name.into(),
            start: input.start,
            prefix: input.prefix,
            key_hash: input.key_hash,
            reference_id: input.reference_id,
            config_id: input.config_id,
            refill_interval: input.refill_interval,
            refill_amount: input.refill_amount,
            last_refill_at: None,
            enabled: input.enabled,
            rate_limit_enabled: input.rate_limit_enabled,
            rate_limit_time_window: input.rate_limit_time_window,
            rate_limit_max: input.rate_limit_max,
            request_count: Some(0.0),
            remaining: input.remaining,
            last_request: None,
            expires_at: input.expires_at,
            created_at: created_at.clone(),
            updated_at: created_at,
            permissions: input.permissions,
            metadata: input.metadata,
        }
    };
    if config.storage == ApiKeyStorage::SecondaryStorage {
        put(
            required_backend(config, ctx)?.as_ref(),
            &key,
            config.fallback_to_database,
        )
        .await?;
    }
    Ok(key)
}

pub(super) fn apply_update(key: &mut ApiKey, update: UpdateApiKey) {
    if let Some(name) = update.name {
        key.name = Some(name).into();
    }
    macro_rules! optional { ($($field:ident),* $(,)?) => { $(if let Some(value) = update.$field { key.$field = Some(value); })* }; }
    optional!(
        remaining,
        rate_limit_time_window,
        rate_limit_max,
        refill_interval,
        refill_amount,
        permissions,
        metadata,
        request_count
    );
    if let Some(value) = update.enabled {
        key.enabled = value;
    }
    if let Some(value) = update.rate_limit_enabled {
        key.rate_limit_enabled = value;
    }
    if let Some(value) = update.expires_at {
        key.expires_at = value;
    }
    if let Some(value) = update.last_request {
        key.last_request = value;
    }
    if let Some(value) = update.last_refill_at {
        key.last_refill_at = value;
    }
    key.updated_at = now();
}

pub(super) async fn update(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    mut key: ApiKey,
    update: UpdateApiKey,
) -> AuthResult<ApiKey> {
    if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
        key = match ctx.database.update_api_key(&key.id, update).await {
            Ok(updated) => updated,
            // Upstream adapter.update returns null when a row disappears after the ownership lookup.
            Err(AuthError::NotFound(_)) => return Ok(key),
            Err(error) => return Err(error),
        };
    } else {
        apply_update(&mut key, update);
    }
    if config.storage == ApiKeyStorage::SecondaryStorage {
        put(
            required_backend(config, ctx)?.as_ref(),
            &key,
            config.fallback_to_database,
        )
        .await?;
    }
    Ok(key)
}

pub(super) async fn delete(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    key: &ApiKey,
) -> AuthResult<()> {
    if config.storage == ApiKeyStorage::SecondaryStorage {
        remove_cached(
            required_backend(config, ctx)?.as_ref(),
            key,
            config.fallback_to_database,
        )
        .await?;
    }
    if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
        ctx.database.delete_api_key(&key.id).await?;
    }
    Ok(())
}

pub(super) async fn delete_for_verification(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    key: &ApiKey,
) -> AuthResult<()> {
    if !config.defer_updates {
        return delete(config, ctx, key).await;
    }
    let storage = backend(config, ctx).cloned();
    let database = ctx.database.clone();
    let config = config.clone();
    let key = key.clone();
    let _task = tokio::spawn(async move {
        let result: AuthResult<()> = async {
            if config.storage == ApiKeyStorage::SecondaryStorage {
                let storage = storage.ok_or_else(|| {
                    AuthError::internal(
                        "Secondary storage is required when storage mode is 'secondary-storage'",
                    )
                })?;
                remove_cached(storage.as_ref(), &key, config.fallback_to_database).await?;
            }
            if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
                database.delete_api_key(&key.id).await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            better_auth_core::observability::logger::current().error(
                "Deferred API key deletion failed",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
        }
    });
    Ok(())
}

pub(super) async fn list(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    reference: &str,
    sort: Option<(&str, &str)>,
) -> AuthResult<Vec<ApiKey>> {
    let storage = backend(config, ctx);
    if config.storage == ApiKeyStorage::SecondaryStorage {
        if let Some(storage) = storage {
            let ids = reference_ids(storage.get(&format!("api-key:by-ref:{reference}")).await?);
            if !ids.is_empty() || !config.fallback_to_database {
                let failed = AtomicBool::new(false);
                let mut results = stream::iter(ids.into_iter().enumerate())
                    .take_while(|_| future::ready(!failed.load(Ordering::Relaxed)))
                    .map(|(index, id)| {
                        let failed = &failed;
                        async move {
                            let result = async {
                                cached(
                                    storage.as_ref(),
                                    &format!("api-key:by-id:{}", id.display_string()?),
                                )
                                .await
                            }
                            .await;
                            if result.is_err() {
                                failed.store(true, Ordering::Relaxed);
                            }
                            result.map(|key| (index, key))
                        }
                    })
                    .buffer_unordered(STORAGE_CONCURRENCY)
                    // Keep started callbacks in this request's scope. Unlike a JS promise,
                    // the Rust result waits for these peers before returning the first error.
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<AuthResult<Vec<_>>>()?;
                results.sort_unstable_by_key(|(index, _)| *index);
                let mut keys: Vec<_> = results.into_iter().filter_map(|(_, key)| key).collect();
                if let Some((field, direction)) = sort {
                    let mut views: Vec<_> = keys
                        .iter()
                        .map(better_auth_core::wire::ApiKeyView::from)
                        .collect();
                    sort_views(&mut views, field, Some(direction))?;
                    let mut by_id: std::collections::HashMap<_, _> = keys
                        .into_iter()
                        .map(|key| (key.id.as_str().map(str::to_owned), key))
                        .collect();
                    keys = views
                        .into_iter()
                        .filter_map(|view| by_id.remove(&view.id.as_str().map(str::to_owned)))
                        .collect();
                }
                return Ok(keys);
            }
        }
        if !config.fallback_to_database {
            return Ok(Vec::new());
        }
    }
    let (keys, total) = tokio::join!(
        ctx.database.find_api_keys_by_reference(reference, sort),
        ctx.database.count_api_keys_by_reference(reference),
    );
    let mut keys = keys?;
    // The public endpoint recomputes total from these rows, but upstream still
    // performs the adapter count and propagates a failure from that operation.
    let _ = total?;
    if config.storage == ApiKeyStorage::SecondaryStorage
        && !keys.is_empty()
        && let Some(storage) = storage
    {
        let failed = AtomicBool::new(false);
        let mut results = stream::iter(keys.into_iter().enumerate())
            .take_while(|_| future::ready(!failed.load(Ordering::Relaxed)))
            .map(|(index, key)| {
                let failed = &failed;
                async move {
                    let result =
                        put_with_failure_flag(storage.as_ref(), &key, true, Some(failed)).await;
                    if result.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    result.map(|()| (index, key))
                }
            })
            .buffer_unordered(STORAGE_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<AuthResult<Vec<_>>>()?;
        results.sort_unstable_by_key(|(index, _)| *index);
        keys = results.into_iter().map(|(_, key)| key).collect();
        let ids: Vec<_> = keys.iter().map(|key| &key.id).collect();
        storage
            .set(
                &format!("api-key:by-ref:{reference}"),
                &serde_json::to_string(&ids)?,
                None,
            )
            .await?;
    }
    Ok(keys)
}

fn compare_numbers(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left
            .partial_cmp(&right)
            .unwrap_or(std::cmp::Ordering::Equal),
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
    }
}

fn compare_strings(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.encode_utf16().cmp(right.encode_utf16()),
        _ => left.cmp(&right),
    }
}

fn sort_views(
    views: &mut Vec<better_auth_core::wire::ApiKeyView>,
    sort_by: &str,
    direction: Option<&str>,
) -> AuthResult<()> {
    if sort_by == "name" {
        let mut named = std::mem::take(views)
            .into_iter()
            .map(|view| {
                let name = if view.name.is_undefined() {
                    None
                } else {
                    view.name.typed()?.clone()
                };
                Ok((name, view))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        named.sort_by(|a, b| {
            let order = compare_strings(a.0.as_deref(), b.0.as_deref());
            if direction == Some("desc") {
                order.reverse()
            } else {
                order
            }
        });
        *views = named.into_iter().map(|(_, view)| view).collect();
        return Ok(());
    }
    views.sort_by(|a, b| {
        let ordering = match sort_by {
            "id" => compare_strings(a.id.as_str(), b.id.as_str()),
            "start" => a.start.cmp(&b.start),
            "prefix" => compare_strings(a.prefix.as_deref(), b.prefix.as_deref()),
            "referenceId" => compare_strings(Some(&a.reference_id), Some(&b.reference_id)),
            "configId" => compare_strings(Some(&a.config_id), Some(&b.config_id)),
            "enabled" => a.enabled.cmp(&b.enabled),
            "rateLimitEnabled" => a.rate_limit_enabled.cmp(&b.rate_limit_enabled),
            "createdAt" => a.created_at.cmp(&b.created_at),
            "updatedAt" => a.updated_at.cmp(&b.updated_at),
            "expiresAt" => a.expires_at.cmp(&b.expires_at),
            "lastRequest" => a.last_request.cmp(&b.last_request),
            "lastRefillAt" => a.last_refill_at.cmp(&b.last_refill_at),
            "remaining" => compare_numbers(a.remaining, b.remaining),
            "requestCount" => compare_numbers(a.request_count, b.request_count),
            "rateLimitMax" => compare_numbers(a.rate_limit_max, b.rate_limit_max),
            "rateLimitTimeWindow" => {
                compare_numbers(a.rate_limit_time_window, b.rate_limit_time_window)
            }
            "refillAmount" => compare_numbers(a.refill_amount, b.refill_amount),
            "refillInterval" => compare_numbers(a.refill_interval, b.refill_interval),
            _ => std::cmp::Ordering::Equal,
        };
        if direction == Some("desc") {
            ordering.reverse()
        } else {
            ordering
        }
    });
    Ok(())
}

pub(super) fn deduplicate(keys: &mut Vec<ApiKey>) {
    let mut ids = HashSet::new();
    keys.retain(|key| ids.insert(key.id.as_str().map(str::to_owned)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_codec_preserves_unpaired_start_and_structured_metadata() {
        let cached = r#"{"id":"key-id","key":"hash","referenceId":"owner","configId":null,"start":"\ud83d","enabled":true,"rateLimitEnabled":false,"createdAt":"2026-10-01T00:00:00.000Z","updatedAt":"2026-10-01T00:00:00.000Z","metadata":{"purpose":"device"}}"#;
        let key = deserialize(Some(Value::String(cached.into()))).unwrap();
        assert_eq!(key.start.as_ref().unwrap().as_utf16(), &[0xd83d]);
        assert_eq!(key.config_id, "");
        assert_eq!(key.metadata.as_deref(), Some(r#"{"purpose":"device"}"#));
        let serialized = serialize(&key).unwrap();
        let fields: BTreeMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(fields.get("start").unwrap().get(), r#""\ud83d""#);
        assert_eq!(
            fields.get("metadata").unwrap().get(),
            r#"{"purpose":"device"}"#
        );
        let restored = deserialize(Some(Value::String(serialized))).unwrap();
        assert_eq!(restored.start, key.start);
        assert_eq!(restored.metadata, key.metadata);
        assert!(deserialize(Some(Value::String("malformed".into()))).is_none());
    }
}
