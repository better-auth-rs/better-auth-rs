use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock, Weak};

use better_auth_core::store::SecondaryStorage;
use better_auth_core::{ApiKey, AuthContext, AuthError, AuthResult, CreateApiKey, UpdateApiKey};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use tokio::sync::Mutex;

use super::ApiKeyConfig;

mod usage;
pub(super) use usage::consume;

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
        if !decoded.is_null() && !decoded.is_string() {
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

fn reference_ids(value: Option<Value>) -> Vec<String> {
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
    let value = serialize(key)?;
    let ttl = ttl(key)?;
    let hashed = format!("api-key:{}", key.key_hash);
    let id = format!("api-key:by-id:{}", key.id);
    let reference = format!("api-key:by-ref:{}", key.reference_id);
    if fallback {
        let (hashed, id, reference) = tokio::join!(
            storage.set(&hashed, &value, ttl),
            storage.set(&id, &value, ttl),
            storage.delete(&reference)
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
    let id = format!("api-key:by-id:{}", key.id);
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
            id: uuid::Uuid::new_v4().to_string(),
            name: input.name,
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
    macro_rules! optional { ($($field:ident),* $(,)?) => { $(if let Some(value) = update.$field { key.$field = Some(value); })* }; }
    optional!(
        name,
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
) -> AuthResult<Vec<ApiKey>> {
    let storage = backend(config, ctx);
    if config.storage == ApiKeyStorage::SecondaryStorage {
        if let Some(storage) = storage {
            let ids = reference_ids(storage.get(&format!("api-key:by-ref:{reference}")).await?);
            if !ids.is_empty() || !config.fallback_to_database {
                let mut keys = Vec::new();
                for id in ids {
                    if let Some(key) =
                        cached(storage.as_ref(), &format!("api-key:by-id:{id}")).await?
                    {
                        keys.push(key);
                    }
                }
                return Ok(keys);
            }
        }
        if !config.fallback_to_database {
            return Ok(Vec::new());
        }
    }
    let keys = ctx.database.list_api_keys_by_reference(reference).await?;
    if config.storage == ApiKeyStorage::SecondaryStorage
        && !keys.is_empty()
        && let Some(storage) = storage
    {
        for key in &keys {
            put(storage.as_ref(), key, true).await?;
        }
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

pub(super) fn deduplicate(keys: &mut Vec<ApiKey>) {
    let mut ids = HashSet::new();
    keys.retain(|key| ids.insert(key.id.clone()));
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
