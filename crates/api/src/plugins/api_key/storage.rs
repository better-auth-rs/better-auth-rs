#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use better_auth_core::store::SecondaryStorage;
#[cfg(test)]
use better_auth_core::wire::ApiKeyView;
use better_auth_core::{
    ApiKey, AuthContext, AuthError, AuthRecordFields, AuthResult, CreateApiKey, FieldMap,
    FieldValue, FromFieldMap, UpdateApiKey,
};
use chrono::Utc;
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

pub(super) fn now() -> better_auth_core::FieldDate {
    Utc::now().into()
}

fn ttl(key: &ApiKey) -> AuthResult<Option<u64>> {
    let expires = key.expires_at.field_value();
    if !expires.is_truthy() {
        return Ok(None);
    }
    let seconds = ((better_auth_core::query::field_date(&expires)?.milliseconds()
        - Utc::now().timestamp_millis() as f64)
        / 1000.0)
        .floor();
    Ok((seconds > 0.0).then_some(seconds as u64))
}

fn serialize(key: &ApiKey) -> AuthResult<String> {
    let mut fields = key.field_values()?;
    for (name, optional) in [
        ("createdAt", false),
        ("updatedAt", false),
        ("expiresAt", true),
        ("lastRefillAt", true),
        ("lastRequest", true),
    ] {
        let value = fields.get(name).cloned().unwrap_or_default();
        let value = if optional && (value.is_null() || value.is_undefined()) {
            FieldValue::Null
        } else if let FieldValue::Date(date) = &value {
            if !date.milliseconds().is_finite() {
                return Err(AuthError::internal("Invalid time value"));
            }
            value
                .json()?
                .map(FieldValue::from_json)
                .transpose()?
                .unwrap_or_default()
        } else {
            return Err(AuthError::internal(format!(
                "{name}.toISOString is not a function"
            )));
        };
        let _ = fields.insert(name.into(), value);
    }
    FieldValue::from(fields)
        .stringify()?
        .ok_or_else(|| AuthError::internal("API key cache serialization omitted the record"))
}

fn deserialize(value: Option<Value>) -> Option<ApiKey> {
    let Value::String(value) = value? else {
        return None;
    };
    // Upstream treats malformed serialized cache entries as a cache miss.
    let parsed = FieldValue::parse_json(&value).ok()?;
    let mut fields = match parsed {
        FieldValue::Object(fields) => fields.as_ref().clone(),
        FieldValue::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value.clone()))
            .collect(),
        FieldValue::String(text) => text
            .encode_utf16()
            .enumerate()
            .map(|(index, unit)| {
                (
                    index.to_string(),
                    better_auth_core::Utf16String::from_units(vec![unit]).into(),
                )
            })
            .collect(),
        FieldValue::Utf16String(text) => text
            .as_utf16()
            .iter()
            .enumerate()
            .map(|(index, unit)| {
                (
                    index.to_string(),
                    better_auth_core::Utf16String::from_units(vec![*unit]).into(),
                )
            })
            .collect(),
        _ => FieldMap::new(),
    };
    for (name, optional) in [
        ("createdAt", false),
        ("updatedAt", false),
        ("expiresAt", true),
        ("lastRefillAt", true),
        ("lastRequest", true),
    ] {
        let value = fields.get(name).cloned().unwrap_or_default();
        let value = if optional && !value.is_truthy() {
            FieldValue::Null
        } else {
            better_auth_core::query::field_date(&value).ok()?.into()
        };
        let _ = fields.insert(name.into(), value);
    }
    ApiKey::from_field_values(fields).ok()
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
    let index = format!("api-key:by-ref:{}", key.reference_id.display_string()?);
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
    let hashed = format!("api-key:{}", key.key_hash.display_string()?);
    let id = format!("api-key:by-id:{}", key.id.display_string()?);
    let reference = format!("api-key:by-ref:{}", key.reference_id.display_string()?);
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
    let hashed = format!("api-key:{}", key.key_hash.display_string()?);
    let id = format!("api-key:by-id:{}", key.id.display_string()?);
    let reference = format!("api-key:by-ref:{}", key.reference_id.display_string()?);
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
            additional_fields: Default::default(),
            id: ctx
                .config
                .advanced
                .generate_id("apikey", None)?
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| better_auth_core::id::random_id(None))
                .into(),
            name: input.name,
            start: (input.start).into(),
            prefix: (input.prefix).into(),
            key_hash: (input.key_hash).into(),
            reference_id: (input.reference_id).into(),
            config_id: (input.config_id).into(),
            refill_interval: (input.refill_interval).into(),
            refill_amount: (input.refill_amount).into(),
            last_refill_at: (None).into(),
            enabled: input.enabled,
            rate_limit_enabled: input.rate_limit_enabled.into(),
            rate_limit_time_window: (input.rate_limit_time_window).into(),
            rate_limit_max: (input.rate_limit_max).into(),
            request_count: (Some(0.0)).into(),
            remaining: (input.remaining).into(),
            last_request: (None).into(),
            expires_at: (input.expires_at).into(),
            created_at: (created_at.clone()).into(),
            updated_at: (created_at).into(),
            permissions: (input.permissions).into(),
            metadata: better_auth_core::SchemaValue::from_field(
                input
                    .metadata
                    .as_deref()
                    .map(FieldValue::parse_json)
                    .transpose()?
                    .unwrap_or(FieldValue::Null),
            ),
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

pub(super) fn apply_update(key: &mut ApiKey, update: UpdateApiKey) -> AuthResult<()> {
    if let Some(name) = update.name {
        key.name = name;
    }
    macro_rules! optional { ($($field:ident),* $(,)?) => { $(if let Some(value) = update.$field { key.$field = Some(value).into(); })* }; }
    optional!(
        remaining,
        rate_limit_time_window,
        rate_limit_max,
        refill_interval,
        refill_amount,
        permissions,
        request_count
    );
    if let Some(value) = update.metadata {
        key.metadata = better_auth_core::SchemaValue::from_field(FieldValue::parse_json(&value)?);
    }
    if let Some(value) = update.enabled {
        key.enabled = value;
    }
    if let Some(value) = update.rate_limit_enabled {
        key.rate_limit_enabled = value.into();
    }
    if let Some(value) = update.expires_at {
        key.expires_at = value.into();
    }
    if let Some(value) = update.last_request {
        key.last_request = value.into();
    }
    if let Some(value) = update.last_refill_at {
        key.last_refill_at = value.into();
    }
    key.updated_at = now().into();
    Ok(())
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
        apply_update(&mut key, update)?;
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
                    sort_keys(&mut keys, field, Some(direction))?;
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

fn sort_keys(keys: &mut [ApiKey], sort_by: &str, direction: Option<&str>) -> AuthResult<()> {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let mut values = keys
        .iter()
        .map(|key| {
            Ok(key
                .field_values()?
                .get(sort_by)
                .cloned()
                .unwrap_or_default())
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let compare = |left: &FieldValue, right: &FieldValue| -> AuthResult<std::cmp::Ordering> {
        let ordering = match (left, right) {
            (
                FieldValue::Null | FieldValue::Undefined,
                FieldValue::Null | FieldValue::Undefined,
            ) => Equal,
            (FieldValue::Null | FieldValue::Undefined, _) => Less,
            (_, FieldValue::Null | FieldValue::Undefined) => Greater,
            _ => better_auth_core::query::field_compare(left, right)?.unwrap_or(Equal),
        };
        Ok(if direction == Some("desc") {
            ordering.reverse()
        } else {
            ordering
        })
    };
    // Mixed values and invalid dates can violate sort_by's total-order requirement.
    #[expect(
        clippy::indexing_slicing,
        reason = "The outer range bounds current; current only decreases while positive"
    )]
    for index in 1..keys.len() {
        let mut current = index;
        while current > 0 && compare(&values[current], &values[current - 1])? == Less {
            keys.swap(current - 1, current);
            values.swap(current - 1, current);
            current -= 1;
        }
    }
    Ok(())
}

pub(super) fn deduplicate(keys: &mut Vec<ApiKey>) {
    let mut ids = Vec::new();
    keys.retain(|key| {
        let id = key.id.field_value();
        if ids
            .iter()
            .any(|seen: &FieldValue| seen.same_value_zero(&id))
        {
            return false;
        }
        ids.push(id);
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_codec_preserves_nullable_flags_in_public_views() -> AuthResult<()> {
        for (flag, expected, truthy) in [
            (None, FieldValue::Undefined, false),
            (Some(Value::Null), FieldValue::Null, false),
            (Some(Value::Bool(false)), FieldValue::Bool(false), false),
            (Some(Value::Bool(true)), FieldValue::Bool(true), true),
        ] {
            let mut cached = serde_json::json!({
                "id": "nullable-flags", "key": "hash", "referenceId": "owner", "configId": "default",
                "createdAt": "2030-01-02T03:04:05.000Z", "updatedAt": "2030-01-02T03:04:05.000Z",
                "metadata": { "purpose": "device" },
            });
            if let Some(flag) = &flag {
                cached["enabled"] = flag.clone();
                cached["rateLimitEnabled"] = flag.clone();
            }
            let key = deserialize(Some(Value::String(cached.to_string())))
                .ok_or_else(|| AuthError::internal("The nullable cache entry must decode"))?;
            assert_eq!(key.enabled.field_value(), expected);
            assert_eq!(key.rate_limit_enabled.field_value(), expected);
            assert_eq!(key.enabled.is_truthy()?, truthy);
            assert_eq!(key.rate_limit_enabled.is_truthy()?, truthy);
            let serialized = serialize(&key)?;
            let stored: Value = serde_json::from_str(&serialized)?;
            let restored = deserialize(Some(Value::String(serialized)))
                .ok_or_else(|| AuthError::internal("The serialized cache entry must decode"))?;
            assert_eq!(restored.enabled.field_value(), expected);
            assert_eq!(restored.rate_limit_enabled.field_value(), expected);
            let view = serde_json::to_value(ApiKeyView::from(&restored))?;
            for value in [stored, view] {
                assert_eq!(value.get("enabled"), flag.as_ref());
                assert_eq!(value.get("rateLimitEnabled"), flag.as_ref());
                assert_eq!(value["metadata"], cached["metadata"]);
            }
        }
        Ok(())
    }

    #[test]
    fn cache_codec_preserves_unpaired_start_and_structured_metadata() {
        let cached = r#"{"id":"key-id","key":"hash","referenceId":"owner","configId":null,"start":"\ud83d","enabled":true,"rateLimitEnabled":false,"createdAt":"2026-10-01T00:00:00.000Z","updatedAt":"2026-10-01T00:00:00.000Z","metadata":{"purpose":"device"}}"#;
        let key = deserialize(Some(Value::String(cached.into()))).unwrap();
        assert_eq!(
            key.start.typed().unwrap().as_ref().unwrap().as_utf16(),
            &[0xd83d]
        );
        assert_eq!(key.config_id.field_value(), FieldValue::Null);
        assert_eq!(
            key.metadata.json().unwrap(),
            Some(serde_json::json!({"purpose":"device"}))
        );
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
