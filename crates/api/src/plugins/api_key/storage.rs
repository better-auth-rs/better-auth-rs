#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use better_auth_core::request_runtime::concurrent::{self, FailureReporter, StartedOperation};
use better_auth_core::store::SecondaryStorage;
#[cfg(test)]
use better_auth_core::wire::ApiKeyView;
use better_auth_core::{
    ApiKey, AuthContext, AuthError, AuthRecordFields, AuthResult, FieldMap, FieldValue,
    FromFieldMap,
};
use chrono::Utc;
use futures_util::{FutureExt, StreamExt, future, stream};
#[cfg(test)]
use serde_json::Value;

use super::ApiKeyConfig;

const STORAGE_CONCURRENCY: usize = 10;

struct StorageBatch<'a> {
    reporter: &'a FailureReporter,
    failed: AtomicBool,
}

impl<'a> StorageBatch<'a> {
    fn new(reporter: &'a FailureReporter) -> Self {
        Self {
            reporter,
            failed: AtomicBool::new(false),
        }
    }

    fn observe<T>(&self, result: AuthResult<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.failed.store(true, Ordering::Relaxed);
                self.reporter.failed(error);
                None
            }
        }
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }
}

mod usage;
pub(super) use usage::consume;
mod reference;
pub(super) use reference::property as list_field;
use reference::{cache_key, modify_reference};
#[cfg(test)]
mod batch_tests;
#[cfg(test)]
mod cache_key_order_tests;
#[cfg(test)]
mod cache_metadata_tests;
#[cfg(test)]
mod date_methods_tests;
#[cfg(test)]
mod native_sort_tests;

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

fn ttl(key: &ApiKey, clock: impl FnOnce() -> f64) -> AuthResult<Option<u64>> {
    let expires = key.expires_at.field_value();
    if !expires.is_truthy() {
        return Ok(None);
    }
    let now = clock();
    let seconds =
        ((better_auth_core::query::field_date(&expires)?.milliseconds() - now) / 1000.0).floor();
    Ok((seconds > 0.0).then_some(seconds as u64))
}

fn serialize(key: &ApiKey) -> AuthResult<FieldValue> {
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
        } else {
            let result = value.to_iso_string_method(&format!("apiKey.{name}.toISOString"))?;
            if optional && (result.is_null() || result.is_undefined()) {
                FieldValue::Null
            } else {
                result
            }
        };
        let _ = fields.insert(name.into(), value);
    }
    FieldValue::from(fields).stringify_native()
}

fn deserialize(value: Option<FieldValue>) -> Option<ApiKey> {
    ApiKey::from_field_values(deserialize_fields(value)?).ok()
}

fn deserialize_fields(value: Option<FieldValue>) -> Option<FieldMap> {
    let value @ (FieldValue::String(_) | FieldValue::Utf16String(_)) = value? else {
        return None;
    };
    // Upstream treats malformed serialized cache entries as a cache miss.
    let parsed = better_auth_core::utils::json::parse_native_json(&value).ok()?;
    if parsed.is_null() {
        return None;
    }
    // JSON parsing creates owned objects, so this cache boundary cannot read a live source lock.
    let mut fields = parsed.enumerable_fields().ok()?;
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
    Some(fields)
}

async fn cached(storage: Arc<dyn SecondaryStorage>, key: &str) -> AuthResult<Option<ApiKey>> {
    cached_native(storage, &key.into()).await
}

async fn cached_native(
    storage: Arc<dyn SecondaryStorage>,
    key: &FieldValue,
) -> AuthResult<Option<ApiKey>> {
    Ok(deserialize(storage.invoke_get_native(key.clone())?.await?))
}

async fn cached_native_fields(
    storage: Arc<dyn SecondaryStorage>,
    key: &FieldValue,
) -> AuthResult<Option<FieldMap>> {
    Ok(deserialize_fields(
        storage.invoke_get_native(key.clone())?.await?,
    ))
}

pub(super) async fn put(
    storage: Arc<dyn SecondaryStorage>,
    key: &ApiKey,
    fallback: bool,
) -> AuthResult<()> {
    let pending = PendingWrite::start(storage.clone(), key, fallback).await?;
    let key = key.clone();
    concurrent::retain("API key cache write", move |reporter| async move {
        let batch = StorageBatch::new(&reporter);
        pending.finish(storage, &key, &batch).await
    })
    .await
}

struct PendingWrite {
    operations: Vec<StartedOperation<()>>,
    insert_reference: Option<FieldValue>,
}

impl PendingWrite {
    async fn start(
        storage: Arc<dyn SecondaryStorage>,
        key: &ApiKey,
        fallback: bool,
    ) -> AuthResult<Self> {
        let ttl = ttl(key, || Utc::now().timestamp_millis() as f64)?.map(|seconds| seconds as f64);
        let value = serialize(key)?;
        let reference = cache_key("api-key:by-ref:", &key.reference_id.field_value())?;
        let hashed = cache_key("api-key:", &key.key_hash.field_value())?;
        let hashed = StartedOperation::new(
            "API key unowned cache write",
            storage
                .clone()
                .invoke_set_native(hashed, value.clone(), Some(ttl))?,
        )
        .await;
        let id = cache_key("api-key:by-id:", &key.id.field_value())?;
        let id = StartedOperation::new(
            "API key unowned cache write",
            storage.clone().invoke_set_native(id, value, Some(ttl))?,
        )
        .await;
        let mut operations = vec![hashed, id];
        let insert_reference = if fallback {
            operations.push(
                StartedOperation::new(
                    "API key unowned cache invalidation",
                    storage.invoke_delete_native(reference)?,
                )
                .await,
            );
            None
        } else {
            Some(reference)
        };
        Ok(Self {
            operations,
            insert_reference,
        })
    }

    async fn finish(
        self,
        storage: Arc<dyn SecondaryStorage>,
        key: &ApiKey,
        batch: &StorageBatch<'_>,
    ) -> Option<()> {
        future::join_all(
            self.operations
                .into_iter()
                .map(|operation| operation.map(|result| batch.observe(result))),
        )
        .await
        .into_iter()
        .collect::<Option<()>>()?;
        if let Some(reference) = self.insert_reference {
            batch.observe(modify_reference(storage, key, reference, true).await)?;
        }
        Some(())
    }
}

async fn put_in_batch(
    storage: Arc<dyn SecondaryStorage>,
    key: &ApiKey,
    fallback: bool,
    batch: &StorageBatch<'_>,
) -> Option<()> {
    let pending = batch.observe(PendingWrite::start(storage.clone(), key, fallback).await)?;
    pending.finish(storage, key, batch).await
}

async fn remove_cached(
    storage: Arc<dyn SecondaryStorage>,
    key: &ApiKey,
    fallback: bool,
) -> AuthResult<()> {
    let reference = cache_key("api-key:by-ref:", &key.reference_id.field_value())?;
    let hashed = cache_key("api-key:", &key.key_hash.field_value())?;
    let hashed = StartedOperation::new(
        "API key unowned cache removal",
        storage.clone().invoke_delete_native(hashed)?,
    )
    .await;
    let id = cache_key("api-key:by-id:", &key.id.field_value())?;
    let id = StartedOperation::new(
        "API key unowned cache removal",
        storage.clone().invoke_delete_native(id)?,
    )
    .await;
    let key = key.clone();
    let reference = if fallback {
        storage.invoke_delete_native(reference)?
    } else {
        Box::pin(async move { modify_reference(storage, &key, reference, false).await })
    };
    let reference = StartedOperation::new("API key unowned reference removal", reference).await;
    concurrent::retain("API key cache removal", move |reporter| async move {
        let batch = StorageBatch::new(&reporter);
        future::join_all(
            [hashed, id, reference]
                .into_iter()
                .map(|operation| operation.map(|result| batch.observe(result))),
        )
        .await
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .map(|_| ())
    })
    .await
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
            if let Some(key) = cached(storage.clone(), &key).await? {
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
        put(storage.clone(), key, config.fallback_to_database).await?;
    }
    Ok(key)
}

pub(super) async fn create(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    mut fields: FieldMap,
) -> AuthResult<Option<ApiKey>> {
    fields.extend([
        ("createdAt".into(), now().into()),
        ("updatedAt".into(), now().into()),
        ("lastRefillAt".into(), FieldValue::Null),
        ("lastRequest".into(), FieldValue::Null),
    ]);
    let key = if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
        ctx.database
            .create_api_key_record(fields)
            .await?
            .map(ApiKey::from_field_values)
            .transpose()?
    } else {
        let id = ctx
            .config
            .advanced
            .generate_id("apikey", None)?
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| better_auth_core::id::random_id(None));
        let _ = fields.insert("id".into(), id.into());
        Some(ApiKey::from_field_values(fields)?)
    };
    if config.storage == ApiKeyStorage::SecondaryStorage {
        let key = key.as_ref().ok_or_else(|| {
            AuthError::internal("Cannot read properties of null (reading 'expiresAt')")
        })?;
        put(
            required_backend(config, ctx)?.clone(),
            key,
            config.fallback_to_database,
        )
        .await?;
    }
    Ok(key)
}

pub(super) async fn update(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    mut key: ApiKey,
    update: FieldMap,
) -> AuthResult<ApiKey> {
    if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
        key = match ctx.database.update_api_key_record(&key.id, update).await? {
            Some(updated) => ApiKey::from_field_values(updated)?,
            // Upstream adapter.update returns null when a row disappears after the ownership lookup.
            None => return Ok(key),
        };
    } else {
        let mut fields = key.field_values()?;
        fields.extend(update);
        let _ = fields.insert("updatedAt".into(), now().into());
        key = ApiKey::from_field_values(fields)?;
    }
    if config.storage == ApiKeyStorage::SecondaryStorage {
        put(
            required_backend(config, ctx)?.clone(),
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
            required_backend(config, ctx)?.clone(),
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
    better_auth_core::background::run_in_background_with_error_message(
        better_auth_core::background::BackgroundFuture::new(async move {
            if config.storage == ApiKeyStorage::SecondaryStorage {
                let storage = storage.ok_or_else(|| {
                    AuthError::internal(
                        "Secondary storage is required when storage mode is 'secondary-storage'",
                    )
                })?;
                remove_cached(storage, &key, config.fallback_to_database).await?;
            }
            if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
                database.delete_api_key(&key.id).await?;
            }
            Ok(())
        }),
        ctx.config.advanced.background_tasks.as_ref(),
        ctx.logger(),
        "Deferred update failed:",
    )
    .await
}

pub(super) async fn list_groups(
    configurations: &[&ApiKeyConfig],
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    reference: &FieldValue,
    sort: Option<(&str, &str)>,
) -> AuthResult<Vec<FieldValue>> {
    let configurations = configurations
        .iter()
        .map(|config| (*config).clone())
        .collect::<Vec<_>>();
    let ctx = ctx.clone();
    let reference = reference.clone();
    let sort = sort.map(|(field, direction)| (field.to_owned(), direction.to_owned()));
    concurrent::retain("API key cache list", move |reporter| async move {
        let sort = sort
            .as_ref()
            .map(|(field, direction)| (field.as_str(), direction.as_str()));
        let groups = futures_util::future::join_all(
            configurations
                .iter()
                .map(|config| list_in_batch(config, &ctx, &reference, sort, &reporter)),
        )
        .await
        .into_iter()
        .collect::<Option<Vec<_>>>()?;
        Some(groups.into_iter().flatten().collect())
    })
    .await
}

#[cfg(test)]
pub(super) async fn list(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    reference: &str,
    sort: Option<(&str, &str)>,
) -> AuthResult<Vec<FieldValue>> {
    list_groups(&[config], ctx, &reference.into(), sort).await
}

async fn list_in_batch(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    reference: &FieldValue,
    sort: Option<(&str, &str)>,
    reporter: &FailureReporter,
) -> Option<Vec<FieldValue>> {
    // A failed group stops its own workers; independent groups keep running.
    let batch = StorageBatch::new(reporter);
    let storage = backend(config, ctx);
    let reference_key = batch.observe(
        storage
            .filter(|_| config.storage == ApiKeyStorage::SecondaryStorage)
            .map(|_| cache_key("api-key:by-ref:", reference))
            .transpose(),
    )?;
    if config.storage == ApiKeyStorage::SecondaryStorage {
        if let (Some(storage), Some(reference_key)) = (storage, reference_key.as_ref()) {
            let ids = batch.observe(reference::read(storage.clone(), reference_key).await)?;
            if !config.fallback_to_database || batch.observe(reference::has_entries(&ids))? {
                let mut keys = match batch.observe(reference::items(&ids))? {
                    reference::Items::Complete(values) => values,
                    reference::Items::Indexed { count, concurrency } => {
                        let indices = std::iter::successors(Some(0.0), |index| Some(index + 1.0))
                            .take_while(|index| *index < count);
                        let mut results = stream::iter(indices)
                            .take_while(|_| future::ready(!batch.failed()))
                            .map(|index| {
                                let batch = &batch;
                                let ids = &ids;
                                async move {
                                    let result = async {
                                        let id = list_field(
                                            ids,
                                            &better_auth_core::schema_value::number_string(index),
                                        )?;
                                        cached_native_fields(
                                            storage.clone(),
                                            &cache_key("api-key:by-id:", &id)?,
                                        )
                                        .await
                                    }
                                    .await;
                                    batch.observe(result).map(|key| (index, key))
                                }
                            })
                            .buffer_unordered(concurrency)
                            .collect::<Vec<_>>()
                            .await
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>();
                        if batch.failed() {
                            return None;
                        }
                        results.sort_unstable_by(|(left, _), (right, _)| left.total_cmp(right));
                        results
                            .into_iter()
                            .filter_map(|(_, key)| key)
                            .map(FieldValue::from)
                            .collect()
                    }
                };
                keys.retain(|key| !key.is_null() && !key.is_undefined());
                if let Some((field, direction)) = sort {
                    batch.observe(sort_keys(&mut keys, field, Some(direction)))?;
                }
                return Some(keys);
            }
        }
        if !config.fallback_to_database {
            return Some(Vec::new());
        }
    }
    let (keys, total) = tokio::join!(
        ctx.database
            .find_api_keys_by_reference_value(reference, sort)
            .map(|result| batch.observe(result)),
        ctx.database
            .count_api_keys_by_reference_value(reference)
            .map(|result| batch.observe(result)),
    );
    let mut keys = keys?;
    // The public endpoint recomputes total from these rows, but upstream still
    // performs the adapter count and propagates a failure from that operation.
    let _ = total?;
    if config.storage == ApiKeyStorage::SecondaryStorage
        && !keys.is_empty()
        && let Some(storage) = storage
        && let Some(reference_key) = reference_key
    {
        let mut results = stream::iter(keys.into_iter().enumerate())
            .take_while(|_| future::ready(!batch.failed()))
            .map(|(index, key)| {
                let batch = &batch;
                async move {
                    let result = put_in_batch(storage.clone(), &key, true, batch).await;
                    result.map(|()| (index, key))
                }
            })
            .buffer_unordered(STORAGE_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if batch.failed() {
            return None;
        }
        results.sort_unstable_by_key(|(index, _)| *index);
        keys = results.into_iter().map(|(_, key)| key).collect();
        let ids: FieldValue = keys
            .iter()
            .map(|key| key.id.field_value())
            .collect::<Vec<_>>()
            .into();
        batch.observe(
            batch
                .observe(storage.clone().invoke_set_native(
                    reference_key,
                    batch.observe(ids.stringify_native())?,
                    None,
                ))?
                .await,
        )?;
    }
    batch.observe(
        keys.into_iter()
            .map(|key| key.field_values().map(FieldValue::from))
            .collect(),
    )
}

fn sort_keys(keys: &mut [FieldValue], sort_by: &str, direction: Option<&str>) -> AuthResult<()> {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let ascending = direction.filter(|value| !value.is_empty()).unwrap_or("asc") == "asc";
    better_auth_core::query::sort_by(keys, |left, right| {
        let left = list_field(left, sort_by)?;
        let right = list_field(right, sort_by)?;
        let ordering = match (&left, &right) {
            (
                FieldValue::Null | FieldValue::Undefined,
                FieldValue::Null | FieldValue::Undefined,
            ) => Equal,
            (FieldValue::Null | FieldValue::Undefined, _) => Less,
            (_, FieldValue::Null | FieldValue::Undefined) => Greater,
            _ if better_auth_core::query::field_compare(&left, &right)? == Some(Less) => Less,
            _ if better_auth_core::query::field_compare(&left, &right)? == Some(Greater) => Greater,
            _ => Equal,
        };
        Ok(if ascending {
            ordering
        } else {
            ordering.reverse()
        })
    })
}

pub(super) fn deduplicate(keys: &mut Vec<FieldValue>) -> AuthResult<()> {
    let mut ids = Vec::new();
    let mut unique = Vec::with_capacity(keys.len());
    for key in keys.drain(..) {
        let id = list_field(&key, "id")?;
        if ids
            .iter()
            .any(|seen: &FieldValue| seen.same_value_zero(&id))
        {
            continue;
        }
        ids.push(id);
        unique.push(key);
    }
    *keys = unique;
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
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
            let key = deserialize(Some(FieldValue::String(cached.to_string())))
                .ok_or_else(|| AuthError::internal("The nullable cache entry must decode"))?;
            assert_eq!(key.enabled.field_value(), expected);
            assert_eq!(key.rate_limit_enabled.field_value(), expected);
            assert_eq!(key.enabled.is_truthy()?, truthy);
            assert_eq!(key.rate_limit_enabled.is_truthy()?, truthy);
            let serialized = serialize(&key)?;
            let stored: Value = serde_json::from_str(&serialized.decode::<String>()?)?;
            let restored = deserialize(Some(serialized))
                .ok_or_else(|| AuthError::internal("The serialized cache entry must decode"))?;
            assert_eq!(restored.enabled.field_value(), expected);
            assert_eq!(restored.rate_limit_enabled.field_value(), expected);
            let view = serde_json::to_value(ApiKeyView::try_from_api_key(&restored)?)?;
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
        let key = deserialize(Some(FieldValue::String(cached.into()))).unwrap();
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
            serde_json::from_str(&serialized.decode::<String>().unwrap()).unwrap();
        assert_eq!(fields.get("start").unwrap().get(), r#""\ud83d""#);
        assert_eq!(
            fields.get("metadata").unwrap().get(),
            r#"{"purpose":"device"}"#
        );
        let restored = deserialize(Some(serialized)).unwrap();
        assert_eq!(restored.start, key.start);
        assert_eq!(restored.metadata, key.metadata);
        assert!(deserialize(Some(FieldValue::String("malformed".into()))).is_none());
    }
}
