mod fields;

use async_trait::async_trait;
use chrono::Utc;

use super::{EphemeralStore, rows::RowRef};
use crate::store::{ApiKeyStore, ApiKeyUsageWrite};
use crate::{ApiKey, AuthError, AuthResult, CreateApiKey, FieldDate, UpdateApiKey};

fn now() -> FieldDate {
    Utc::now().into()
}

#[async_trait]
impl ApiKeyStore for EphemeralStore {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let created_at = now();
        let fields = self
            .model_fields
            .api_key_fields_for_storage(
                Some(input.name.into()),
                input.additional_fields,
                true,
                |field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let mut key = ApiKey {
            additional_fields: fields.additional_fields,
            id: self
                .generated_id("apikey", None, self.lock()?.api_keys.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            name: fields.name.unwrap_or_default(),
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
        };
        let selected = self
            .raw("apikey", "create", |state| {
                self.assign_insert_serial_id(&mut key.id, state.api_keys.len());
                let source = state.api_keys.push_ref(key.clone());
                Ok((key, source))
            })
            .await?;
        Ok(self.project_api_key_refs(vec![selected]).await?.remove(0))
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        self.find_api_key(|row| row.id == id).await
    }

    async fn get_api_key_by_id_value(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<ApiKey>> {
        self.find_api_key(|row| row.id.field_value().strict_equals(&id.field_value()))
            .await
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        self.find_api_key(|row| row.key_hash == hash).await
    }

    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let rows = self
            .raw("apikey", "findMany", |state| {
                let mut keys: Vec<_> = state
                    .api_keys
                    .select_refs(|key| key.reference_id == reference_id)?
                    .into_iter()
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                if let Some(("name", direction)) = sort.filter(|_| keys.len() > 1) {
                    let mut named = keys
                        .into_iter()
                        .map(|key| {
                            let name = if key.0.name.is_undefined() {
                                None
                            } else {
                                key.0.name.typed()?.clone()
                            };
                            Ok((name, key))
                        })
                        .collect::<AuthResult<Vec<_>>>()?;
                    named.sort_by(|a, b| {
                        let order = a.0.cmp(&b.0);
                        if direction == "desc" {
                            order.reverse()
                        } else {
                            order
                        }
                    });
                    keys = named.into_iter().map(|(_, key)| key).collect();
                } else if let Some((field, direction)) = sort.filter(|_| keys.len() > 1) {
                    let compare = comparator(field)?;
                    keys.sort_by(|a, b| {
                        let order = compare(&a.0, &b.0);
                        if direction == "desc" {
                            order.reverse()
                        } else {
                            order
                        }
                    });
                }
                Ok(crate::query::paginate_memory(
                    keys,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.project_api_key_refs(rows).await
    }

    async fn count_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<u64> {
        self.raw("apikey", "count", |state| {
            Ok(state
                .api_keys
                .snapshot()?
                .iter()
                .filter(|key| key.reference_id == reference_id)
                .count() as u64)
        })
        .await
    }

    async fn update_api_key(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<ApiKey> {
        self.update_api_key_optional(id, update)
            .await?
            .ok_or_else(|| AuthError::not_found("API Key not found"))
    }

    async fn update_api_key_optional(
        &self,
        id: &crate::SchemaValue<String>,
        mut update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        let fields = self
            .model_fields
            .api_key_fields_for_storage(
                update.name.take(),
                std::mem::take(&mut update.additional_fields),
                false,
                |field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let row = self
            .raw("apikey", "update", |state| {
                let Some(source) = state
                    .api_keys
                    .first_ref(|key| key.id.field_value().strict_equals(&id.field_value()))?
                else {
                    return Ok(None);
                };
                let snapshot = source.write(|key| {
                    fields.apply(key);
                    macro_rules! optional {
            ($($field:ident),* $(,)?) => {
                $(if let Some(value) = update.$field { key.$field = Some(value); })*
            };
        }
                    optional!(
                        remaining,
                        rate_limit_time_window,
                        rate_limit_max,
                        refill_interval,
                        refill_amount,
                        permissions,
                        metadata,
                        request_count,
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
                    Ok(key.clone())
                })?;
                Ok(Some((snapshot, source)))
            })
            .await?;
        Ok(self
            .project_api_key_refs(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn write_api_key_usage(
        &self,
        id: &crate::SchemaValue<String>,
        write: ApiKeyUsageWrite,
    ) -> AuthResult<Option<ApiKey>> {
        // Upstream does not run update policies for an increment without a set patch.
        let fields = if matches!(&write, ApiKeyUsageWrite::Decrement) {
            Default::default()
        } else {
            self.model_fields
                .api_key_fields_for_storage(None, Default::default(), false, |field, value| {
                    self.memory_plugin_field_input(field, value)
                })
                .await?
        };
        let row = self
            .raw("apikey", write.operation(), |state| {
                let Some(source) = state
                    .api_keys
                    .first_ref(|key| key.id.field_value().strict_equals(&id.field_value()))?
                else {
                    return Ok(None);
                };
                let snapshot = source.write(|key| {
                    match write {
                        ApiKeyUsageWrite::Refill {
                            previous,
                            remaining,
                            at,
                        } => {
                            let actual = key.last_refill_at.as_ref().map(FieldDate::milliseconds);
                            if actual != previous.map(|date| date.timestamp_millis() as f64) {
                                return Ok(None);
                            }
                            key.remaining = Some(remaining);
                            key.last_refill_at = Some(at.into());
                        }
                        ApiKeyUsageWrite::Decrement => {
                            let Some(remaining) =
                                key.remaining.filter(|remaining| *remaining > 0.0)
                            else {
                                return Ok(None);
                            };
                            key.remaining = Some(remaining - 1.0);
                        }
                        ApiKeyUsageWrite::StartWindow {
                            previous_before,
                            at,
                        } => {
                            let actual = key.last_request.as_ref().map(FieldDate::milliseconds);
                            let matches = match previous_before {
                                None => actual.is_none(),
                                Some(previous) => actual.is_some_and(|actual| {
                                    actual <= previous.timestamp_millis() as f64
                                }),
                            };
                            if !matches {
                                return Ok(None);
                            }
                            key.request_count = Some(1.0);
                            key.last_request = Some(at.into());
                        }
                        ApiKeyUsageWrite::IncrementWindow {
                            previous_after,
                            maximum,
                            at,
                        } => {
                            let actual = key.last_request.as_ref().map(FieldDate::milliseconds);
                            if !actual.is_some_and(|actual| {
                                actual > previous_after.timestamp_millis() as f64
                            }) || key.request_count.unwrap_or(0.0) >= maximum
                            {
                                return Ok(None);
                            }
                            key.request_count = Some(key.request_count.unwrap_or(0.0) + 1.0);
                            key.last_request = Some(at.into());
                        }
                        ApiKeyUsageWrite::LastRequest(at) => {
                            key.last_request = Some(at.into());
                        }
                        ApiKeyUsageWrite::UpdatedAt(at) => {
                            key.updated_at = at.into();
                        }
                    }
                    fields.apply(key);
                    Ok(Some(key.clone()))
                })?;
                Ok(snapshot.map(|snapshot| (snapshot, source)))
            })
            .await?;
        Ok(self
            .project_api_key_refs(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_api_key(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.raw("apikey", "delete", |state| {
            let _ = state.api_keys.remove(id)?;
            Ok(())
        })
        .await
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        self.raw("apikey", "deleteMany", |state| {
            let current = Utc::now().timestamp_millis() as f64;
            let mut expired = Vec::new();
            for key in state.api_keys.snapshot()?.iter() {
                if let Some(expires) = key.expires_at.as_ref()
                    && expires.milliseconds() < current
                {
                    expired.push(key.id.clone());
                }
            }
            for id in &expired {
                let _ = state.api_keys.remove(id)?;
            }
            Ok(expired.len())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConsumeApiKeyResult;

    async fn consume(
        store: &EphemeralStore,
        id: &crate::SchemaValue<String>,
        rate: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let snapshot = store
            .get_api_key_by_id_value(id)
            .await?
            .expect("created key");
        store.consume_api_key_usage(&snapshot, rate).await
    }

    fn input() -> CreateApiKey {
        CreateApiKey {
            additional_fields: Default::default(),
            reference_id: "owner".into(),
            config_id: "default".into(),
            name: None,
            prefix: None,
            key_hash: "stored-hash".into(),
            start: None,
            expires_at: None,
            remaining: Some(3.0),
            rate_limit_enabled: true,
            rate_limit_time_window: Some(60_000.0),
            rate_limit_max: Some(1.0),
            refill_interval: None,
            refill_amount: None,
            permissions: None,
            metadata: None,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn rate_rejection_consumes_quota_without_advancing_the_window_or_updated_at() {
        let store = EphemeralStore::default();
        let key = store.create_api_key(input()).await.unwrap();
        let ConsumeApiKeyResult::Allowed(allowed) = consume(&store, &key.id, true).await.unwrap()
        else {
            panic!("first request must be allowed");
        };
        assert_eq!(allowed.remaining, Some(2.0));
        assert_eq!(allowed.request_count, Some(1.0));
        let unchanged: FieldDate = chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc)
            .into();
        store
            .lock()
            .unwrap()
            .api_keys
            .get_mut(&key.id)
            .unwrap()
            .unwrap()
            .updated_at = unchanged.clone();
        for remaining in [1.0, 0.0] {
            assert!(matches!(
                consume(&store, &key.id, true).await.unwrap(),
                ConsumeApiKeyResult::RateLimited { .. }
            ));
            let stored = store
                .get_api_key_by_id(key.id.typed().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.remaining, Some(remaining));
            assert_eq!(stored.request_count, allowed.request_count);
            assert_eq!(stored.last_request, allowed.last_request);
            assert_eq!(stored.updated_at, unchanged);
        }
        assert!(matches!(
            consume(&store, &key.id, true).await.unwrap(),
            ConsumeApiKeyResult::UsageExhausted
        ));
        assert!(
            store
                .get_api_key_by_hash(&key.key_hash)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn refill_preserves_fractional_quota_and_keeps_the_exhausted_refillable_key() {
        let store = EphemeralStore::default();
        let key = store
            .create_api_key(CreateApiKey {
                remaining: Some(0.0),
                refill_interval: Some(60_000.0),
                refill_amount: Some(1.5),
                ..input()
            })
            .await
            .unwrap();
        store
            .update_api_key(
                &key.id,
                UpdateApiKey {
                    last_refill_at: Some(Some(
                        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")
                            .unwrap()
                            .with_timezone(&Utc)
                            .into(),
                    )),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut refill = None;
        for remaining in [0.5, -0.5] {
            let ConsumeApiKeyResult::Allowed(allowed) =
                consume(&store, &key.id, false).await.unwrap()
            else {
                panic!("positive quota or a due refill must allow a request");
            };
            assert_eq!(allowed.remaining, Some(remaining));
            assert_eq!(allowed.request_count, Some(0.0));
            assert!(allowed.last_request.is_some());
            if let Some(refill) = refill.as_ref() {
                assert_eq!(allowed.last_refill_at.as_ref(), Some(refill));
            } else {
                refill = allowed.last_refill_at.clone();
            }
        }
        assert!(matches!(
            consume(&store, &key.id, false).await.unwrap(),
            ConsumeApiKeyResult::UsageExhausted
        ));
        let stored = store
            .get_api_key_by_id(key.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.remaining, Some(-0.5));
    }

    #[tokio::test]
    async fn invalid_last_request_does_not_match_an_active_rate_window() {
        let store = EphemeralStore::default();
        let key = store.create_api_key(input()).await.unwrap();
        let invalid = FieldDate::invalid();
        store
            .update_api_key(
                &key.id,
                UpdateApiKey {
                    last_request: Some(Some(invalid.clone())),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let at = Utc::now();
        assert!(
            store
                .write_api_key_usage(
                    &key.id,
                    ApiKeyUsageWrite::IncrementWindow {
                        previous_after: at - chrono::Duration::minutes(1),
                        maximum: 1.0,
                        at,
                    },
                )
                .await
                .unwrap()
                .is_none()
        );
        let stored = store
            .get_api_key_by_id_value(&key.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.request_count, Some(0.0));
        assert!(stored.last_request.unwrap().same_object(&invalid));
    }
}

fn comparator(field: &str) -> AuthResult<fn(&ApiKey, &ApiKey) -> std::cmp::Ordering> {
    Ok(match field {
        "id" => |a, b| match (a.id.as_str(), b.id.as_str()) {
            (Some(a), Some(b)) => a.cmp(b),
            _ => std::cmp::Ordering::Equal,
        },
        "start" => |a, b| a.start.cmp(&b.start),
        "prefix" => |a, b| a.prefix.cmp(&b.prefix),
        "referenceId" => |a, b| a.reference_id.cmp(&b.reference_id),
        "configId" => |a, b| a.config_id.cmp(&b.config_id),
        "enabled" => |a, b| a.enabled.cmp(&b.enabled),
        "rateLimitEnabled" => |a, b| a.rate_limit_enabled.cmp(&b.rate_limit_enabled),
        "createdAt" => |a, b| compare_dates(Some(&a.created_at), Some(&b.created_at)),
        "updatedAt" => |a, b| compare_dates(Some(&a.updated_at), Some(&b.updated_at)),
        "expiresAt" => |a, b| compare_dates(a.expires_at.as_ref(), b.expires_at.as_ref()),
        "lastRequest" => |a, b| compare_dates(a.last_request.as_ref(), b.last_request.as_ref()),
        "lastRefillAt" => {
            |a, b| compare_dates(a.last_refill_at.as_ref(), b.last_refill_at.as_ref())
        }
        "permissions" => |a, b| a.permissions.cmp(&b.permissions),
        "metadata" => |a, b| a.metadata.cmp(&b.metadata),
        "key" => |a, b| a.key_hash.cmp(&b.key_hash),
        "remaining" => |a, b| compare_numbers(a.remaining, b.remaining),
        "requestCount" => |a, b| compare_numbers(a.request_count, b.request_count),
        "rateLimitMax" => |a, b| compare_numbers(a.rate_limit_max, b.rate_limit_max),
        "rateLimitTimeWindow" => {
            |a, b| compare_numbers(a.rate_limit_time_window, b.rate_limit_time_window)
        }
        "refillAmount" => |a, b| compare_numbers(a.refill_amount, b.refill_amount),
        "refillInterval" => |a, b| compare_numbers(a.refill_interval, b.refill_interval),
        _ => {
            return Err(AuthError::config(format!(
                "Field {field} not found in model apikey"
            )));
        }
    })
}

fn compare_numbers(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.total_cmp(&right),
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
    }
}

fn compare_dates(left: Option<&FieldDate>, right: Option<&FieldDate>) -> std::cmp::Ordering {
    left.map_or(0.0, FieldDate::milliseconds)
        .partial_cmp(&right.map_or(0.0, FieldDate::milliseconds))
        .unwrap_or(std::cmp::Ordering::Equal)
}
