mod fields;

use async_trait::async_trait;
use chrono::Utc;

use super::{EphemeralStore, rows::RowRef};
use crate::store::schema::EntityRole;
use crate::store::{ApiKeyStore, ApiKeyUsageWrite};
use crate::{
    ApiKey, AuthError, AuthResult, CreateApiKey, FieldDate, FieldValue, FromFieldMap, UpdateApiKey,
};

fn now() -> FieldDate {
    Utc::now().into()
}

#[async_trait]
impl ApiKeyStore for EphemeralStore {
    async fn create_api_key_record(&self, input: crate::FieldMap) -> AuthResult<crate::FieldMap> {
        self.create_plugin_record(EntityRole::ApiKey, input, Default::default())
            .await
    }

    async fn get_api_key_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.get_plugin_record(EntityRole::ApiKey, id).await
    }

    async fn update_api_key_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.update_plugin_record(EntityRole::ApiKey, id, input, Default::default())
            .await
    }

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let created_at = now();
        let mut fields = input.into_adapter_fields()?;
        fields.extend([
            ("createdAt".into(), created_at.clone().into()),
            ("updatedAt".into(), created_at.into()),
            ("lastRefillAt".into(), FieldValue::Null),
            ("lastRequest".into(), FieldValue::Null),
        ]);
        ApiKey::from_field_values(self.create_api_key_record(fields).await?)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        self.get_api_key_by_id_value(&id.to_owned().into()).await
    }

    async fn get_api_key_by_id_value(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<ApiKey>> {
        self.get_api_key_record(id)
            .await?
            .map(ApiKey::from_field_values)
            .transpose()
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::ApiKey);
        let column = schema.record_storage_key("key");
        let value = self.plugin_query_value(EntityRole::ApiKey, "key", hash.into())?;
        self.find_api_key(|row| {
            row.get(column)
                .is_some_and(|actual| actual.strict_equals(&value))
        })
        .await
    }

    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let schema = self
            .model_fields
            .plugin_fields(EntityRole::ApiKey)
            .adapter_fields(&[]);
        let column = schema.record_storage_key("referenceId");
        let reference =
            self.plugin_query_value(EntityRole::ApiKey, "referenceId", reference_id.into())?;
        let rows = self
            .raw("apikey", "findMany", |state| {
                let mut keys: Vec<_> = state
                    .api_keys
                    .select_refs(|key| {
                        key.get(column)
                            .is_some_and(|value| value.strict_equals(&reference))
                    })?
                    .into_iter()
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                if let Some((field, direction)) = sort.filter(|_| keys.len() > 1) {
                    crate::memory_sort::sort(&mut keys, direction == "desc", |(key, _)| {
                        schema
                            .fields()
                            .get(field)
                            .map(|_| {
                                key.get(schema.record_storage_key(field))
                                    .cloned()
                                    .unwrap_or_default()
                            })
                            .ok_or_else(|| {
                                AuthError::config(format!(
                                    "Field {field} not found in model apikey"
                                ))
                            })
                    })?;
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
        let schema = self.model_fields.plugin_fields(EntityRole::ApiKey);
        let column = schema.record_storage_key("referenceId");
        let reference =
            self.plugin_query_value(EntityRole::ApiKey, "referenceId", reference_id.into())?;
        self.raw("apikey", "count", |state| {
            Ok(state
                .api_keys
                .snapshot()?
                .iter()
                .filter(|key| {
                    key.get(column)
                        .is_some_and(|value| value.strict_equals(&reference))
                })
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
        update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        let mut fields = update.into_adapter_fields()?;
        let _ = fields.insert("updatedAt".into(), now().into());
        self.update_api_key_record(id, fields)
            .await?
            .map(ApiKey::from_field_values)
            .transpose()
    }

    async fn write_api_key_usage(
        &self,
        id: &crate::SchemaValue<String>,
        write: ApiKeyUsageWrite,
    ) -> AuthResult<Option<ApiKey>> {
        use crate::query::{field_compare, field_matches_equality};
        let id = self.plugin_query_value(EntityRole::ApiKey, "id", id.field_value())?;
        let query = |name, value| self.plugin_query_value(EntityRole::ApiKey, name, value);
        let previous = match &write {
            ApiKeyUsageWrite::Refill { previous, .. } => query("lastRefillAt", previous.clone())?,
            ApiKeyUsageWrite::StartWindow {
                previous_before, ..
            } => query(
                "lastRequest",
                previous_before.clone().map_or(FieldValue::Null, Into::into),
            )?,
            ApiKeyUsageWrite::IncrementWindow { previous_after, .. } => {
                query("lastRequest", previous_after.clone().into())?
            }
            _ => FieldValue::Undefined,
        };
        let maximum = match &write {
            ApiKeyUsageWrite::Decrement => query("remaining", 0.0.into())?,
            ApiKeyUsageWrite::IncrementWindow { maximum, .. } => {
                query("requestCount", maximum.clone())?
            }
            _ => FieldValue::Undefined,
        };
        let schema = self.model_fields.plugin_fields(EntityRole::ApiKey);
        let fields = if matches!(&write, ApiKeyUsageWrite::Decrement) {
            crate::FieldMap::new()
        } else {
            self.prepare_plugin_fields(EntityRole::ApiKey, write.set_fields(), false)
                .await?
        };
        let row = self
            .raw("apikey", write.operation(), |state| {
                let Some(source) = state.api_keys.first_ref(|key| {
                    crate::query::field_matches_equality(
                        key.get("id").unwrap_or(&FieldValue::Undefined),
                        &id,
                    )
                })?
                else {
                    return Ok(None);
                };
                let wrote = source.write(|key| {
                    let value = |name| {
                        key.get(schema.record_storage_key(name))
                            .cloned()
                            .unwrap_or_default()
                    };
                    let increment = match &write {
                        ApiKeyUsageWrite::Refill { .. } => {
                            if !field_matches_equality(&value("lastRefillAt"), &previous) {
                                return Ok(false);
                            }
                            None
                        }
                        ApiKeyUsageWrite::Decrement => {
                            let remaining = value("remaining");
                            if !field_compare(&remaining, &maximum)?
                                .is_some_and(|order| order.is_gt())
                            {
                                return Ok(false);
                            }
                            Some((
                                "remaining",
                                FieldValue::Number(remaining.as_f64().unwrap_or(0.0) - 1.0),
                            ))
                        }
                        ApiKeyUsageWrite::StartWindow {
                            previous_before, ..
                        } => {
                            let actual = value("lastRequest");
                            let matches = match previous_before {
                                None => field_matches_equality(&actual, &previous),
                                Some(_) => field_compare(&actual, &previous)?
                                    .is_some_and(|order| order.is_le()),
                            };
                            if !matches {
                                return Ok(false);
                            }
                            None
                        }
                        ApiKeyUsageWrite::IncrementWindow { .. } => {
                            let count = value("requestCount");
                            if !field_compare(&value("lastRequest"), &previous)?
                                .is_some_and(|order| order.is_gt())
                                || !field_compare(&count, &maximum)?
                                    .is_some_and(|order| order.is_lt())
                            {
                                return Ok(false);
                            }
                            Some((
                                "requestCount",
                                FieldValue::Number(count.as_f64().unwrap_or(0.0) + 1.0),
                            ))
                        }
                        ApiKeyUsageWrite::LastRequest(_) | ApiKeyUsageWrite::UpdatedAt(_) => None,
                    };
                    if let Some((name, value)) = increment {
                        let _ = key.insert(schema.record_storage_key(name).to_owned(), value);
                    }
                    key.extend(fields);
                    Ok(true)
                })?;
                Ok(wrote.then_some(source))
            })
            .await?;
        self.project_plugin_refs(EntityRole::ApiKey, row.into_iter().collect())
            .await?
            .into_iter()
            .map(ApiKey::from_field_values)
            .next()
            .transpose()
    }

    async fn delete_api_key(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        let id = self.plugin_query_value(EntityRole::ApiKey, "id", id.field_value())?;
        self.raw("apikey", "delete", |state| {
            let _ = state.api_keys.remove_first(|key| {
                crate::query::field_matches_equality(
                    key.get("id").unwrap_or(&FieldValue::Undefined),
                    &id,
                )
            })?;
            Ok(())
        })
        .await
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        self.model_fields.begin_id_query(EntityRole::ApiKey)?;
        let schema = self.model_fields.plugin_fields(EntityRole::ApiKey);
        let column = schema.record_storage_key("expiresAt");
        self.raw("apikey", "deleteMany", |state| {
            let current: FieldValue = now().into();
            let before = state.api_keys.len();
            state.api_keys.try_retain(|key| {
                let value = key.get(column).cloned().unwrap_or_default();
                Ok(value.is_null()
                    || !crate::query::field_compare(&value, &current)?
                        .is_some_and(|order| order.is_lt()))
            })?;
            Ok(before - state.api_keys.len())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    mod enabled;
    mod sorting;
    mod usage_values;

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
            name: None.into(),
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
            enabled: true.into(),
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
        let _ = store
            .lock()
            .unwrap()
            .api_keys
            .find_mut(|row| row.get("id") == Some(&key.id.field_value()))
            .unwrap()
            .unwrap()
            .insert("updatedAt".into(), unchanged.clone().into());
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
                .get_api_key_by_hash(key.key_hash.typed().unwrap())
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
            assert!(allowed.last_request.typed().unwrap().is_some());
            if let Some(refill) = refill.as_ref() {
                assert_eq!(
                    allowed.last_refill_at.typed().unwrap().as_ref(),
                    Some(refill)
                );
            } else {
                refill = allowed.last_refill_at.typed().unwrap().clone();
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
                        previous_after: (at - chrono::Duration::minutes(1)).into(),
                        maximum: 1.0.into(),
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
        assert!(
            stored
                .last_request
                .typed()
                .unwrap()
                .as_ref()
                .unwrap()
                .same_object(&invalid)
        );
    }
}
