use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};

use super::EphemeralStore;
use crate::store::{ApiKeyStore, ConsumeApiKeyResult};
use crate::{ApiKey, AuthError, AuthResult, CreateApiKey, UpdateApiKey};

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn timestamp(value: &str) -> AuthResult<i64> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.timestamp_millis())
        .map_err(|error| AuthError::internal(format!("Invalid stored API key timestamp: {error}")))
}

#[async_trait]
impl ApiKeyStore for EphemeralStore {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let created_at = now();
        let key = ApiKey {
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
        };
        let _ = self.lock()?.api_keys.insert(key.id.clone(), key.clone());
        Ok(key)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        Ok(self.lock()?.api_keys.get(id).cloned())
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        Ok(self
            .lock()?
            .api_keys
            .values()
            .find(|key| key.key_hash == hash)
            .cloned())
    }

    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        let mut keys: Vec<_> = self
            .lock()?
            .api_keys
            .values()
            .filter(|key| key.reference_id == reference_id)
            .cloned()
            .collect();
        keys.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(keys)
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let mut state = self.lock()?;
        let key = state
            .api_keys
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("API Key not found"))?;
        macro_rules! optional {
            ($($field:ident),* $(,)?) => {
                $(if let Some(value) = update.$field { key.$field = Some(value); })*
            };
        }
        optional!(
            name,
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
    }

    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let mut state = self.lock()?;
        let mut key = state
            .api_keys
            .get(id)
            .cloned()
            .ok_or_else(|| AuthError::not_found("API Key not found"))?;
        let current = Utc::now();
        let milliseconds = current.timestamp_millis();
        let current = current.to_rfc3339_opts(SecondsFormat::Millis, true);
        if let Some(remaining) = key.remaining {
            if remaining == 0.0 && key.refill_amount.is_none() {
                let _ = state.api_keys.shift_remove(id);
                return Ok(ConsumeApiKeyResult::UsageExhausted);
            }
            if let (Some(interval), Some(amount)) = (key.refill_interval, key.refill_amount)
                && interval != 0.0
                && amount != 0.0
                && (milliseconds
                    - timestamp(key.last_refill_at.as_deref().unwrap_or(&key.created_at))?)
                    as f64
                    > interval
            {
                key.remaining = Some(amount - 1.0);
                key.last_refill_at = Some(current.clone());
            } else if remaining > 0.0 {
                key.remaining = Some(remaining - 1.0);
            } else {
                return Ok(ConsumeApiKeyResult::UsageExhausted);
            }
        }

        if global_rate_limit_enabled && key.rate_limit_enabled {
            if let (Some(window), Some(max)) = (key.rate_limit_time_window, key.rate_limit_max) {
                let elapsed = key
                    .last_request
                    .as_deref()
                    .map(timestamp)
                    .transpose()?
                    .map(|last| (milliseconds - last) as f64);
                if let Some(elapsed) = elapsed
                    && elapsed <= window
                    && key.request_count.unwrap_or(0.0) >= max
                {
                    // The adapter consumes quota before rate rejection but preserves updated_at.
                    let _ = state.api_keys.insert(id.to_owned(), key);
                    return Ok(ConsumeApiKeyResult::RateLimited {
                        try_again_in: (window - elapsed).ceil(),
                    });
                }
                key.request_count = Some(if elapsed.is_none_or(|elapsed| elapsed > window) {
                    1.0
                } else {
                    key.request_count.unwrap_or(0.0) + 1.0
                });
                key.last_request = Some(current.clone());
            }
        } else {
            key.last_request = Some(current.clone());
        }
        key.updated_at = current;
        let _ = state.api_keys.insert(id.to_owned(), key.clone());
        Ok(ConsumeApiKeyResult::Allowed(Box::new(key)))
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        let _ = self.lock()?.api_keys.shift_remove(id);
        Ok(())
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        let mut state = self.lock()?;
        let current = Utc::now().timestamp_millis();
        let mut expired = Vec::new();
        for key in state.api_keys.values() {
            if let Some(expires) = key.expires_at.as_deref()
                && timestamp(expires)? < current
            {
                expired.push(key.id.clone());
            }
        }
        for id in &expired {
            let _ = state.api_keys.shift_remove(id);
        }
        Ok(expired.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> CreateApiKey {
        CreateApiKey {
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
        let ConsumeApiKeyResult::Allowed(allowed) =
            store.consume_api_key_usage(&key.id, true).await.unwrap()
        else {
            panic!("first request must be allowed");
        };
        assert_eq!(allowed.remaining, Some(2.0));
        assert_eq!(allowed.request_count, Some(1.0));
        let unchanged = "2000-01-01T00:00:00.000Z";
        store
            .lock()
            .unwrap()
            .api_keys
            .get_mut(&key.id)
            .unwrap()
            .updated_at = unchanged.into();
        for remaining in [1.0, 0.0] {
            assert!(matches!(
                store.consume_api_key_usage(&key.id, true).await.unwrap(),
                ConsumeApiKeyResult::RateLimited { .. }
            ));
            let stored = store.get_api_key_by_id(&key.id).await.unwrap().unwrap();
            assert_eq!(stored.remaining, Some(remaining));
            assert_eq!(stored.request_count, allowed.request_count);
            assert_eq!(stored.last_request, allowed.last_request);
            assert_eq!(stored.updated_at, unchanged);
        }
        assert!(matches!(
            store.consume_api_key_usage(&key.id, true).await.unwrap(),
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
                    last_refill_at: Some(Some("2000-01-01T00:00:00.000Z".into())),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut refill = None;
        for remaining in [0.5, -0.5] {
            let ConsumeApiKeyResult::Allowed(allowed) =
                store.consume_api_key_usage(&key.id, false).await.unwrap()
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
            store.consume_api_key_usage(&key.id, false).await.unwrap(),
            ConsumeApiKeyResult::UsageExhausted
        ));
        let stored = store.get_api_key_by_id(&key.id).await.unwrap().unwrap();
        assert_eq!(stored.remaining, Some(-0.5));
    }
}
