use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use crate::FieldValue;
use crate::error::{AuthError, AuthResult};

/// Shared secondary storage. Values have no expiration when `ttl_seconds` is absent.
#[async_trait]
pub trait SecondaryStorage: Send + Sync {
    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>>;
    async fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> AuthResult<()> {
        self.set_native(
            &key.into(),
            value,
            ttl_seconds.map(|seconds| seconds as f64),
        )
        .await
    }
    /// Preserve projected keys and numeric TTLs until the backend applies its own storage contract.
    async fn set_native(
        &self,
        key: &FieldValue,
        value: &str,
        ttl_seconds: Option<f64>,
    ) -> AuthResult<()>;
    async fn delete(&self, key: &str) -> AuthResult<()>;
    /// Atomically return and delete a value. Verification consumption requires this guarantee.
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>>;
    /// Atomically increment a counter. Apply the TTL only when the counter does not exist.
    async fn increment(&self, _key: &str, _ttl_seconds: f64) -> AuthResult<f64> {
        Err(AuthError::config(
            "Secondary-storage rate limiting requires SecondaryStorage.increment.",
        ))
    }
}

/// Standalone cache operations; the auth runtime does not install a cache automatically.
#[async_trait]
pub trait CacheAdapter: Send + Sync {
    /// Set a value with expiration
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()>;

    /// Get a value by key
    async fn get(&self, key: &str) -> AuthResult<Option<String>>;

    /// Delete a value by key
    async fn delete(&self, key: &str) -> AuthResult<()>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> AuthResult<bool>;

    /// Set expiration for a key
    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()>;

    /// Clear all cached values
    async fn clear(&self) -> AuthResult<()>;
}

/// In-memory cache adapter for testing and development
pub struct MemoryCacheAdapter {
    data: Arc<Mutex<HashMap<CacheKey, CacheEntry>>>,
}

#[derive(Clone, Debug)]
struct CacheKey(FieldValue);

impl From<&str> for CacheKey {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.same_value_zero(&other.0)
    }
}

impl Eq for CacheKey {}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            FieldValue::Undefined => 0_u8.hash(state),
            FieldValue::Null => 1_u8.hash(state),
            FieldValue::Bool(value) => (2_u8, value).hash(state),
            FieldValue::Number(value) => {
                let bits = if value.is_nan() {
                    f64::NAN.to_bits()
                } else if *value == 0.0 {
                    0
                } else {
                    value.to_bits()
                };
                (3_u8, bits).hash(state);
            }
            FieldValue::String(value) => {
                (4_u8, value.encode_utf16().collect::<Vec<_>>()).hash(state);
            }
            FieldValue::Utf16String(value) => (4_u8, value.as_utf16()).hash(state),
            FieldValue::Date(value) => (5_u8, value.milliseconds().to_bits()).hash(state),
            FieldValue::Array(value) => (6_u8, Arc::as_ptr(value)).hash(state),
            FieldValue::Object(value) => (7_u8, Arc::as_ptr(value)).hash(state),
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: String,
    expires_at: Option<f64>,
}

impl MemoryCacheAdapter {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Clean up expired entries
    fn cleanup_expired(&self) {
        if let Ok(mut data) = self.data.lock() {
            let now = Utc::now().timestamp_millis() as f64;
            data.retain(|_, entry| entry.expires_at.is_none_or(|expires| expires > now));
        }
    }
}

impl Default for MemoryCacheAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheAdapter for MemoryCacheAdapter {
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
        self.cleanup_expired();

        let expires_at =
            Utc::now().timestamp_millis() as f64 + expires_in.num_milliseconds() as f64;
        let entry = CacheEntry {
            value: value.to_string(),
            expires_at: Some(expires_at),
        };

        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.insert(key.into(), entry);

        Ok(())
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now().timestamp_millis() as f64;

        if let Some(entry) = data.get(&CacheKey::from(key)) {
            if entry.expires_at.is_none_or(|expires| expires > now) {
                Ok(Some(entry.value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.remove(&CacheKey::from(key));
        Ok(())
    }

    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now().timestamp_millis() as f64;

        if let Some(entry) = data.get(&CacheKey::from(key)) {
            Ok(entry.expires_at.is_none_or(|expires| expires > now))
        } else {
            Ok(false)
        }
    }

    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;

        if let Some(entry) = data.get_mut(&CacheKey::from(key)) {
            entry.expires_at =
                Some(Utc::now().timestamp_millis() as f64 + expires_in.num_milliseconds() as f64);
        }

        Ok(())
    }

    async fn clear(&self) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        data.clear();
        Ok(())
    }
}

#[async_trait]
impl SecondaryStorage for MemoryCacheAdapter {
    async fn increment(&self, key: &str, ttl_seconds: f64) -> AuthResult<f64> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now().timestamp_millis() as f64;
        data.retain(|_, entry| entry.expires_at.is_none_or(|expires| expires > now));
        if let Some(entry) = data.get_mut(&CacheKey::from(key)) {
            let count = entry
                .value
                .parse::<i64>()
                .map_err(|error| {
                    AuthError::internal(format!("Invalid secondary counter: {error}"))
                })?
                .checked_add(1)
                .ok_or_else(|| AuthError::internal("Secondary counter overflow"))?;
            entry.value = count.to_string();
            return Ok(count as f64);
        }
        let expires_at = now + ttl_seconds * 1_000.0;
        let _ = data.insert(
            key.into(),
            CacheEntry {
                value: "1".to_owned(),
                expires_at: Some(expires_at),
            },
        );
        Ok(1.0)
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        Ok(data
            .remove(&CacheKey::from(key))
            .filter(|entry| {
                entry
                    .expires_at
                    .is_none_or(|expires| expires > Utc::now().timestamp_millis() as f64)
            })
            .map(|entry| serde_json::Value::String(entry.value)))
    }

    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        CacheAdapter::get(self, key)
            .await
            .map(|value| value.map(serde_json::Value::String))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &str,
        ttl_seconds: Option<f64>,
    ) -> AuthResult<()> {
        let expires_at =
            ttl_seconds.map(|seconds| Utc::now().timestamp_millis() as f64 + seconds * 1_000.0);
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.insert(
            CacheKey(key.clone()),
            CacheEntry {
                value: value.to_owned(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        CacheAdapter::delete(self, key).await
    }
}

#[cfg(feature = "redis-cache")]
pub mod redis_adapter {
    use super::*;
    use crate::error::AuthError;
    use redis::{AsyncCommands, Client, aio::ConnectionManager};

    /// Standalone Redis cache. Authentication sessions do not use this adapter automatically.
    #[derive(Clone)]
    pub struct RedisAdapter {
        connection: ConnectionManager,
    }

    impl RedisAdapter {
        /// Connect to Redis using Tokio without blocking the executor.
        pub async fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
            let connection = Client::open(redis_url)?.get_connection_manager().await?;
            Ok(Self { connection })
        }
    }

    #[async_trait]
    impl CacheAdapter for RedisAdapter {
        async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
            let seconds = u64::try_from(expires_in.num_seconds())
                .map_err(|_| AuthError::validation("Redis set_ex requires non-negative TTL"))?;
            let mut connection = self.connection.clone();
            connection.set_ex::<_, _, ()>(key, value, seconds).await?;
            Ok(())
        }

        async fn get(&self, key: &str) -> AuthResult<Option<String>> {
            Ok(self.connection.clone().get(key).await?)
        }

        async fn delete(&self, key: &str) -> AuthResult<()> {
            let _: usize = self.connection.clone().del(key).await?;
            Ok(())
        }

        async fn exists(&self, key: &str) -> AuthResult<bool> {
            Ok(self.connection.clone().exists(key).await?)
        }

        async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
            let _: bool = self
                .connection
                .clone()
                .expire(key, expires_in.num_seconds())
                .await?;
            Ok(())
        }

        /// Remove every key from the selected Redis database.
        async fn clear(&self) -> AuthResult<()> {
            redis::cmd("FLUSHDB")
                .query_async::<()>(&mut self.connection.clone())
                .await?;
            Ok(())
        }
    }

    #[async_trait]
    impl SecondaryStorage for RedisAdapter {
        async fn increment(&self, key: &str, ttl_seconds: f64) -> AuthResult<f64> {
            let milliseconds = (ttl_seconds * 1000.0).ceil();
            let milliseconds = if milliseconds.is_finite() {
                milliseconds.max(0.0)
            } else {
                milliseconds
            };
            // SET validates the expiration before creating the counter; Lua errors do not roll back writes.
            let count: i64 = redis::cmd("EVAL")
                .arg(
                    "if redis.call('EXISTS', KEYS[1]) == 1 then return redis.call('INCR', KEYS[1]) end\n\
                     if ARGV[1] == '0' then return 1 end\n\
                     redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])\n\
                     return 1",
                )
                .arg(1)
                .arg(key)
                .arg(milliseconds.to_string())
                .query_async(&mut self.connection.clone())
                .await?;
            Ok(count as f64)
        }

        async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
            let mut connection = self.connection.clone();
            let value: Option<String> = redis::cmd("GETDEL")
                .arg(key)
                .query_async(&mut connection)
                .await?;
            Ok(value.map(serde_json::Value::String))
        }

        async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
            CacheAdapter::get(self, key)
                .await
                .map(|value| value.map(serde_json::Value::String))
        }

        async fn set_native(
            &self,
            key: &FieldValue,
            value: &str,
            ttl_seconds: Option<f64>,
        ) -> AuthResult<()> {
            let mut connection = self.connection.clone();
            let key = String::from_utf16_lossy(key.display_utf16()?.as_utf16());
            let mut command = redis::cmd("SET");
            command.arg(key).arg(value);
            if let Some(seconds) = ttl_seconds {
                command
                    .arg("EX")
                    .arg(crate::schema_value::number_string(seconds));
            }
            command.query_async::<()>(&mut connection).await?;
            Ok(())
        }

        async fn delete(&self, key: &str) -> AuthResult<()> {
            CacheAdapter::delete(self, key).await
        }
    }
}

#[cfg(feature = "redis-cache")]
pub use redis_adapter::RedisAdapter;

#[cfg(test)]
mod tests {
    use super::{CacheAdapter, MemoryCacheAdapter, SecondaryStorage};

    #[cfg(feature = "redis-cache")]
    #[tokio::test]
    #[ignore = "Requires REDIS_TEST_URL for a disposable Redis 7+ instance"]
    async fn redis_counters_create_atomically_and_preserve_the_initial_expiration() {
        use super::RedisAdapter;
        use redis::AsyncCommands;

        let url = std::env::var("REDIS_TEST_URL").expect("Set REDIS_TEST_URL");
        let cache = RedisAdapter::new(&url).await.unwrap();
        let mut connection = redis::Client::open(url)
            .unwrap()
            .get_connection_manager()
            .await
            .unwrap();
        let key = format!("rate-limit-regression:{}", uuid::Uuid::new_v4());
        for ttl in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MAX] {
            assert!(cache.increment(&key, ttl).await.is_err());
            assert!(!connection.exists::<_, bool>(&key).await.unwrap());
        }
        for ttl in [0.0, -0.5] {
            assert_eq!(cache.increment(&key, ttl).await.unwrap(), 1.0);
            assert!(!connection.exists::<_, bool>(&key).await.unwrap());
        }

        assert_eq!(cache.increment(&key, 60.5).await.unwrap(), 1.0);
        let expiration: i64 = redis::cmd("PEXPIRETIME")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(expiration > 0);
        let mut increments = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let key = key.clone();
            increments.spawn(async move { cache.increment(&key, f64::NAN).await.unwrap() as i64 });
        }
        let mut counts = Vec::new();
        while let Some(result) = increments.join_next().await {
            counts.push(result.unwrap());
        }
        counts.sort_unstable();
        assert_eq!(counts, (2..=17).collect::<Vec<_>>());
        assert_eq!(
            redis::cmd("PEXPIRETIME")
                .arg(&key)
                .query_async::<i64>(&mut connection)
                .await
                .unwrap(),
            expiration
        );
        assert_eq!(connection.get::<_, i64>(&key).await.unwrap(), 17);
        let _: bool = connection.pexpire(&key, 0).await.unwrap();
        assert_eq!(cache.increment(&key, 0.5).await.unwrap(), 1.0);
        assert!(connection.pttl::<_, i64>(&key).await.unwrap() > 0);
        SecondaryStorage::delete(&cache, &key).await.unwrap();
    }

    #[tokio::test]
    async fn secondary_counters_are_atomic_and_preserve_the_initial_expiration() {
        let cache = std::sync::Arc::new(MemoryCacheAdapter::new());
        SecondaryStorage::set(cache.as_ref(), "counter", "0", Some(60))
            .await
            .unwrap();
        let expires_at = cache.data.lock().unwrap()[&super::CacheKey::from("counter")].expires_at;
        let mut increments = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let cache = cache.clone();
            increments
                .spawn(async move { cache.increment("counter", 3600.0).await.unwrap() as i64 });
        }
        let mut counts = Vec::new();
        while let Some(result) = increments.join_next().await {
            counts.push(result.unwrap());
        }
        counts.sort_unstable();
        assert_eq!(counts, (1..=16).collect::<Vec<_>>());
        assert_eq!(
            cache.data.lock().unwrap()[&super::CacheKey::from("counter")].expires_at,
            expires_at
        );
        assert_eq!(
            CacheAdapter::get(cache.as_ref(), "counter").await.unwrap(),
            Some("16".to_owned())
        );
        SecondaryStorage::set(cache.as_ref(), "counter", "16", Some(0))
            .await
            .unwrap();
        assert_eq!(cache.increment("counter", 0.5).await.unwrap(), 1.0);
        assert_eq!(cache.increment("counter", 0.0).await.unwrap(), 2.0);
    }

    #[tokio::test]
    async fn secondary_storage_uses_optional_ttl_and_shares_the_cache_backend() {
        let cache = MemoryCacheAdapter::new();
        SecondaryStorage::set(&cache, "entry", "expired", Some(0))
            .await
            .unwrap();
        assert!(
            SecondaryStorage::get(&cache, "entry")
                .await
                .unwrap()
                .is_none()
        );
        SecondaryStorage::set(&cache, "entry", "persistent", None)
            .await
            .unwrap();
        assert_eq!(
            CacheAdapter::get(&cache, "entry").await.unwrap().as_deref(),
            Some("persistent")
        );
        CacheAdapter::delete(&cache, "entry").await.unwrap();
        assert!(
            SecondaryStorage::get(&cache, "entry")
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn concurrent_secondary_consumers_receive_one_value() {
        let cache = std::sync::Arc::new(MemoryCacheAdapter::new());
        SecondaryStorage::set(cache.as_ref(), "one-time", "value", None)
            .await
            .unwrap();
        let mut consumers = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let cache = cache.clone();
            consumers.spawn(async move {
                SecondaryStorage::get_and_delete(cache.as_ref(), "one-time")
                    .await
                    .unwrap()
            });
        }
        let mut received = Vec::new();
        while let Some(result) = consumers.join_next().await {
            if let Some(value) = result.unwrap() {
                received.push(value);
            }
        }
        assert_eq!(received, vec![serde_json::Value::String("value".into())]);
        SecondaryStorage::set(cache.as_ref(), "expired", "value", Some(0))
            .await
            .unwrap();
        assert!(
            SecondaryStorage::get_and_delete(cache.as_ref(), "expired")
                .await
                .unwrap()
                .is_none()
        );
    }
}
