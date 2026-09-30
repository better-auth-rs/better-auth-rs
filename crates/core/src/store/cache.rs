use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::{AuthError, AuthResult};

/// Shared secondary storage. Values have no expiration when `ttl_seconds` is absent.
#[async_trait]
pub trait SecondaryStorage: Send + Sync {
    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>>;
    async fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> AuthResult<()>;
    async fn delete(&self, key: &str) -> AuthResult<()>;
    /// Atomically return and delete a value. Verification consumption requires this guarantee.
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>>;
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
    data: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: String,
    expires_at: Option<DateTime<Utc>>,
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
            let now = Utc::now();
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

        let expires_at = Utc::now() + expires_in;
        let entry = CacheEntry {
            value: value.to_string(),
            expires_at: Some(expires_at),
        };

        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.insert(key.to_string(), entry);

        Ok(())
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now();

        if let Some(entry) = data.get(key) {
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
        let _ = data.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now();

        if let Some(entry) = data.get(key) {
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

        if let Some(entry) = data.get_mut(key) {
            entry.expires_at = Some(Utc::now() + expires_in);
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
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        Ok(data
            .remove(key)
            .filter(|entry| entry.expires_at.is_none_or(|expires| expires > Utc::now()))
            .map(|entry| serde_json::Value::String(entry.value)))
    }

    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        CacheAdapter::get(self, key)
            .await
            .map(|value| value.map(serde_json::Value::String))
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> AuthResult<()> {
        let expires_at = ttl_seconds
            .map(|seconds| {
                i64::try_from(seconds)
                    .ok()
                    .and_then(Duration::try_seconds)
                    .and_then(|duration| Utc::now().checked_add_signed(duration))
                    .ok_or_else(|| AuthError::validation("Secondary storage TTL is out of range"))
            })
            .transpose()?;
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.insert(
            key.to_owned(),
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

        async fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> AuthResult<()> {
            let mut connection = self.connection.clone();
            if let Some(seconds) = ttl_seconds {
                connection.set_ex::<_, _, ()>(key, value, seconds).await?;
            } else {
                connection.set::<_, _, ()>(key, value).await?;
            }
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
