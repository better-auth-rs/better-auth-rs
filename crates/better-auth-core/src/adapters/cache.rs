use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::{AuthError, AuthResult};

/// Cache adapter trait for session caching
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
    expires_at: DateTime<Utc>,
}

impl MemoryCacheAdapter {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Clean up expired entries
    fn cleanup_expired(&self) {
        let mut data = self.data.lock().unwrap();
        let now = Utc::now();
        data.retain(|_, entry| entry.expires_at > now);
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
            expires_at,
        };
        
        let mut data = self.data.lock().unwrap();
        data.insert(key.to_string(), entry);
        
        Ok(())
    }
    
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cleanup_expired();
        
        let data = self.data.lock().unwrap();
        let now = Utc::now();
        
        if let Some(entry) = data.get(key) {
            if entry.expires_at > now {
                Ok(Some(entry.value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    async fn delete(&self, key: &str) -> AuthResult<()> {
        let mut data = self.data.lock().unwrap();
        data.remove(key);
        Ok(())
    }
    
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cleanup_expired();
        
        let data = self.data.lock().unwrap();
        let now = Utc::now();
        
        if let Some(entry) = data.get(key) {
            Ok(entry.expires_at > now)
        } else {
            Ok(false)
        }
    }
    
    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
        let mut data = self.data.lock().unwrap();
        
        if let Some(entry) = data.get_mut(key) {
            entry.expires_at = Utc::now() + expires_in;
        }
        
        Ok(())
    }
    
    async fn clear(&self) -> AuthResult<()> {
        let mut data = self.data.lock().unwrap();
        data.clear();
        Ok(())
    }
}

#[cfg(feature = "redis-cache")]
pub mod redis_adapter {
    use super::*;
    use redis::{Client, Connection, Commands};
    
    pub struct RedisAdapter {
        client: Client,
    }
    
    impl RedisAdapter {
        pub async fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
            let client = Client::open(redis_url)?;
            Ok(Self { client })
        }
    }
    
    #[async_trait]
    impl CacheAdapter for RedisAdapter {
        async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
            let mut conn = self.client.get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {}", e)))?;
            
            let seconds = expires_in.num_seconds() as u64;
            conn.set_ex(key, value, seconds)
                .map_err(|e| AuthError::internal(format!("Redis set error: {}", e)))?;
            
            Ok(())
        }
        
        async fn get(&self, key: &str) -> AuthResult<Option<String>> {
            let mut conn = self.client.get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {}", e)))?;
            
            let result: Option<String> = conn.get(key)
                .map_err(|e| AuthError::internal(format!("Redis get error: {}", e)))?;
            
            Ok(result)
        }
        
        async fn delete(&self, key: &str) -> AuthResult<()> {
            let mut conn = self.client.get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {}", e)))?;
            
            conn.del(key)
                .map_err(|e| AuthError::internal(format!("Redis delete error: {}", e)))?;
            
            Ok(())
        }
        
        async fn exists(&self, key: &str) -> AuthResult<bool> {
            let mut conn = self.client.get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {}", e)))?;
            
            let exists: bool = conn.exists(key)
                .map_err(|e| AuthError::internal(format!("Redis exists error: {}", e)))?;
            
            Ok(exists)
        }
        
        async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
            let mut conn = self.client.get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {}", e)))?;
            
            let seconds = expires_in.num_seconds() as u64;
            conn.expire(key, seconds)
                .map_err(|e| AuthError::internal(format!("Redis expire error: {}", e)))?;
            
            Ok(())
        }
        
        async fn clear(&self) -> AuthResult<()> {
            let mut conn = self.client.get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {}", e)))?;
            
            redis::cmd("FLUSHDB").execute(&mut conn);
            
            Ok(())
        }
    }
}

#[cfg(feature = "redis-cache")]
pub use redis_adapter::RedisAdapter; 