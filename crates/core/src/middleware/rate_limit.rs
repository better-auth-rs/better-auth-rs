use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::Middleware;
use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse};

/// Configuration for the rate limiting middleware.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default rate limit applied to all endpoints.
    pub default: EndpointRateLimit,

    /// Per-endpoint overrides. Key is the path (e.g. "/sign-in/email").
    pub per_endpoint: HashMap<String, EndpointRateLimit>,

    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

/// Rate limit parameters for a single endpoint.
#[derive(Debug, Clone)]
pub struct EndpointRateLimit {
    /// Sliding window duration.
    pub window: Duration,

    /// Maximum number of requests allowed within the window.
    pub max_requests: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut per_endpoint = HashMap::new();

        // Stricter limits for sign-in endpoints (10 req/min)
        let sign_in_limit = EndpointRateLimit {
            window: Duration::from_secs(60),
            max_requests: 10,
        };
        per_endpoint.insert("/sign-in/email".to_string(), sign_in_limit.clone());
        per_endpoint.insert("/sign-in/username".to_string(), sign_in_limit);

        // Stricter limits for sign-up and forget-password (5 req/min)
        let strict_limit = EndpointRateLimit {
            window: Duration::from_secs(60),
            max_requests: 5,
        };
        per_endpoint.insert("/sign-up/email".to_string(), strict_limit.clone());
        per_endpoint.insert("/forget-password".to_string(), strict_limit);

        Self {
            default: EndpointRateLimit {
                window: Duration::from_secs(60),
                max_requests: 100,
            },
            per_endpoint,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default_limit(mut self, window: Duration, max_requests: u32) -> Self {
        self.default = EndpointRateLimit {
            window,
            max_requests,
        };
        self
    }

    pub fn endpoint(
        mut self,
        path: impl Into<String>,
        window: Duration,
        max_requests: u32,
    ) -> Self {
        self.per_endpoint.insert(
            path.into(),
            EndpointRateLimit {
                window,
                max_requests,
            },
        );
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// In-memory sliding-window rate limiter.
///
/// For production use with multiple instances, a `CacheAdapter`-backed
/// implementation should be used instead. This implementation is suitable
/// for single-process deployments and testing.
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    /// Keyed by (client_identifier, path) → list of request timestamps.
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Derive a client key from the request. Uses X-Forwarded-For, then
    /// falls back to a fixed key (single-bucket) when no IP is available.
    fn client_key(req: &AuthRequest) -> String {
        req.headers
            .get("x-forwarded-for")
            .or_else(|| req.headers.get("x-real-ip"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn limit_for_path(&self, path: &str) -> &EndpointRateLimit {
        self.config
            .per_endpoint
            .get(path)
            .unwrap_or(&self.config.default)
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let limit = self.limit_for_path(&req.path);
        let key = format!("{}:{}", Self::client_key(req), req.path);
        let now = Instant::now();
        let window = limit.window;

        let mut buckets = self.buckets.lock().unwrap();
        let timestamps = buckets.entry(key).or_default();

        // Remove timestamps outside the window
        timestamps.retain(|&t| now.duration_since(t) < window);

        if timestamps.len() as u32 >= limit.max_requests {
            let retry_after = timestamps
                .first()
                .map(|&t| {
                    window
                        .as_secs()
                        .saturating_sub(now.duration_since(t).as_secs())
                })
                .unwrap_or(window.as_secs());

            return Ok(Some(
                AuthResponse::json(
                    429,
                    &crate::types::RateLimitErrorResponse {
                        code: "RATE_LIMIT_EXCEEDED",
                        message: "Too many requests",
                        retry_after,
                    },
                )?
                .with_header("Retry-After", retry_after.to_string()),
            ));
        }

        timestamps.push(now);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HttpMethod;
    use std::collections::HashMap as StdHashMap;

    fn make_request(path: &str, ip: &str) -> AuthRequest {
        let mut headers = StdHashMap::new();
        headers.insert("x-forwarded-for".to_string(), ip.to_string());
        AuthRequest {
            method: HttpMethod::Post,
            path: path.to_string(),
            headers,
            body: None,
            query: StdHashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_allows_within_limit() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 5);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/sign-in/email", "1.2.3.4");

        for _ in 0..5 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_over_limit() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 3);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/sign-in/email", "1.2.3.4");

        for _ in 0..3 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }

        let resp = mw.before_request(&req).await.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status, 429);
    }

    #[tokio::test]
    async fn test_rate_limit_per_client() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 2);
        let mw = RateLimitMiddleware::new(config);

        let req_a = make_request("/sign-in/email", "1.1.1.1");
        let req_b = make_request("/sign-in/email", "2.2.2.2");

        // Client A uses up its limit
        for _ in 0..2 {
            assert!(mw.before_request(&req_a).await.unwrap().is_none());
        }
        assert!(mw.before_request(&req_a).await.unwrap().is_some());

        // Client B should still be allowed
        assert!(mw.before_request(&req_b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_rate_limit_per_endpoint_override() {
        let config = RateLimitConfig::new()
            .default_limit(Duration::from_secs(60), 100)
            .endpoint("/sign-in/email", Duration::from_secs(60), 2);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/sign-in/email", "1.2.3.4");

        for _ in 0..2 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
        assert!(mw.before_request(&req).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let config = RateLimitConfig::new()
            .default_limit(Duration::from_secs(60), 1)
            .enabled(false);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/sign-in/email", "1.2.3.4");

        for _ in 0..10 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
    }
}
