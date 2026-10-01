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
    /// Idle duration after the last allowed request before the counter resets.
    pub window: Duration,

    /// Maximum number of requests allowed within the window.
    pub max_requests: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default: EndpointRateLimit {
                window: Duration::from_secs(60),
                max_requests: 100,
            },
            per_endpoint: HashMap::new(),
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
        _ = self.per_endpoint.insert(
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

/// In-memory rate limiter with a counter that resets after an idle window.
///
/// For production use with multiple instances, a `CacheAdapter`-backed
/// implementation should be used instead. This implementation is suitable
/// for single-process deployments and testing.
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    ip_address: crate::config::IpAddressConfig,
    /// Keyed by (client_identifier, path).
    buckets: Mutex<HashMap<String, RateLimitBucket>>,
}

struct RateLimitBucket {
    count: u32,
    last_request: Instant,
}

impl RateLimitBucket {
    fn consume(&mut self, now: Instant, limit: &EndpointRateLimit) -> Option<u64> {
        let elapsed = now.duration_since(self.last_request);
        if self.count == 0 || elapsed >= limit.window {
            self.count = 1;
        } else if self.count >= limit.max_requests {
            let remaining = limit.window - elapsed;
            return Some(
                remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() != 0)),
            );
        } else {
            self.count += 1;
        }
        self.last_request = now;
        None
    }
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_address: crate::config::IpAddressConfig::default(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Use the same client-address policy as session creation and HTTP plugins.
    pub fn ip_address_config(mut self, config: crate::config::IpAddressConfig) -> Self {
        self.ip_address = config;
        self
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
        if !self.config.enabled || self.ip_address.disable_ip_tracking {
            return Ok(None);
        }

        let limit = self.limit_for_path(&req.path);
        let ip = self.ip_address.resolve(req);
        let key = format!("{}|{}", ip.as_deref().unwrap_or("no-trusted-ip"), req.path);
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_| crate::error::AuthError::internal("Rate-limit lock poisoned"))?;
        let bucket = buckets.entry(key).or_insert(RateLimitBucket {
            count: 0,
            last_request: now,
        });
        if let Some(retry_after) = bucket.consume(now, limit) {
            return Ok(Some(
                AuthResponse::json(
                    429,
                    &crate::types::ErrorCodeMessageResponse {
                        code: None,
                        message: "Too many requests. Please try again later.".to_string(),
                    },
                )?
                .with_header("content-type", "text/plain;charset=UTF-8")
                .with_header("X-Retry-After", retry_after.to_string()),
            ));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HttpMethod;
    use std::collections::HashMap as StdHashMap;

    #[test]
    fn counter_resets_only_after_idle_window_and_denials_do_not_extend_it() {
        let start = Instant::now();
        let limit = EndpointRateLimit {
            window: Duration::from_secs(2),
            max_requests: 5,
        };
        let mut bucket = RateLimitBucket {
            count: 0,
            last_request: start,
        };
        assert_eq!(bucket.consume(start, &limit), None);
        for _ in 0..4 {
            assert_eq!(
                bucket.consume(start + Duration::from_millis(1300), &limit),
                None
            );
        }
        assert_eq!(
            bucket.consume(start + Duration::from_millis(2200), &limit),
            Some(2)
        );
        assert_eq!(
            bucket.consume(start + Duration::from_millis(3200), &limit),
            Some(1)
        );
        assert_eq!(
            bucket.consume(start + Duration::from_millis(3300), &limit),
            None
        );
        for _ in 0..4 {
            assert_eq!(
                bucket.consume(start + Duration::from_millis(3300), &limit),
                None
            );
        }
        assert_eq!(
            bucket.consume(start + Duration::from_millis(3300), &limit),
            Some(2)
        );
    }

    fn make_request(path: &str, ip: &str) -> AuthRequest {
        let mut headers = StdHashMap::new();
        headers.insert("x-forwarded-for".to_string(), ip.to_string());
        AuthRequest::from_parts(
            HttpMethod::Post,
            path.to_string(),
            headers,
            None,
            StdHashMap::new(),
        )
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_rate_limit_allows_within_limit() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 5);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/sign-in/email", "1.2.3.4");

        for _ in 0..5 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
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

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
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

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
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

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
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
