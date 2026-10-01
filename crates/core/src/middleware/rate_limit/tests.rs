use super::*;
use crate::types::HttpMethod;
use std::{collections::HashMap as StdHashMap, time::Duration};

fn make_request(path: &str, ip: &str) -> AuthRequest {
    let mut headers = StdHashMap::new();
    headers.insert("x-forwarded-for".to_string(), ip.to_string());
    AuthRequest::from_parts(HttpMethod::Post, path.to_string(), headers, None, None)
}

#[tokio::test]
async fn test_rate_limit_allows_within_limit() {
    let config = RateLimitConfig::new()
        .enabled(true)
        .default_limit(Duration::from_secs(60), 5);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/rate-limit/within", "1.2.3.4");

    for _ in 0..5 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn test_rate_limit_blocks_over_limit() {
    let config = RateLimitConfig::new()
        .enabled(true)
        .default_limit(Duration::from_secs(60), 3);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/rate-limit/blocked", "1.2.3.4");

    for _ in 0..3 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    let resp = mw.before_request(&req).await.unwrap();
    assert!(resp.is_some());
    assert_eq!(resp.unwrap().status, 429);
}

#[tokio::test]
async fn test_rate_limit_per_client() {
    let config = RateLimitConfig::new()
        .enabled(true)
        .default_limit(Duration::from_secs(60), 2);
    let mw = RateLimitMiddleware::new(config);

    let req_a = make_request("/rate-limit/client", "1.1.1.1");
    let req_b = make_request("/rate-limit/client", "2.2.2.2");

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
        .enabled(true)
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

#[derive(Default)]
struct CaptureStorage(std::sync::Mutex<Vec<(String, EndpointRateLimit)>>);

#[async_trait]
impl RateLimitStorage for CaptureStorage {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.0.lock().unwrap().push((key.to_owned(), rule));
        Ok(RateLimitDecision {
            allowed: false,
            retry_after: None,
        })
    }
}

struct AsyncRule(Arc<CaptureStorage>);

#[async_trait]
impl RateLimitRuleResolver for AsyncRule {
    async fn resolve(
        &self,
        request: &AuthRequest,
        current: EndpointRateLimit,
    ) -> AuthResult<RateLimitOverride> {
        tokio::task::yield_now().await;
        self.0
            .0
            .lock()
            .unwrap()
            .push((request.path().to_owned(), current));
        Ok(RateLimitOverride::Limit(EndpointRateLimit {
            window: 7.5,
            max_requests: 1.5,
        }))
    }
}

#[tokio::test]
async fn ordered_rules_receive_plugin_values_and_normalize_only_the_counter_key() {
    let storage = Arc::new(CaptureStorage::default());
    let config = RateLimitConfig::new()
        .enabled(true)
        .custom_storage(storage.clone())
        .storage(RateLimitStorageKind::Database)
        .rule(
            "/sign-in/*",
            CustomRateLimitRule::Dynamic(Arc::new(AsyncRule(storage.clone()))),
        )
        .rule("/sign-in/email", RateLimitOverride::Disabled);
    let mut limiter = RateLimitMiddleware::new(config);
    limiter.base_path = Box::new(|| "/custom/auth/".into());
    limiter.plugin_limits = vec![
        PluginRateLimit::prefix(
            "/sign-in",
            EndpointRateLimit {
                window: 21.0,
                max_requests: 4.0,
            },
        ),
        PluginRateLimit::exact(
            "/sign-in/email",
            EndpointRateLimit {
                window: 22.0,
                max_requests: 5.0,
            },
        ),
    ];
    let request = make_request("/sign-in/email", "192.0.2.30").with_url(
        url::Url::parse("https://auth.example/custom/auth/sign-in/email///?attempt=1").unwrap(),
    );
    let denied = limiter.before_request(&request).await.unwrap().unwrap();
    assert_eq!(denied.status, 429);
    assert_eq!(
        denied.headers.get("X-Retry-After").map(String::as_str),
        Some("7.5")
    );
    let entries = storage.0.lock().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (
            &*entries[0].0,
            entries[0].1.window,
            entries[0].1.max_requests
        ),
        ("/sign-in/email", 21.0, 4.0)
    );
    assert_eq!(
        (
            &*entries[1].0,
            entries[1].1.window,
            entries[1].1.max_requests
        ),
        ("192.0.2.30|/sign-in/email", 7.5, 1.5)
    );
}

#[tokio::test]
async fn first_custom_match_can_disable_or_preserve_the_special_rule() {
    let storage = Arc::new(CaptureStorage::default());
    for (override_rule, expected_calls) in [
        (RateLimitOverride::Disabled, 0),
        (RateLimitOverride::Unchanged, 1),
    ] {
        let limiter = RateLimitMiddleware::new(
            RateLimitConfig::new()
                .enabled(true)
                .custom_storage(storage.clone())
                .rule("/sign-in/**", override_rule)
                .rule("/sign-in/email/nested", RateLimitOverride::Disabled),
        );
        let result = limiter
            .before_request(&AuthRequest::new(HttpMethod::Get, "/sign-in/email/nested"))
            .await
            .unwrap();
        assert_eq!(result.is_some(), expected_calls == 1);
        assert_eq!(storage.0.lock().unwrap().len(), expected_calls);
    }
    let entries = storage.0.lock().unwrap();
    assert_eq!(
        (
            &*entries[0].0,
            entries[0].1.window,
            entries[0].1.max_requests
        ),
        ("no-trusted-ip|/sign-in/email/nested", 10.0, 3.0)
    );
}

#[tokio::test]
async fn secondary_denials_still_increment_and_return_the_full_fractional_window() {
    let cache = Arc::new(crate::store::MemoryCacheAdapter::new());
    let storage = SecondaryRateLimitStorage {
        storage: Some(cache.clone()),
    };
    let rule = EndpointRateLimit {
        window: 2.5,
        max_requests: 1.5,
    };
    assert!(
        storage
            .consume("secondary-limiter", rule)
            .await
            .unwrap()
            .allowed
    );
    for _ in 0..2 {
        let result = storage.consume("secondary-limiter", rule).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.retry_after, Some(2.5));
    }
    assert_eq!(
        crate::store::SecondaryStorage::get(cache.as_ref(), "secondary-limiter")
            .await
            .unwrap(),
        Some(serde_json::Value::String("3".into()))
    );
}

#[tokio::test]
async fn memory_limits_share_counters_between_auth_instances() {
    let config = RateLimitConfig::new().enabled(true).rule(
        "/shared-memory-probe",
        EndpointRateLimit {
            window: 60.0,
            max_requests: 0.0,
        },
    );
    let first = RateLimitMiddleware::new(config.clone());
    let second = RateLimitMiddleware::new(config);
    let request = make_request("/shared-memory-probe", "192.0.2.31");
    assert!(first.before_request(&request).await.unwrap().is_none());
    assert_eq!(
        second
            .before_request(&request)
            .await
            .unwrap()
            .unwrap()
            .status,
        429
    );
}

#[tokio::test]
async fn matcher_failures_propagate_before_storage_and_disabled_ip_tracking_skips_matchers() {
    let storage = Arc::new(CaptureStorage::default());
    let mut limiter = RateLimitMiddleware::new(
        RateLimitConfig::new()
            .enabled(true)
            .custom_storage(storage.clone()),
    );
    limiter
        .plugin_limits
        .push(PluginRateLimit::new(limiter.config.default, |_| {
            Err(AuthError::internal("matcher failed"))
        }));
    let request = make_request("/matcher-error", "192.0.2.32");
    assert!(
        matches!(limiter.before_request(&request).await, Err(AuthError::Internal(message)) if message == "matcher failed")
    );
    assert!(storage.0.lock().unwrap().is_empty());
    limiter.ip_address.disable_ip_tracking = true;
    assert!(limiter.before_request(&request).await.unwrap().is_none());
    assert!(storage.0.lock().unwrap().is_empty());
}
