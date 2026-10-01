use std::sync::{LazyLock, Mutex};

use async_trait::async_trait;
use indexmap::IndexMap;

use super::{EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use crate::{AuthError, AuthResult};

static BUCKETS: LazyLock<Mutex<IndexMap<String, Bucket>>> =
    LazyLock::new(|| Mutex::new(IndexMap::new()));
const MAX_ENTRIES: usize = 100_000;

pub(super) struct MemoryRateLimitStorage;

struct Bucket {
    count: f64,
    last_request: f64,
    expires_at: f64,
}

fn consume(
    buckets: &mut IndexMap<String, Bucket>,
    key: &str,
    rule: EndpointRateLimit,
    now: f64,
) -> RateLimitDecision {
    buckets.retain(|_, entry| entry.expires_at.is_nan() || now < entry.expires_at);
    if buckets.len() > MAX_ENTRIES {
        let overflow = buckets.len() - MAX_ENTRIES;
        drop(buckets.drain(..overflow));
    }
    let entry = buckets.get(key).filter(|entry| now < entry.expires_at);
    let count = match entry {
        None => 1.0,
        Some(entry) if now - entry.last_request >= rule.window * 1000.0 => 1.0,
        Some(entry) if entry.count >= rule.max_requests => {
            return RateLimitDecision {
                allowed: false,
                retry_after: Some(
                    ((entry.last_request + rule.window * 1000.0 - now) / 1000.0).ceil(),
                ),
            };
        }
        Some(entry) => entry.count + 1.0,
    };
    let _ = buckets.insert(
        key.to_owned(),
        Bucket {
            count,
            last_request: now,
            expires_at: now + rule.window * 1000.0,
        },
    );
    RateLimitDecision {
        allowed: true,
        retry_after: None,
    }
}

#[async_trait]
impl RateLimitStorage for MemoryRateLimitStorage {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        // ponytail: one process-wide lock and expiry scan match upstream; use database or secondary storage for distributed limits.
        let mut buckets = BUCKETS
            .lock()
            .map_err(|_| AuthError::internal("Rate-limit lock poisoned"))?;
        Ok(consume(
            &mut buckets,
            key,
            rule,
            chrono::Utc::now().timestamp_millis() as f64,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_requests_extend_the_window_and_denials_preserve_the_counter() {
        let mut buckets = IndexMap::new();
        let rule = EndpointRateLimit {
            window: 2.0,
            max_requests: 2.0,
        };
        assert!(consume(&mut buckets, "key", rule, 1000.0).allowed);
        assert!(consume(&mut buckets, "key", rule, 2300.0).allowed);
        let denied = consume(&mut buckets, "key", rule, 3200.0);
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after, Some(2.0));
        assert_eq!(buckets["key"].count, 2.0);
        assert_eq!(buckets["key"].last_request, 2300.0);
        assert!(consume(&mut buckets, "key", rule, 4300.0).allowed);
        assert_eq!(buckets["key"].count, 1.0);
    }

    #[test]
    fn fractional_and_non_finite_rules_keep_the_upstream_memory_decisions() {
        for (window, max_requests, expected) in [
            (10.0, 1.5, [true, true, false]),
            (10.0, 0.0, [true, false, false]),
            (10.0, -1.0, [true, false, false]),
            (0.0, 1.0, [true, true, true]),
            (-1.0, 1.0, [true, true, true]),
            (f64::NAN, 1.0, [true, true, true]),
            (10.0, f64::NAN, [true, true, true]),
            (f64::INFINITY, 1.0, [true, false, false]),
            (10.0, f64::INFINITY, [true, true, true]),
        ] {
            let mut buckets = IndexMap::new();
            for (index, expected) in expected.into_iter().enumerate() {
                let rule = EndpointRateLimit {
                    window,
                    max_requests,
                };
                assert_eq!(
                    consume(&mut buckets, "key", rule, index as f64).allowed,
                    expected
                );
            }
        }
    }
}
