use super::*;
use crate::middleware::{EndpointRateLimit, RateLimitDecision};
use crate::store::{RateLimitRecord, RateLimitStore};

#[async_trait]
impl RateLimitStore for EphemeralStore {
    async fn consume_rate_limit(
        &self,
        key: &str,
        rule: EndpointRateLimit,
        cleanup_window: f64,
    ) -> AuthResult<RateLimitDecision> {
        let mut state = self.lock()?;
        let now = Utc::now().timestamp_millis();
        let numeric_now = now as f64;
        let window = rule.window * 1000.0;
        let mut reset = false;
        let allowed = match state.rate_limits.get_mut(key) {
            None => {
                let id = self
                    .generated_id("rateLimit", None, state.rate_limits.len())?
                    .map(crate::SchemaValue::Typed)
                    .unwrap_or_default();
                let _ = state.rate_limits.insert(
                    key.to_owned(),
                    RateLimitRecord {
                        id,
                        key: key.to_owned(),
                        count: 1.0,
                        last_request: now,
                    },
                );
                true
            }
            Some(row) => {
                let previous = row.last_request as f64;
                if numeric_now - previous >= window {
                    row.count = 1.0;
                    row.last_request = now;
                    reset = true;
                    true
                } else if previous > numeric_now - window && row.count < rule.max_requests {
                    row.count += 1.0;
                    row.last_request = now;
                    true
                } else {
                    return Ok(RateLimitDecision {
                        allowed: false,
                        retry_after: Some(((previous + window - numeric_now) / 1000.0).ceil()),
                    });
                }
            }
        };
        if reset {
            let cutoff = numeric_now - cleanup_window * 1000.0;
            state.rate_limits.retain(|_, row| {
                (row.last_request as f64).partial_cmp(&cutoff) != Some(std::cmp::Ordering::Less)
            });
        }
        Ok(RateLimitDecision {
            allowed,
            retry_after: None,
        })
    }
}
