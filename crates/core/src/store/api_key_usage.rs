use chrono::{DateTime, Utc};

use super::{ApiKeyStore, ConsumeApiKeyResult};
use crate::{ApiKey, AuthError, AuthResult, FieldDate};

/// A single guarded counter write or timestamp update for API key verification.
#[derive(Debug, Clone)]
pub enum ApiKeyUsageWrite {
    Refill {
        /// Clone the observed [`ApiKey::last_refill_at`] value.
        /// Memory compares Date identity; SQL compares the persisted Date value.
        /// `None` requires no previous refill Date.
        previous: Option<FieldDate>,
        remaining: f64,
        at: DateTime<Utc>,
    },
    Decrement,
    StartWindow {
        /// `None` requires a missing previous request; `Some` requires an expired window.
        previous_before: Option<DateTime<Utc>>,
        at: DateTime<Utc>,
    },
    IncrementWindow {
        previous_after: DateTime<Utc>,
        maximum: f64,
        at: DateTime<Utc>,
    },
    LastRequest(DateTime<Utc>),
    UpdatedAt(DateTime<Utc>),
}

impl ApiKeyUsageWrite {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::LastRequest(_) | Self::UpdatedAt(_) => "update",
            _ => "incrementOne",
        }
    }
}

pub(super) async fn consume(
    store: &(impl ApiKeyStore + ?Sized),
    snapshot: &ApiKey,
    rate_enabled: bool,
) -> AuthResult<ConsumeApiKeyResult> {
    if snapshot.remaining == Some(0.0) && snapshot.refill_amount.is_none() {
        store.delete_api_key(&snapshot.id).await?;
        return Ok(ConsumeApiKeyResult::UsageExhausted);
    }
    let mut row = snapshot.clone();
    if snapshot.remaining.is_some() {
        let now = Utc::now();
        let mut refilled = None;
        if let (Some(interval), Some(amount)) = (snapshot.refill_interval, snapshot.refill_amount)
            && interval != 0.0
            && amount != 0.0
        {
            let previous = snapshot.last_refill_at.as_ref();
            let last = previous.unwrap_or(&snapshot.created_at).milliseconds();
            if now.timestamp_millis() as f64 - last > interval {
                refilled = store
                    .write_api_key_usage(
                        &snapshot.id,
                        ApiKeyUsageWrite::Refill {
                            previous: previous.cloned(),
                            remaining: amount - 1.0,
                            at: now,
                        },
                    )
                    .await?;
            }
        }
        let consumed = match refilled {
            Some(row) => Some(row),
            None => {
                store
                    .write_api_key_usage(&snapshot.id, ApiKeyUsageWrite::Decrement)
                    .await?
            }
        };
        let Some(consumed) = consumed else {
            return Ok(ConsumeApiKeyResult::UsageExhausted);
        };
        row = consumed;
    }

    loop {
        let now = Utc::now();
        if !rate_enabled || !row.rate_limit_enabled.is_truthy()? {
            if let Some(updated) = store
                .write_api_key_usage(&row.id, ApiKeyUsageWrite::LastRequest(now))
                .await?
            {
                row = updated;
            }
            break;
        }
        let (Some(window), Some(maximum)) = (row.rate_limit_time_window, row.rate_limit_max) else {
            break;
        };
        let elapsed = row
            .last_request
            .as_ref()
            .map(|last| now.timestamp_millis() as f64 - last.milliseconds());
        let mutation = if let Some(elapsed) = elapsed {
            // Date truncates fractional milliseconds toward zero.
            let cutoff = DateTime::from_timestamp_millis(
                (now.timestamp_millis() as f64 - window).trunc() as i64,
            )
            .ok_or_else(|| AuthError::internal("Invalid API key rate-limit window"))?;
            if elapsed > window {
                ApiKeyUsageWrite::StartWindow {
                    previous_before: Some(cutoff),
                    at: now,
                }
            } else if row.request_count.unwrap_or(0.0) >= maximum {
                return Ok(ConsumeApiKeyResult::RateLimited {
                    try_again_in: (window - elapsed).ceil(),
                });
            } else {
                ApiKeyUsageWrite::IncrementWindow {
                    previous_after: cutoff,
                    maximum,
                    at: now,
                }
            }
        } else {
            ApiKeyUsageWrite::StartWindow {
                previous_before: None,
                at: now,
            }
        };
        if let Some(updated) = store.write_api_key_usage(&row.id, mutation).await? {
            row = updated;
            break;
        }
        row = store
            .get_api_key_by_id_value(&row.id)
            .await?
            .ok_or_else(|| AuthError::not_found("API Key not found"))?;
    }

    let updated = store
        .write_api_key_usage(&row.id, ApiKeyUsageWrite::UpdatedAt(Utc::now()))
        .await?
        .ok_or_else(|| AuthError::not_found("API Key not found"))?;
    Ok(ConsumeApiKeyResult::Allowed(Box::new(updated)))
}
