use chrono::{DateTime, Utc};

use super::{ApiKeyStore, ConsumeApiKeyResult};
use crate::{ApiKey, AuthError, AuthResult};

/// A single guarded counter write or timestamp update for API key verification.
#[derive(Debug, Clone)]
pub enum ApiKeyUsageWrite {
    Refill {
        previous: Option<DateTime<Utc>>,
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

fn timestamp(value: &str) -> AuthResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| AuthError::internal(format!("Invalid stored API key timestamp: {error}")))
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
            let previous = snapshot
                .last_refill_at
                .as_deref()
                .map(timestamp)
                .transpose()?;
            let last = match previous {
                Some(last) => last,
                None => timestamp(&snapshot.created_at)?,
            };
            if (now.timestamp_millis() - last.timestamp_millis()) as f64 > interval {
                refilled = store
                    .write_api_key_usage(
                        &snapshot.id,
                        ApiKeyUsageWrite::Refill {
                            previous,
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
        if !rate_enabled || !row.rate_limit_enabled {
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
        let last = row.last_request.as_deref().map(timestamp).transpose()?;
        let elapsed = last.map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
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
