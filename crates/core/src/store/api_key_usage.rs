use chrono::{DateTime, Utc};

use super::{ApiKeyStore, ConsumeApiKeyResult};
use crate::{
    ApiKey, AuthError, AuthResult, FieldDate, FieldValue,
    query::{field_compare, field_date, field_number},
};

/// A single guarded counter write or timestamp update for API key verification.
#[derive(Debug, Clone)]
pub enum ApiKeyUsageWrite {
    Refill {
        /// Clone the observed [`ApiKey::last_refill_at`] value.
        /// Memory compares Date identity; SQL compares the persisted Date value.
        /// Preserve null, omission, and replacement values in the adapter guard.
        previous: FieldValue,
        remaining: f64,
        at: DateTime<Utc>,
    },
    Decrement,
    StartWindow {
        /// `None` requires a missing previous request; `Some` requires an expired window.
        previous_before: Option<FieldDate>,
        at: DateTime<Utc>,
    },
    IncrementWindow {
        previous_after: FieldDate,
        maximum: FieldValue,
        at: DateTime<Utc>,
    },
    LastRequest(DateTime<Utc>),
    UpdatedAt(DateTime<Utc>),
}

impl ApiKeyUsageWrite {
    /// Return setter values without evaluating the adapter's atomic increment expressions.
    pub fn set_fields(&self) -> crate::FieldMap {
        match self {
            Self::Refill { remaining, at, .. } => crate::FieldMap::from([
                ("remaining".into(), (*remaining).into()),
                ("lastRefillAt".into(), (*at).into()),
            ]),
            Self::StartWindow { at, .. } => crate::FieldMap::from([
                ("requestCount".into(), 1.0.into()),
                ("lastRequest".into(), (*at).into()),
            ]),
            Self::IncrementWindow { at, .. } | Self::LastRequest(at) => {
                crate::FieldMap::from([("lastRequest".into(), (*at).into())])
            }
            Self::UpdatedAt(at) => crate::FieldMap::from([("updatedAt".into(), (*at).into())]),
            Self::Decrement => crate::FieldMap::new(),
        }
    }

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
    if snapshot.remaining.field_value().strict_equals(&0.0.into())
        && snapshot.refill_amount.field_value().is_null()
    {
        store.delete_api_key(&snapshot.id).await?;
        return Ok(ConsumeApiKeyResult::UsageExhausted);
    }
    let mut row = snapshot.clone();
    if !snapshot.remaining.field_value().is_null() {
        let now = Utc::now();
        let mut refilled = None;
        let interval = snapshot.refill_interval.field_value();
        let amount = snapshot.refill_amount.field_value();
        if interval.is_truthy() && amount.is_truthy() {
            let previous = snapshot.last_refill_at.field_value();
            let date_input = if previous.is_null() || previous.is_undefined() {
                snapshot.created_at.field_value()
            } else {
                previous.clone()
            };
            let last = field_date(&date_input)?.milliseconds();
            if now.timestamp_millis() as f64 - last > field_number(&interval)? {
                refilled = store
                    .write_api_key_usage(
                        &snapshot.id,
                        ApiKeyUsageWrite::Refill {
                            previous,
                            remaining: field_number(&amount)? - 1.0,
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
        if !rate_enabled
            || row
                .rate_limit_enabled
                .field_value()
                .strict_equals(&false.into())
        {
            if let Some(updated) = store
                .write_api_key_usage(&row.id, ApiKeyUsageWrite::LastRequest(now))
                .await?
            {
                row = updated;
            }
            break;
        }
        let window = row.rate_limit_time_window.field_value();
        let maximum = row.rate_limit_max.field_value();
        if window.is_null() || maximum.is_null() {
            break;
        }
        let last_request = row.last_request.field_value();
        let mutation = if last_request.is_null() {
            ApiKeyUsageWrite::StartWindow {
                previous_before: None,
                at: now,
            }
        } else {
            let elapsed = now.timestamp_millis() as f64 - field_date(&last_request)?.milliseconds();
            let window = field_number(&window)?;
            let cutoff = FieldDate::from_milliseconds(now.timestamp_millis() as f64 - window);
            if elapsed > window {
                ApiKeyUsageWrite::StartWindow {
                    previous_before: Some(cutoff),
                    at: now,
                }
            } else if matches!(
                field_compare(&row.request_count.field_value(), &maximum)?,
                Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
            ) {
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
