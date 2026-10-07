use super::SchemaValue;
use crate::{AuthError, AuthResult, FieldDate, FieldValue};
use chrono::{DateTime, Utc};

impl SchemaValue<FieldDate> {
    /// Read the Date object's timestamp at a getTime operation.
    pub fn date_milliseconds(&self) -> AuthResult<f64> {
        match self {
            Self::Typed(date) => Ok(date.milliseconds()),
            Self::Dynamic(_) | Self::Undefined => {
                Err(AuthError::internal("Date.getTime is not a function"))
            }
        }
    }

    /// Compare a projected date as the upstream relational expression does.
    /// Undefined and invalid dates produce NaN, so neither comparison reports an expired value.
    pub fn is_before(&self, now: DateTime<Utc>) -> bool {
        self.relational_milliseconds() < now.timestamp_millis() as f64
    }

    /// Compare a projected date without replacing NaN with a valid timestamp.
    pub fn is_after(&self, now: DateTime<Utc>) -> bool {
        self.relational_milliseconds() > now.timestamp_millis() as f64
    }

    /// Apply an inclusive comparison without treating NaN as an expired value.
    pub fn is_before_or_equal(&self, now: DateTime<Utc>) -> bool {
        self.relational_milliseconds() <= now.timestamp_millis() as f64
    }

    /// Apply an inclusive comparison without treating NaN as a valid expiration.
    pub fn is_after_or_equal(&self, now: DateTime<Utc>) -> bool {
        self.relational_milliseconds() >= now.timestamp_millis() as f64
    }

    fn relational_milliseconds(&self) -> f64 {
        crate::query::field_number(&self.field_value())
    }

    /// Compute create-cache TTL. Upstream accepts a number or calls the Date object's getTime method.
    /// Invalid Date skips the cache write; other replacement types fail at this operation boundary.
    pub fn cache_ttl(&self, now: DateTime<Utc>) -> AuthResult<u64> {
        let millis = match self {
            Self::Typed(date) => date.milliseconds(),
            Self::Dynamic(FieldValue::Number(value)) => *value,
            Self::Dynamic(_) | Self::Undefined => {
                return Err(AuthError::internal("expiresAt.getTime is not a function"));
            }
        };
        ttl(millis, now)
    }

    /// Compute update-cache TTL after the endpoint's explicit Date constructor conversion.
    pub fn converted_cache_ttl(&self, now: DateTime<Utc>) -> AuthResult<u64> {
        self.clone().converted_date().cache_ttl(now)
    }

    /// Apply the Date constructor used when consuming a secondary verification snapshot.
    pub fn converted_date(self) -> Self {
        let value = self.into_field_value();
        let date = match value {
            FieldValue::Date(date) => date,
            FieldValue::String(text) => crate::utils::date::parse_adapter_date(&text)
                .map(FieldDate::from)
                .unwrap_or_else(FieldDate::invalid),
            FieldValue::Utf16String(_)
            | FieldValue::Array(_)
            | FieldValue::Object(_)
            | FieldValue::Undefined => FieldDate::invalid(),
            value => FieldDate::from_milliseconds(crate::query::field_number(&value)),
        };
        Self::Typed(date)
    }
}

fn ttl(millis: f64, now: DateTime<Utc>) -> AuthResult<u64> {
    let seconds = ((millis - now.timestamp_millis() as f64) / 1_000.0).floor();
    // Upstream guards the write with ttl > 0. NaN therefore has no secondary effect.
    if seconds.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return Ok(0);
    }
    std::time::Duration::try_from_secs_f64(seconds)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            AuthError::internal(format!(
                "Verification cache TTL exceeds the backend range: {error}"
            ))
        })
}
