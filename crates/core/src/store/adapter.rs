//! Input handling shared by the database store implementations.

use chrono::{DateTime, Utc};

use crate::error::{AuthError, AuthResult};

/// Normalize a user email for storage and lookup.
pub fn normalize_email(email: &str) -> String {
    email.to_lowercase()
}

pub fn normalize_optional_email(email: Option<String>) -> Option<String> {
    email.map(|email| normalize_email(&email))
}

/// The error returned when a `before_*` database hook cancels a write.
pub fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

pub fn parse_rfc3339(value: &str, field: &str) -> AuthResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

pub fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> AuthResult<Option<DateTime<Utc>>> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}

pub fn to_i32(value: i64, field: &str) -> AuthResult<i32> {
    i32::try_from(value).map_err(|_| AuthError::bad_request(format!("{field} exceeds i32 range")))
}

pub fn to_optional_i32(value: Option<i64>, field: &str) -> AuthResult<Option<i32>> {
    value.map(|inner| to_i32(inner, field)).transpose()
}
