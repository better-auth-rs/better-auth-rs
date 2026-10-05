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
