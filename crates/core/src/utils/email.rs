//! Email-related helpers for canonical auth persistence behavior.

/// Normalize a user identity email to the canonical persisted form.
pub(crate) fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}

/// Normalize an optional user identity email to the canonical persisted form.
pub(crate) fn normalize_optional_user_email(email: Option<String>) -> Option<String> {
    email.map(|email| normalize_user_email(&email))
}
