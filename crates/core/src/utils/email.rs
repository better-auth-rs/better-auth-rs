//! Email-related helpers for canonical auth persistence behavior.

/// Normalize a user identity email to the canonical persisted form.
pub(crate) fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}
