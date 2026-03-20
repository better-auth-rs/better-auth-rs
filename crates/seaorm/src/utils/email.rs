pub(crate) fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}

pub(crate) fn normalize_optional_user_email(email: Option<String>) -> Option<String> {
    email.map(|email| normalize_user_email(&email))
}
