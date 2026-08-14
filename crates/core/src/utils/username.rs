//! Shared username normalization and validation helpers.

pub const USERNAME_MIN_LENGTH: usize = 3;
pub const USERNAME_MAX_LENGTH: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameValidationError {
    TooShort,
    TooLong,
    Invalid,
}

pub fn normalize_username(username: &str) -> String {
    username.to_lowercase()
}

pub fn validate_username(username: &str) -> Result<(), UsernameValidationError> {
    if username.len() < USERNAME_MIN_LENGTH {
        return Err(UsernameValidationError::TooShort);
    }

    if username.len() > USERNAME_MAX_LENGTH {
        return Err(UsernameValidationError::TooLong);
    }

    if username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
    {
        Ok(())
    } else {
        Err(UsernameValidationError::Invalid)
    }
}

pub fn normalize_username_fields(
    mut username: Option<String>,
    mut display_username: Option<String>,
) -> (Option<String>, Option<String>) {
    if username.is_some() && display_username.is_none() {
        display_username = username.clone();
    }

    if display_username.is_some() && username.is_none() {
        username = display_username.clone();
    }

    if let Some(username_value) = username.as_mut() {
        *username_value = normalize_username(username_value);
    }

    (username, display_username)
}
