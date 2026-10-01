use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult};

/// Synchronous normalization applied at each upstream endpoint and adapter boundary.
pub type UsernameNormalizer = dyn Fn(&str) -> AuthResult<String> + Send + Sync;

/// Asynchronous validation of a username or display username.
#[async_trait]
pub trait UsernameValidator: Send + Sync {
    /// Return false to reject the value. Callback errors retain their original response.
    async fn validate(&self, value: &str) -> AuthResult<bool>;
}

/// Input normalization for one username field.
#[derive(Clone, Default)]
pub enum UsernameNormalization {
    /// Lowercase usernames and preserve display usernames.
    #[default]
    Default,
    /// Preserve the supplied field exactly.
    Disabled,
    /// Run a synchronous, fallible application callback.
    Custom(Arc<UsernameNormalizer>),
}

/// Order used by the configured username endpoint or database-hook validator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UsernameValidationOrder {
    /// Validate before normalization, except for the upstream sign-in ordering.
    PreNormalization,
    /// Validate after normalization in signup, updates and direct adapter writes.
    PostNormalization,
}

/// Username plugin options, independent of the password login plugin.
#[derive(Clone)]
pub struct UsernameConfig {
    /// Minimum UTF-16 length. Zero and NaN select the upstream default of three.
    pub min_username_length: f64,
    /// Maximum UTF-16 length. Zero and NaN select the upstream default of thirty.
    pub max_username_length: f64,
    /// Custom asynchronous username validator; the default accepts ASCII letters, digits, `_` and `.`.
    pub username_validator: Option<Arc<dyn UsernameValidator>>,
    /// Optional asynchronous display-name validator.
    pub display_username_validator: Option<Arc<dyn UsernameValidator>>,
    /// Username normalization; default lowercase is separate from disabled normalization.
    pub username_normalization: UsernameNormalization,
    /// Display-name normalization; the default preserves input.
    pub display_username_normalization: UsernameNormalization,
    /// Preserve omission because upstream sign-in treats it differently from explicit pre-normalization.
    pub username_validation_order: Option<UsernameValidationOrder>,
    /// Display-name validation order.
    pub display_username_validation_order: Option<UsernameValidationOrder>,
    /// Reject changed usernames through the update-user endpoint once a username is set.
    pub immutable_username: bool,
    /// Add and maintain the separate displayUsername field.
    pub display_username: bool,
    /// Serialized application field used to store the username.
    pub username_field_name: Option<String>,
    /// Serialized application field used to store the display username.
    pub display_username_field_name: Option<String>,
}

impl Default for UsernameConfig {
    fn default() -> Self {
        Self {
            min_username_length: 3.0,
            max_username_length: 30.0,
            username_validator: None,
            display_username_validator: None,
            username_normalization: UsernameNormalization::Default,
            display_username_normalization: UsernameNormalization::Default,
            username_validation_order: None,
            display_username_validation_order: None,
            immutable_username: false,
            display_username: true,
            username_field_name: None,
            display_username_field_name: None,
        }
    }
}

pub(super) fn error(status: u16, code: &'static str, message: &'static str) -> AuthError {
    AuthError::Upstream {
        status,
        code,
        message,
    }
}

impl UsernameConfig {
    pub(super) fn normalize(&self, value: &str) -> AuthResult<String> {
        match &self.username_normalization {
            UsernameNormalization::Default => Ok(value.to_lowercase()),
            UsernameNormalization::Disabled => Ok(value.to_owned()),
            UsernameNormalization::Custom(callback) => callback(value),
        }
    }

    pub(super) fn normalize_display(&self, value: &str) -> AuthResult<String> {
        match &self.display_username_normalization {
            UsernameNormalization::Default | UsernameNormalization::Disabled => {
                Ok(value.to_owned())
            }
            UsernameNormalization::Custom(callback) => callback(value),
        }
    }

    pub(super) async fn validate_raw(
        &self,
        value: &str,
    ) -> AuthResult<Option<(&'static str, &'static str)>> {
        let length = value.encode_utf16().count() as f64;
        let minimum = if self.min_username_length == 0.0 || self.min_username_length.is_nan() {
            3.0
        } else {
            self.min_username_length
        };
        let maximum = if self.max_username_length == 0.0 || self.max_username_length.is_nan() {
            30.0
        } else {
            self.max_username_length
        };
        if length < minimum {
            return Ok(Some(("USERNAME_TOO_SHORT", "Username is too short")));
        }
        if length > maximum {
            return Ok(Some(("USERNAME_TOO_LONG", "Username is too long")));
        }
        let valid = match &self.username_validator {
            Some(callback) => callback.validate(value).await?,
            None => {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
            }
        };
        Ok((!valid).then_some(("INVALID_USERNAME", "Username is invalid")))
    }

    pub(super) async fn validate_input(
        &self,
        value: &str,
    ) -> AuthResult<Option<(&'static str, &'static str)>> {
        if self.username_validation_order == Some(UsernameValidationOrder::PostNormalization) {
            self.validate_raw(&self.normalize(value)?).await
        } else {
            self.validate_raw(value).await
        }
    }

    pub(super) async fn validate_display(&self, value: &str) -> AuthResult<()> {
        if let Some(callback) = &self.display_username_validator {
            let valid = if self.display_username_validation_order
                == Some(UsernameValidationOrder::PostNormalization)
            {
                callback.validate(&self.normalize_display(value)?).await?
            } else {
                callback.validate(value).await?
            };
            if !valid {
                return Err(error(
                    400,
                    "INVALID_DISPLAY_USERNAME",
                    "Display username is invalid",
                ));
            }
        }
        Ok(())
    }
}
