use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    #[validate(email(message = "Invalid email address"))]
    pub(crate) new_email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct DeleteUserRequest {
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) token: Option<String>,
}

/// Query parameters for token-based verification endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenQuery {
    pub(crate) token: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}
