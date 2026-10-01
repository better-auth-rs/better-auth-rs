use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    pub(crate) new_email: String,
    #[serde(rename = "callbackURL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct DeleteUserRequest {
    #[serde(rename = "callbackURL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) token: Option<String>,
}

/// Query parameters for token-based verification endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenQuery {
    pub(crate) token: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}
