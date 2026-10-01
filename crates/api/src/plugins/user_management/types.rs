use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    pub(crate) new_email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
