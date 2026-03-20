use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SendVerificationEmailRequest {
    #[validate(email(message = "Invalid email address"))]
    pub(crate) email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Query parameters for `GET /verify-email`.
#[derive(Debug, Deserialize)]
pub(crate) struct VerifyEmailQuery {
    pub(crate) token: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Result of the verify-email core function.
pub(crate) enum VerifyEmailResult {
    Redirect {
        url: String,
        session_token: Option<String>,
    },
    Json {
        body: serde_json::Value,
        session_token: Option<String>,
    },
}
