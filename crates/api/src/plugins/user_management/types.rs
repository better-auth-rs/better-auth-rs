use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    #[validate(email(message = "Invalid email address"))]
    pub(crate) new_email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Request body for `POST /delete-user`. Currently empty; the user is
/// identified by the session.
#[derive(Debug, Deserialize, Validate)]
pub(crate) struct DeleteUserRequest {}

/// Query parameters for token-based verification endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenQuery {
    pub(crate) token: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct StatusMessageResponse {
    pub(crate) status: bool,
    pub(crate) message: String,
}
