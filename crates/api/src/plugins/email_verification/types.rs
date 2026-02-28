use serde::{Deserialize, Serialize};
use validator::Validate;

// Request structures for email verification endpoints
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

// Response structures

#[derive(Debug, Serialize)]
pub(crate) struct VerifyEmailResponse<U: Serialize> {
    pub(crate) user: U,
    pub(crate) status: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyEmailWithSessionResponse<U: Serialize, S: Serialize> {
    pub(crate) user: U,
    pub(crate) session: S,
    pub(crate) status: bool,
}

/// Result of the verify-email core function.
pub(crate) enum VerifyEmailResult<U: Serialize, S: Serialize> {
    /// Already verified -- return JSON with user.
    AlreadyVerified(VerifyEmailResponse<U>),
    /// Redirect to callback URL with optional session cookie.
    Redirect {
        url: String,
        session_token: Option<String>,
    },
    /// JSON response with user only (no auto sign-in).
    Json(VerifyEmailResponse<U>),
    /// JSON response with user + session (auto sign-in).
    JsonWithSession {
        response: VerifyEmailWithSessionResponse<U, S>,
        session_token: String,
    },
}
