use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SendVerificationEmailRequest {
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
        session_data: Option<better_auth_core::session::SessionData>,
    },
    Json {
        body: serde_json::Value,
        session_data: Option<better_auth_core::session::SessionData>,
    },
}

pub(super) fn body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (body, projection) = crate::plugins::json_body::email_input::<SendVerificationEmailRequest>(
        req,
        "email",
        "callbackURL",
    )?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        body,
    ))
}
