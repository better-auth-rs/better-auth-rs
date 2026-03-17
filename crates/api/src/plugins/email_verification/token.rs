use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use better_auth_core::AuthResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EmailVerificationClaims {
    pub(crate) email: String,
    #[serde(rename = "updateTo", skip_serializing_if = "Option::is_none")]
    pub(crate) update_to: Option<String>,
    #[serde(rename = "requestType", skip_serializing_if = "Option::is_none")]
    pub(crate) request_type: Option<String>,
    pub(crate) exp: usize,
    pub(crate) iat: usize,
}

pub(crate) fn create_email_verification_token(
    secret: &str,
    email: &str,
    update_to: Option<&str>,
    expires_in: Duration,
    request_type: Option<&str>,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = EmailVerificationClaims {
        email: email.to_lowercase(),
        update_to: update_to.map(str::to_string),
        request_type: request_type.map(str::to_string),
        exp: (now + expires_in).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_email_verification_token(
    secret: &str,
    token: &str,
) -> AuthResult<EmailVerificationClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    Ok(decode::<EmailVerificationClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims)
}
