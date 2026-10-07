use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, errors::ErrorKind,
};
use serde::{Deserialize, Serialize};

use better_auth_core::AuthResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EmailVerificationClaims {
    pub(crate) email: String,
    #[serde(rename = "updateTo", skip_serializing_if = "Option::is_none")]
    pub(crate) update_to: Option<String>,
    #[serde(rename = "requestType", skip_serializing_if = "Option::is_none")]
    pub(crate) request_type: Option<String>,
    pub(crate) iat: i64,
    #[serde(serialize_with = "numeric_date")]
    pub(crate) exp: f64,
}

fn numeric_date<S: serde::Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    better_auth_core::wire::serialize_optional_number(&Some(*value), serializer)
}

pub(crate) fn create_email_verification_token(
    secret: &str,
    email: &str,
    update_to: Option<&str>,
    expires_in: Duration,
    request_type: Option<&str>,
) -> AuthResult<String> {
    create_email_verification_token_at(
        secret,
        email,
        update_to,
        expires_in,
        request_type,
        Utc::now(),
    )
}

fn create_email_verification_token_at(
    secret: &str,
    email: &str,
    update_to: Option<&str>,
    expires_in: Duration,
    request_type: Option<&str>,
    now: DateTime<Utc>,
) -> AuthResult<String> {
    let claims = EmailVerificationClaims {
        email: email.to_lowercase(),
        update_to: update_to.map(str::to_string),
        request_type: request_type.map(str::to_string),
        iat: now.timestamp(),
        exp: now.timestamp() as f64 + expires_in.as_seconds_f64(),
    };

    Ok(encode(
        &Header {
            typ: None,
            ..Default::default()
        },
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_email_verification_token(
    secret: &str,
    token: &str,
) -> AuthResult<EmailVerificationClaims> {
    decode_email_verification_token_at(secret, token, Utc::now())
}

fn decode_email_verification_token_at(
    secret: &str,
    token: &str,
    now: DateTime<Utc>,
) -> AuthResult<EmailVerificationClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    // The typed claims require exp. Validate its fractional value without the library's rounding or clock tolerance.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let claims = decode::<EmailVerificationClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims;
    if claims.exp <= now.timestamp() as f64 {
        return Err(jsonwebtoken::errors::Error::from(ErrorKind::ExpiredSignature).into());
    }
    Ok(claims)
}

#[cfg(test)]
#[path = "duration_tests.rs"]
mod tests;
