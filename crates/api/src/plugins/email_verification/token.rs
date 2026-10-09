use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode, errors::ErrorKind};
use serde::{Deserialize, Serialize, de::Error as _};

use better_auth_core::{AuthResult, FieldMap, FieldValue, Utf16String};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EmailVerificationClaims {
    pub(crate) email: String,
    #[serde(
        rename = "updateTo",
        serialize_with = "better_auth_core::field_value::serde::optional_value::serialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) update_to: Option<FieldValue>,
    #[serde(
        rename = "requestType",
        serialize_with = "better_auth_core::field_value::serde::optional_value::serialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) request_type: Option<FieldValue>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "better_auth_core::wire::serialize_optional_number"
    )]
    pub(crate) iat: Option<f64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "better_auth_core::wire::serialize_optional_number"
    )]
    pub(crate) exp: Option<f64>,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(transparent)]
struct VerificationPayload(
    #[serde_as(as = "std::collections::HashMap<serde_with::Bytes, _>")]
    std::collections::HashMap<Vec<u8>, Box<serde_json::value::RawValue>>,
);

impl VerificationPayload {
    fn field(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.0
            .get(name.as_bytes())
            .map(|value| FieldValue::parse_json(value.get()))
            .transpose()
    }
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
    create_native_token_at(
        secret,
        &email.into(),
        update_to.map(Utf16String::from).as_ref(),
        expires_in,
        request_type,
        now,
    )
}

pub(super) fn create_native_email_verification_token(
    secret: &str,
    email: &Utf16String,
    update_to: Option<&Utf16String>,
    expires_in: Duration,
    request_type: Option<&str>,
) -> AuthResult<String> {
    create_native_token_at(
        secret,
        email,
        update_to,
        expires_in,
        request_type,
        Utc::now(),
    )
}

fn create_native_token_at(
    secret: &str,
    email: &Utf16String,
    update_to: Option<&Utf16String>,
    expires_in: Duration,
    request_type: Option<&str>,
    now: DateTime<Utc>,
) -> AuthResult<String> {
    #[derive(Serialize)]
    #[serde(transparent)]
    struct Claims(#[serde(with = "better_auth_core::field_value::serde::map")] FieldMap);

    let mut claims = FieldMap::from([("email".into(), email.to_lowercase().into())]);
    if let Some(update_to) = update_to {
        let _ = claims.insert("updateTo".into(), update_to.to_lowercase().into());
    }
    if let Some(request_type) = request_type {
        let _ = claims.insert("requestType".into(), request_type.into());
    }
    let _ = claims.insert("iat".into(), (now.timestamp() as f64).into());
    let _ = claims.insert(
        "exp".into(),
        (now.timestamp() as f64 + expires_in.as_seconds_f64()).into(),
    );
    Ok(encode(
        &Header {
            typ: None,
            ..Default::default()
        },
        &Claims(claims),
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
    let bytes = crate::plugins::jwt::verify_hs256_raw(token, secret)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))?;
    let fields: VerificationPayload =
        serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(text))
            .map_err(jsonwebtoken::errors::Error::from)?;
    // jose accepts optional fractional dates and checks nbf before exp without clock tolerance.
    let iat = numeric_date_claim(&fields, "iat")?;
    if numeric_date_claim(&fields, "nbf")?.is_some_and(|value| value > now.timestamp() as f64) {
        return Err(jsonwebtoken::errors::Error::from(ErrorKind::ImmatureSignature).into());
    }
    let exp = numeric_date_claim(&fields, "exp")?;
    if exp.is_some_and(|value| value <= now.timestamp() as f64) {
        return Err(jsonwebtoken::errors::Error::from(ErrorKind::ExpiredSignature).into());
    }
    // Upstream parses email fields after JWT verification; business payload errors remain server errors.
    let email = fields.field("email")?;
    let email = email
        .as_ref()
        .and_then(FieldValue::as_str)
        .ok_or_else(|| serde_json::Error::custom("Expected an email string"))?;
    if !crate::plugins::json_body::valid_email(email)? {
        return Err(serde_json::Error::custom("Invalid email address").into());
    }
    Ok(EmailVerificationClaims {
        email: email.into(),
        update_to: optional_string_claim(&fields, "updateTo")?,
        request_type: optional_string_claim(&fields, "requestType")?,
        iat,
        exp,
    })
}

fn numeric_date_claim(
    fields: &VerificationPayload,
    name: &str,
) -> Result<Option<f64>, jsonwebtoken::errors::Error> {
    fields
        .field(name)
        .map_err(|_| jsonwebtoken::errors::Error::from(ErrorKind::InvalidClaimFormat(name.into())))?
        .map(|value| {
            value.as_f64().ok_or_else(|| {
                jsonwebtoken::errors::Error::from(ErrorKind::InvalidClaimFormat(name.into()))
            })
        })
        .transpose()
}

fn optional_string_claim(
    fields: &VerificationPayload,
    name: &str,
) -> AuthResult<Option<FieldValue>> {
    fields
        .field(name)?
        .map(|value| {
            if value.is_string() {
                Ok(value)
            } else {
                Err(serde_json::Error::custom(format!("Expected a string for {name}")).into())
            }
        })
        .transpose()
}

#[cfg(test)]
#[path = "duration_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "payload_tests.rs"]
mod payload_tests;

#[cfg(test)]
#[path = "claims_tests.rs"]
mod claims_tests;
