//! Retain typed rejection details until native logging and response consumption.

use super::ApiKeyErrorCode;
use better_auth_core::{AuthError, AuthResponse, AuthResult, FieldMap, FieldValue};
use serde::Serialize;

/// Additional information returned when a key reaches its rate limit.
#[derive(Debug, Serialize)]
pub struct ApiKeyErrorDetails {
    /// Milliseconds until the key's rate-limit window elapses.
    #[serde(rename = "tryAgainIn")]
    pub try_again_in: f64,
}

/// An API key rejection with the upstream error code and response fields.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiKeyErrorMessage {
    /// A public error message.
    Text(String),
    /// Upstream returns its complete error constant on selected verification failures.
    Code {
        code: ApiKeyErrorCode,
        message: String,
    },
}

impl std::fmt::Display for ApiKeyErrorMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(message) | Self::Code { message, .. } => formatter.write_str(message),
        }
    }
}

/// An API key rejection with the upstream error code and response fields.
#[derive(Debug)]
pub struct ApiKeyValidationError {
    /// Stable upstream API key error code.
    pub code: ApiKeyErrorCode,
    /// Upstream error message.
    pub message: ApiKeyErrorMessage,
    /// Rate-limit timing, when the rejection is a rate limit.
    pub details: Option<ApiKeyErrorDetails>,
    native: Option<AuthError>,
}

impl ApiKeyValidationError {
    /// Create a typed rejection before constructing its native error at the logging boundary.
    pub fn new(code: ApiKeyErrorCode) -> Self {
        Self {
            code,
            message: ApiKeyErrorMessage::Text(code.message().to_owned()),
            details: None,
            native: None,
        }
    }

    pub(super) fn invalid_constant(code: ApiKeyErrorCode) -> Self {
        Self {
            code,
            message: ApiKeyErrorMessage::Code {
                code: ApiKeyErrorCode::InvalidApiKey,
                message: ApiKeyErrorCode::InvalidApiKey.message().to_owned(),
            },
            details: None,
            native: None,
        }
    }

    fn status(&self) -> (&'static str, u16) {
        match self.code {
            ApiKeyErrorCode::NoDefaultConfiguration => ("BAD_REQUEST", 400),
            ApiKeyErrorCode::RateLimited | ApiKeyErrorCode::UsageExceeded => {
                ("TOO_MANY_REQUESTS", 429)
            }
            _ => ("UNAUTHORIZED", 401),
        }
    }

    fn declared_body(&self) -> FieldValue {
        let message = match &self.message {
            ApiKeyErrorMessage::Text(message) => message.clone().into(),
            ApiKeyErrorMessage::Code { code, message } => FieldMap::from([
                ("code".into(), code.as_str().into()),
                ("message".into(), message.clone().into()),
            ])
            .into(),
        };
        let mut body = FieldMap::from([
            ("message".into(), message),
            ("code".into(), self.code.as_str().into()),
        ]);
        if let Some(details) = &self.details {
            let _ = body.insert(
                "details".into(),
                FieldMap::from([("tryAgainIn".into(), details.try_again_in.into())]).into(),
            );
        }
        body.into()
    }

    fn body_value(&self) -> AuthResult<FieldValue> {
        self.native
            .as_ref()
            .map_or_else(|| Ok(self.declared_body()), AuthError::body_value)
    }

    pub(super) fn capture_native(&mut self) -> &AuthError {
        let status = self.status().0;
        let body = self.declared_body();
        self.native
            .get_or_insert_with(|| AuthError::from_status(status, body))
    }

    pub(super) fn response(&self) -> AuthResult<AuthResponse> {
        Ok(AuthResponse::json_value(
            self.status().1,
            self.body_value()?,
        ))
    }

    fn caught_response(&self) -> AuthResult<AuthResponse> {
        let body = match &self.native {
            Some(error) => caught_error_body(error)?,
            None => self.declared_body(),
        };
        Ok(verification_envelope(body))
    }
}

/// Distinguishes a rejected credential from a storage or infrastructure failure.
#[derive(Debug)]
pub enum ApiKeyVerificationError {
    /// The credential or its permissions, quota, or configuration was rejected.
    Validation(ApiKeyValidationError),
    /// An application API error caught by unscoped verification, including its complete response body.
    Rejected(AuthError),
    /// An internal operation failed. The original typed error is preserved.
    Internal(AuthError),
    /// An endpoint hook or scoped validator failed before the verification catch boundary.
    Endpoint(AuthError),
}

impl std::fmt::Display for ApiKeyVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => write!(formatter, "{}", error.message),
            Self::Internal(error) | Self::Endpoint(error) | Self::Rejected(error) => {
                write!(formatter, "API key verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for ApiKeyVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) | Self::Endpoint(error) | Self::Rejected(error) => Some(error),
            Self::Validation(_) => None,
        }
    }
}

impl ApiKeyVerificationError {
    /// Render the server-only endpoint's upstream response while retaining typed errors until this boundary.
    pub fn into_response(self) -> AuthResult<AuthResponse> {
        let error = match self {
            Self::Endpoint(error) => return Err(error),
            Self::Rejected(error) => return Ok(verification_envelope(caught_error_body(&error)?)),
            Self::Validation(error) => error,
            Self::Internal(_) => {
                ApiKeyValidationError::invalid_constant(ApiKeyErrorCode::InvalidApiKey)
            }
        };
        error.caught_response()
    }
}

impl From<AuthError> for ApiKeyVerificationError {
    fn from(error: AuthError) -> Self {
        Self::Internal(error)
    }
}

impl From<ApiKeyErrorCode> for ApiKeyVerificationError {
    fn from(code: ApiKeyErrorCode) -> Self {
        Self::Validation(ApiKeyValidationError::new(code))
    }
}

impl Serialize for ApiKeyValidationError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.body_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

fn caught_error_body(error: &AuthError) -> AuthResult<FieldValue> {
    let mut body = error.body_value()?.enumerable_fields()?;
    for name in ["message", "code"] {
        let value = error.body_value()?;
        let value = if value.is_null() || value.is_undefined() {
            FieldValue::Undefined
        } else {
            value.model_property(name)?
        };
        let _ = body.insert(name.into(), value);
    }
    Ok(body.into())
}

fn verification_envelope(body: FieldValue) -> AuthResponse {
    AuthResponse::json_value(
        None,
        FieldMap::from([
            ("valid".into(), false.into()),
            ("error".into(), body),
            ("key".into(), FieldValue::Null),
        ])
        .into(),
    )
}
