use crate::{FieldMap, FieldValue, SchemaValue};
use thiserror::Error;

mod database;
mod http;
mod native;
mod native_value;
mod shared;
pub use database::{DatabaseError, DatabaseErrorCause};
#[cfg(test)]
pub(crate) use native::brand_api_error_object;
pub use native::{
    ApiErrorClass, ApiErrorInit, api_error_instance, is_api_error_value, is_error_value,
};
pub use shared::SharedAuthError;

/// A thrown native value whose properties are excluded from Rust diagnostics.
pub struct ApiErrorResponse {
    value: FieldValue,
    captured_headers: Option<FieldValue>,
}

impl std::fmt::Debug for ApiErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiErrorResponse").finish_non_exhaustive()
    }
}

impl std::fmt::Display for ApiErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Native endpoint error")
    }
}

/// Authentication framework error types.
///
/// Native errors retain their status values until HTTP materialization.
/// Typed variants remain available for ordinary Rust callers.
#[derive(Error, Debug)]
pub enum AuthError {
    /// An original error retained across a transport that shares ownership.
    #[error(transparent)]
    Shared(SharedAuthError),
    /// Runtime schema failures reject the host entry point before endpoint error handling.
    #[error(transparent)]
    SchemaCheck(std::sync::Arc<crate::store::schema::SchemaCheckError>),
    /// Preserve a thrown value, its object identity, and captured endpoint headers.
    #[error("{0}")]
    Response(ApiErrorResponse),
    /// Better Auth field-policy error with a named `BAD_REQUEST` status.
    #[error("{message}")]
    FieldInput {
        /// Upstream schema error code.
        code: &'static str,
        /// Validation message safe to return to the caller.
        message: String,
    },
    /// Better Call request-schema error with a numeric 400 status.
    #[error("{message}")]
    RequestValidation {
        /// Ordered validation issues safe to return to the caller.
        message: String,
    },
    /// A documented upstream API error whose message is safe to return publicly.
    #[error("{message}")]
    Upstream {
        /// HTTP response status defined by the upstream endpoint.
        status: u16,
        /// Stable upstream error code.
        code: &'static str,
        /// Documented public error message. Never include internal failure details.
        message: &'static str,
    },

    #[error("{0}")]
    BadRequest(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid email or password")]
    InvalidCredentials,

    #[error("Unauthorized")]
    Unauthenticated,

    #[error("{0}")]
    AuthenticationFailed(String),

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    BannedUser(String),

    #[error("Insufficient permissions")]
    Unauthorized,

    #[error("User not found")]
    UserNotFound,

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    MethodNotAllowed(String),

    #[error("{0}")]
    PayloadTooLarge(String),

    #[error("{0}")]
    UnprocessableEntity(String),

    #[error("Too many requests")]
    RateLimited,

    #[error("{0}")]
    NotImplemented(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    /// Redis cache failure with the original source error.
    #[cfg(feature = "redis-cache")]
    #[error("Redis cache error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Plugin error: {plugin} - {message}")]
    Plugin { plugin: String, message: String },

    /// A structured clone encountered a function value.
    #[error("The object can not be cloned.")]
    DataClone,

    /// A native value rejected a JavaScript property or method operation.
    #[error("{0}")]
    TypeError(String),

    /// A native value is outside a runtime constructor's accepted range.
    #[error("{0}")]
    RangeError(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl AuthError {
    /// Construct an upstream BetterAuthError with native identity and hidden error properties.
    pub fn better_auth(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::better_auth_native(message)
    }

    /// Preserve UTF-16 message code units in the shared native BetterAuthError representation.
    pub fn better_auth_native(message: impl Into<crate::Utf16String>) -> Self {
        Self::from_thrown(native::better_auth(message.into()))
    }

    /// Construct an API error and execute message and cause access at this call boundary.
    pub fn try_api_error(init: ApiErrorInit) -> AuthResult<Self> {
        Ok(Self::from_thrown(native::construct(init)?))
    }

    /// Retain a thrown value without constructing an API error or reading properties.
    pub fn from_thrown(value: FieldValue) -> Self {
        Self::Response(ApiErrorResponse {
            value,
            captured_headers: None,
        })
    }

    /// Recover an already returned error without running its constructor again.
    pub fn from_returned_response(response: crate::AuthResponse) -> AuthResult<Self> {
        let captured_headers = response.captured_headers_value();
        let mut error = Self::from_thrown(response.body.field_value()?);
        if let Some(headers) = captured_headers {
            error = error.capture_native_headers(headers);
        }
        Ok(error)
    }

    /// Borrow a native thrown value without projecting its properties.
    pub fn raw_value(&self) -> Option<&FieldValue> {
        match self.original() {
            Self::Response(error) => Some(&error.value),
            Self::Database(error) => Some(error.native_value()),
            _ => None,
        }
    }

    /// Construct an API error with the original status and explicit body, including constructor failures.
    pub fn from_status(status: impl Into<FieldValue>, body: FieldValue) -> Self {
        match Self::try_api_error(ApiErrorInit {
            status: status.into(),
            body,
            ..Default::default()
        }) {
            Ok(error) | Err(error) => error,
        }
    }

    /// Construct an upstream coded API error with `message` before `code` in the native body.
    /// Use [`Self::from_status`] to preserve an explicit error body instead.
    pub fn from_code(
        status: impl Into<FieldValue>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::from_status(
            status,
            FieldMap::from([
                ("message".into(), message.into().into()),
                ("code".into(), code.into().into()),
            ])
            .into(),
        )
    }

    /// Diagnostic message for tracing. Response headers are never included.
    pub fn instrumentation_message(&self) -> AuthResult<String> {
        let message = self.message_value()?;
        let value = if message.is_null() || message.is_undefined() {
            self.raw_value()
                .cloned()
                .unwrap_or_else(|| self.to_string().into())
        } else {
            message
        };
        SchemaValue::<String>::from_field(value).display_string()
    }

    /// Read the current top-level message independently of the error body.
    pub fn message_value(&self) -> AuthResult<FieldValue> {
        if let Some(value) = self.raw_value() {
            return native::optional_property(value, "message");
        }
        Ok(match self.original() {
            Self::Internal(message)
            | Self::TypeError(message)
            | Self::RangeError(message)
            | Self::Config(message)
            | Self::PasswordHash(message) => message.clone().into(),
            _ => self.to_string().into(),
        })
    }

    /// Read the original status value, which can be a symbolic name or any native value.
    pub fn status_value(&self) -> AuthResult<FieldValue> {
        if let Some(value) = self.raw_value() {
            return native::optional_property(value, "status");
        }
        match self.original() {
            Self::FieldInput { .. } => Ok("BAD_REQUEST".into()),
            _ => Ok(self.status_code()?.into_field_value()),
        }
    }

    /// Read one current body value without applying JSON conversion.
    pub fn body_value(&self) -> AuthResult<FieldValue> {
        if let Some(value) = self.raw_value() {
            return native::optional_property(value, "body");
        }
        let (_, code, message) = self.error_payload()?;
        let mut fields = FieldMap::new();
        if matches!(
            self.original(),
            Self::FieldInput { .. } | Self::RequestValidation { .. }
        ) {
            let _ = fields.insert("message".into(), message.clone().into());
        }
        if let Some(code) = code {
            let _ = fields.insert("code".into(), code.into());
        }
        let _ = fields.insert("message".into(), message.into());
        Ok(fields.into())
    }

    /// Read one current header initializer without converting or copying its object.
    pub fn headers_value(&self) -> AuthResult<FieldValue> {
        match self.raw_value() {
            Some(value) => native::optional_property(value, "headers"),
            None => Ok(FieldMap::new().into()),
        }
    }

    /// Create a redirect that bypasses the HTTP error callback, like upstream `FOUND`.
    /// Numeric 302 errors created from `AuthResponse` retain the ordinary API error policy.
    pub fn redirect(location: impl Into<String>) -> Self {
        match Self::try_api_error(ApiErrorInit {
            status: "FOUND".into(),
            headers: FieldMap::from([("location".into(), location.into().into())]).into(),
            ..Default::default()
        }) {
            Ok(error) | Err(error) => error,
        }
    }

    /// Whether this error is an explicit `FOUND` redirect.
    pub fn is_found_redirect(&self) -> AuthResult<bool> {
        Ok(self.is_api_error()? && self.status_value()?.strict_equals(&"FOUND".into()))
    }

    /// Attach endpoint headers while preserving the redirect's error-policy behavior.
    pub fn capture_endpoint_headers(self, headers: crate::Headers) -> Self {
        self.capture_native_headers(headers.into())
    }

    /// Retain captured endpoint headers, including the original initializer identity.
    pub fn capture_native_headers(self, headers: FieldValue) -> Self {
        match self {
            Self::Shared(mut error)
                if matches!(
                    error.source.original(),
                    Self::Response(_) | Self::Database(_)
                ) =>
            {
                error.captured_headers = Some(headers);
                Self::Shared(error)
            }
            Self::Response(mut response) => {
                response.captured_headers = Some(headers);
                Self::Response(response)
            }
            Self::Database(mut error) => {
                error.capture_native_headers(headers);
                Self::Database(error)
            }
            other => match other
                .to_auth_response()
                .and_then(Self::from_returned_response)
            {
                Ok(error) => error.capture_native_headers(headers),
                Err(error) => error,
            },
        }
    }

    /// Read captured endpoint headers without materializing a Headers value.
    pub fn captured_headers_value(&self) -> Option<FieldValue> {
        match self {
            Self::Shared(error) => error
                .captured_headers
                .clone()
                .or_else(|| error.source.captured_headers_value()),
            Self::Response(response) => response.captured_headers.clone(),
            Self::Database(error) => error.captured_headers_value(),
            _ => None,
        }
    }

    /// Whether the error is an intentional endpoint rejection, including redirects and server API errors.
    pub fn is_api_error(&self) -> AuthResult<bool> {
        if let Some(value) = self.raw_value() {
            return is_api_error_value(value);
        }
        Ok(self.is_api_error_instance(ApiErrorClass::BetterCall))
    }

    /// Check JavaScript Error inheritance without reading the object's name or message.
    pub fn is_error_instance(&self) -> bool {
        self.raw_value().is_none_or(is_error_value)
    }

    /// Check the constructor family without invoking a structural name getter.
    pub fn is_api_error_instance(&self, class: ApiErrorClass) -> bool {
        match self {
            Self::Shared(error) => error.source.is_api_error_instance(class),
            Self::Response(error) => api_error_instance(&error.value, class),
            Self::RequestValidation { .. } => class == ApiErrorClass::BetterCall,
            Self::FieldInput { .. }
            | Self::Upstream { .. }
            | Self::BadRequest(_)
            | Self::InvalidRequest(_)
            | Self::Validation(_)
            | Self::InvalidCredentials
            | Self::Unauthenticated
            | Self::AuthenticationFailed(_)
            | Self::SessionNotFound
            | Self::Forbidden(_)
            | Self::BannedUser(_)
            | Self::Unauthorized
            | Self::UserNotFound
            | Self::NotFound(_)
            | Self::Conflict(_)
            | Self::MethodNotAllowed(_)
            | Self::PayloadTooLarge(_)
            | Self::UnprocessableEntity(_)
            | Self::RateLimited
            | Self::NotImplemented(_) => true,
            Self::SchemaCheck(_)
            | Self::Config(_)
            | Self::Database(_)
            | Self::Serialization(_)
            | Self::Plugin { .. }
            | Self::Internal(_)
            | Self::TypeError(_)
            | Self::RangeError(_)
            | Self::DataClone
            | Self::PasswordHash(_)
            | Self::Jwt(_) => false,
            #[cfg(feature = "redis-cache")]
            Self::Redis(_) => false,
        }
    }

    /// Serialize an HTTP endpoint failure without exposing ordinary runtime errors.
    pub fn to_http_response(self) -> AuthResult<crate::AuthResponse> {
        if self.is_api_error()? {
            self.to_auth_response()?.into_http_response()
        } else {
            crate::observability::logger::default_logger().error(
                "Authentication request failed",
                &[crate::observability::LogArgument::Error(&self)],
            )?;
            let mut response = crate::AuthResponse::new(500);
            response.status_text = "Internal Server Error".into();
            Ok(response)
        }
    }

    /// Status owned by this error. Dispatch can preserve a different endpoint status for HTTP output.
    pub fn status_code(&self) -> AuthResult<SchemaValue<u16>> {
        if let Some(value) = self.raw_value() {
            return Ok(SchemaValue::from_field(native::optional_property(
                value,
                "statusCode",
            )?));
        }
        let status = match self {
            Self::Shared(error) => return error.source.status_code(),
            Self::FieldInput { .. } | Self::RequestValidation { .. } => 400,
            Self::Upstream { status, .. } => *status,
            // 400
            Self::BadRequest(_) | Self::InvalidRequest(_) | Self::Validation(_) => 400,
            // 401
            Self::InvalidCredentials
            | Self::Unauthenticated
            | Self::AuthenticationFailed(_)
            | Self::SessionNotFound => 401,
            // 403
            Self::Forbidden(_) | Self::BannedUser(_) | Self::Unauthorized => 403,
            // 404
            Self::UserNotFound | Self::NotFound(_) => 404,
            // 409
            Self::Conflict(_) => 409,
            // 405
            Self::MethodNotAllowed(_) => 405,
            // 413
            Self::PayloadTooLarge(_) => 413,
            // 422
            Self::UnprocessableEntity(_) => 422,
            // 429
            Self::RateLimited => 429,
            // 501
            Self::NotImplemented(_) => 501,
            // 500
            #[cfg(feature = "redis-cache")]
            Self::Redis(_) => 500,
            Self::SchemaCheck(_)
            | Self::Response(_)
            | Self::Config(_)
            | Self::Database(_)
            | Self::Serialization(_)
            | Self::Plugin { .. }
            | Self::Internal(_)
            | Self::TypeError(_)
            | Self::RangeError(_)
            | Self::DataClone
            | Self::PasswordHash(_)
            | Self::Jwt(_) => 500,
        };
        Ok(SchemaValue::Typed(status))
    }

    /// Resolve the wire error code for a message, if upstream defines one.
    ///
    /// better-auth 1.5 replaced message-derived codes with explicit constants,
    /// and only errors built from one of those constants carry a `code` at all
    /// (`APIError.from` sets it; a plain `new APIError(status, { message })`
    /// does not). So an unknown message yields `None` and the field is omitted,
    /// rather than being back-derived from the text.
    pub fn code_from_message(message: &str) -> Option<String> {
        crate::error_codes::upstream_code(message).map(str::to_string)
    }

    /// Compute the HTTP status, error code, and user-facing message.
    ///
    /// The code is `None` for messages upstream has no constant for; those
    /// responses carry only a `message`.
    ///
    /// Internal errors (500) are logged and replaced with a generic message
    /// to avoid leaking details.
    pub fn error_payload(&self) -> AuthResult<(SchemaValue<u16>, Option<String>, String)> {
        let status = self.status_code()?;
        if self.raw_value().is_some() {
            let body = self.body_value()?;
            let code = native::optional_property(&body, "code")?;
            let code = if code.is_undefined() {
                None
            } else {
                Some(code.decode::<String>()?)
            };
            let message = native::optional_property(&body, "message")?.decode::<String>()?;
            return Ok((status, code, message));
        }
        let (code, message) = match self.original() {
            Self::FieldInput { code, message } => (Some((*code).to_owned()), message.clone()),
            Self::RequestValidation { message } => {
                (Some("VALIDATION_ERROR".into()), message.clone())
            }
            Self::Upstream { code, message, .. } => {
                (Some((*code).to_owned()), (*message).to_owned())
            }
            Self::BannedUser(message) => (Some("BANNED_USER".to_string()), message.clone()),
            _ => {
                let message = if status == 500 {
                    crate::observability::logger::current().error(
                        "Internal server error",
                        &[crate::observability::LogArgument::Error(self)],
                    )?;
                    "Internal server error".to_string()
                } else {
                    self.to_string()
                };
                let code = Self::code_from_message(&message);
                (code, message)
            }
        };
        Ok((status, code, message))
    }

    /// Convert this error into an [`AuthResponse`](crate::types::AuthResponse).
    /// Native errors move their complete raw value without reading properties.
    /// Input errors retain their constructor class, status, and message-first coded body.
    /// Legacy convenience variants generate a code-first body from [`Self::error_payload`].
    ///
    /// Named `to_auth_response` to avoid collision with Axum's
    /// `IntoResponse::into_response` when the `axum` feature is enabled.
    pub fn to_auth_response(self) -> AuthResult<crate::types::AuthResponse> {
        let mut response = self.original().response_view()?;
        if let Some(headers) = self.captured_headers_value() {
            response.capture_native_error_headers(headers);
        }
        Ok(response)
    }

    fn response_view(&self) -> AuthResult<crate::types::AuthResponse> {
        if let Some(value) = self.raw_value() {
            let mut response = crate::AuthResponse::native(None, value.clone());
            response.set_endpoint_headers(None);
            return Ok(response);
        }
        if let Self::PasswordHash(error) = self {
            crate::observability::logger::current().error(
                "Password hashing failed",
                &[crate::observability::LogArgument::Value(
                    &serde_json::json!(error),
                )],
            )?;
            return Ok(crate::types::AuthResponse::new(500));
        }
        if self.is_api_error_instance(ApiErrorClass::BetterCall) {
            let mut response = crate::AuthResponse::native(None, self.callback_value()?);
            response.set_endpoint_headers(None);
            return Ok(response);
        }
        let status = self.status_code()?;
        let body = self.body_value()?;
        Ok(crate::AuthResponse::native(Some(*status.typed()?), body))
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    pub fn banned_user(message: impl Into<String>) -> Self {
        Self::BannedUser(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    pub fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::MethodNotAllowed(message.into())
    }

    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::PayloadTooLarge(message.into())
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::NotImplemented(message.into())
    }

    pub fn plugin(plugin: &str, message: impl Into<String>) -> Self {
        Self::Plugin {
            plugin: plugin.to_string(),
            message: message.into(),
        }
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Preserve a native TypeError for server callers and error callbacks.
    pub fn type_error(message: impl Into<String>) -> Self {
        Self::TypeError(message.into())
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn authentication_failed(message: impl Into<String>) -> Self {
        Self::AuthenticationFailed(message.into())
    }
}

pub type AuthResult<T> = Result<T, AuthError>;

impl From<crate::types::AuthResponse> for AuthError {
    fn from(response: crate::types::AuthResponse) -> Self {
        let status = if response.is_native() {
            response.native_status().field_value()
        } else {
            f64::from(response.status).into()
        };
        let captured_headers = response.captured_headers_value();
        let headers = match response.explicit_response_headers().cloned() {
            Some(mut owned) => {
                owned.merge(response.headers.clone());
                owned
            }
            None => response.headers.clone(),
        };
        let body = match &response.body {
            crate::ResponseBody::Bytes(bytes)
                if headers.get("content-type").is_some_and(|value| {
                    value
                        .get(..5)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/"))
                }) =>
            {
                std::str::from_utf8(bytes)
                    .map(|text| FieldValue::from(text.to_owned()))
                    .map_err(|error| {
                        AuthError::internal(format!(
                            "Cannot decode explicit text response as UTF-8: {error}"
                        ))
                    })
            }
            body => body.field_value(),
        };
        let body = match body {
            Ok(body) => body,
            Err(error) => return error,
        };
        match Self::try_api_error(ApiErrorInit {
            status,
            body,
            headers: headers.into(),
            ..Default::default()
        }) {
            Ok(mut error) => {
                if let Some(headers) = captured_headers {
                    error = error.capture_native_headers(headers);
                }
                error
            }
            Err(error) => error,
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        finish_axum_response(self.to_http_response())
    }
}

/// Materialize native response values once at the Axum transport boundary.
#[cfg(feature = "axum")]
#[doc(hidden)]
pub fn materialize_axum_response(
    response: crate::AuthResponse,
) -> AuthResult<axum::response::Response> {
    let response = response.into_http_response()?;
    let body = response.body.into_bytes()?;
    let mut output = axum::response::Response::builder().status(response.status);
    for (name, value) in response.headers {
        output = output.header(name, value);
    }
    output
        .body(axum::body::Body::from(body))
        .map_err(|error| AuthError::internal(format!("Cannot build Axum response: {error}")))
}

/// Axum cannot return a conversion failure; report once without invoking application callbacks.
#[cfg(feature = "axum")]
#[doc(hidden)]
pub fn finish_axum_response(response: AuthResult<crate::AuthResponse>) -> axum::response::Response {
    match response.and_then(materialize_axum_response) {
        Ok(response) => response,
        Err(error) => {
            crate::observability::report_terminal_error("axum response", error);
            let mut response =
                axum::response::Response::new(axum::body::Body::from("Internal server error"));
            *response.status_mut() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

/// Convert `validator::ValidationErrors` into a standardized error response body.
///
/// Returns a 400 response with `{ "code": "VALIDATION_ERROR", "message": "[body.field] ..." }`
/// matching the TS better-auth error shape.
pub fn validation_error_response(
    errors: &validator::ValidationErrors,
) -> crate::types::AuthResponse {
    crate::types::AuthResponse::json_value(400, validation_error_fields(errors).into())
}

fn validation_error_fields(errors: &validator::ValidationErrors) -> FieldMap {
    let messages: Vec<String> = errors
        .field_errors()
        .into_iter()
        .flat_map(|(field, errs)| {
            errs.iter().map(move |error| {
                let message = error
                    .message
                    .as_ref()
                    .map(|message| message.to_string())
                    .unwrap_or_else(|| format!("Invalid value for {field}"));
                format!("[body.{field}] {message}")
            })
        })
        .collect();
    FieldMap::from([
        ("code".into(), "VALIDATION_ERROR".into()),
        ("message".into(), messages.join("; ").into()),
    ])
}

/// Parse and validate a request body, preserving failures as native API errors.
pub fn validate_request_body<T>(req: &crate::types::AuthRequest) -> AuthResult<T>
where
    T: serde::de::DeserializeOwned + validator::Validate,
{
    let value: T = match req.body_as_json() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("Invalid JSON: {error}");
            let mut body = FieldMap::new();
            if let Some(code) = AuthError::code_from_message(&message) {
                let _ = body.insert("code".into(), code.into());
            }
            let _ = body.insert("message".into(), message.into());
            return Err(AuthError::try_api_error(ApiErrorInit {
                status: 400.0.into(),
                body: body.into(),
                ..Default::default()
            })?);
        }
    };
    if let Err(errors) = value.validate() {
        return Err(AuthError::try_api_error(ApiErrorInit {
            status: 400.0.into(),
            body: validation_error_fields(&errors).into(),
            ..Default::default()
        })?);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "error/construction_tests.rs"]
mod construction_tests;

#[cfg(test)]
#[path = "error/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "error/native_tests.rs"]
mod native_tests;

#[cfg(test)]
mod http_tests;

#[cfg(test)]
#[path = "error/logger_boundary_tests.rs"]
mod logger_boundary_tests;
