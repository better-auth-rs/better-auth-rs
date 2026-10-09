use thiserror::Error;

/// An endpoint error response whose body and headers are excluded from diagnostics.
pub struct ApiErrorResponse(Box<crate::types::AuthResponse>, bool);

impl std::fmt::Debug for ApiErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiErrorResponse")
            .field("status", &self.0.status)
            .finish()
    }
}

impl std::fmt::Display for ApiErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint rejected request (HTTP {})", self.0.status)
    }
}

/// Authentication framework error types.
///
/// Each variant maps to an HTTP status code via [`AuthError::status_code`].
/// Use [`AuthError::to_auth_response`] to produce a standardized JSON response
/// matching the better-auth OpenAPI spec: `{ "message": "..." }`.
#[derive(Error, Debug)]
pub enum AuthError {
    /// Runtime schema failures reject the host entry point before endpoint error handling.
    #[error(transparent)]
    SchemaCheck(std::sync::Arc<crate::store::schema::SchemaCheckError>),
    /// Preserve an endpoint's complete error body and repeated response headers.
    #[error("{0}")]
    Response(ApiErrorResponse),
    /// Public schema error with a field-specific message.
    #[error("{message}")]
    FieldInput {
        /// Upstream schema error code.
        code: &'static str,
        /// Validation message safe to return to the caller.
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
    /// Diagnostic message for tracing. Response headers are never included.
    pub fn instrumentation_message(&self) -> String {
        match self {
            Self::Response(response) => response
                .0
                .body
                .json()
                .ok()
                .flatten()
                .and_then(|body| {
                    body.get("message")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| self.to_string()),
            Self::Internal(message)
            | Self::TypeError(message)
            | Self::RangeError(message)
            | Self::Config(message)
            | Self::PasswordHash(message) => message.clone(),
            _ => self.to_string(),
        }
    }

    /// Create a redirect that bypasses the HTTP error callback, like upstream `FOUND`.
    /// Numeric 302 errors created from `AuthResponse` retain the ordinary API error policy.
    pub fn redirect(location: impl Into<String>) -> Self {
        Self::Response(ApiErrorResponse(
            Box::new(
                crate::AuthResponse::new(302)
                    .with_header("location", location)
                    .with_header("content-type", "application/json"),
            ),
            true,
        ))
    }

    /// Whether this error is an explicit `FOUND` redirect.
    pub fn is_found_redirect(&self) -> bool {
        matches!(self, Self::Response(ApiErrorResponse(_, true)))
    }

    /// Attach endpoint headers while preserving the redirect's error-policy behavior.
    pub fn capture_endpoint_headers(self, headers: crate::Headers) -> Self {
        match self {
            Self::Response(mut response) => {
                response.0.capture_error_headers(headers);
                Self::Response(response)
            }
            other => {
                let mut response = other.to_auth_response();
                response.capture_error_headers(headers);
                response.into()
            }
        }
    }

    /// Whether the error is an intentional endpoint rejection, including redirects and server API errors.
    pub fn is_api_error(&self) -> bool {
        match self {
            Self::Response(_)
            | Self::FieldInput { .. }
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
        if self.is_api_error() {
            self.to_auth_response().into_http_response()
        } else {
            crate::observability::logger::current().error(
                "Authentication request failed",
                &[crate::observability::LogArgument::Error(&self)],
            );
            Ok(crate::AuthResponse::new(500))
        }
    }

    /// Status owned by this error. Dispatch can preserve a different endpoint status for HTTP output.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Response(response) => response.0.api_error_status().unwrap_or(response.0.status),
            Self::FieldInput { .. } => 400,
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
        }
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
    pub fn error_payload(&self) -> (u16, Option<String>, String) {
        let status = self.status_code();
        let (code, message) = match self {
            Self::FieldInput { code, message } => (Some((*code).to_owned()), message.clone()),
            Self::Upstream { code, message, .. } => {
                (Some((*code).to_owned()), (*message).to_owned())
            }
            Self::BannedUser(message) => (Some("BANNED_USER".to_string()), message.clone()),
            _ => {
                let message = match status {
                    500 => {
                        crate::observability::logger::current().error(
                            "Internal server error",
                            &[crate::observability::LogArgument::Error(&self)],
                        );
                        "Internal server error".to_string()
                    }
                    _ => self.to_string(),
                };
                let code = Self::code_from_message(&message);
                (code, message)
            }
        };
        (status, code, message)
    }

    /// Convert this error into a standardized [`AuthResponse`](crate::types::AuthResponse) matching the
    /// better-auth spec: `{ "code": "...", "message": "..." }`.
    ///
    /// Named `to_auth_response` to avoid collision with Axum's
    /// `IntoResponse::into_response` when the `axum` feature is enabled.
    pub fn to_auth_response(self) -> crate::types::AuthResponse {
        if let Self::Response(response) = self {
            return (*response.0).into_api_error();
        }
        if let Self::PasswordHash(error) = self {
            crate::observability::logger::current().error(
                "Password hashing failed",
                &[crate::observability::LogArgument::Value(
                    &serde_json::json!(error),
                )],
            );
            return crate::types::AuthResponse::new(500);
        }
        let is_api_error = self.is_api_error();
        let (status, code, message) = self.error_payload();
        let response = crate::types::AuthResponse::json(
            status,
            &crate::types::ErrorCodeMessageResponse {
                code,
                message: message.clone(),
            },
        )
        .unwrap_or_else(|_| crate::types::AuthResponse::text(status, &message));
        if is_api_error {
            response.into_api_error()
        } else {
            response
        }
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

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Constraint violation: {0}")]
    Constraint(String),

    /// A uniqueness conflict that callers may resolve by generating another value.
    #[error("Unique constraint violation: {0}")]
    UniqueConstraint(String),

    #[error("Transaction error: {0}")]
    Transaction(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

impl From<crate::types::AuthResponse> for AuthError {
    fn from(response: crate::types::AuthResponse) -> Self {
        Self::Response(ApiErrorResponse(Box::new(response), false))
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let response = match self.to_auth_response().into_http_response() {
            Ok(response) => response,
            Err(error) => return error.into_response(),
        };
        let body = match response.body.into_bytes() {
            Ok(body) => body,
            Err(error) => return error.into_response(),
        };
        let status = axum::http::StatusCode::from_u16(response.status)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let mut output = axum::response::Response::new(axum::body::Body::from(body));
        *output.status_mut() = status;
        for (name, value) in response.headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                axum::http::HeaderValue::from_str(&value),
            ) {
                let _ = output.headers_mut().append(name, value);
            }
        }
        output
    }
}

/// Convert `validator::ValidationErrors` into a standardized error response body.
///
/// Returns a 400 response with `{ "code": "VALIDATION_ERROR", "message": "[body.field] ..." }`
/// matching the TS better-auth error shape.
pub fn validation_error_response(
    errors: &validator::ValidationErrors,
) -> crate::types::AuthResponse {
    // Build a TS-compatible message: "[body.field] message; [body.field2] message2"
    let messages: Vec<String> = errors
        .field_errors()
        .into_iter()
        .flat_map(|(field, errs)| {
            errs.iter().map(move |e| {
                let msg = e
                    .message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| format!("Invalid value for {}", field));
                format!("[body.{}] {}", field, msg)
            })
        })
        .collect();
    let message = messages.join("; ");

    let body = crate::types::ErrorCodeMessageResponse {
        code: Some("VALIDATION_ERROR".to_string()),
        message,
    };

    // Validation errors return 400 (not 422) per the TS spec
    crate::types::AuthResponse::json(400, &body)
        .unwrap_or_else(|_| crate::types::AuthResponse::text(400, "Validation failed"))
}

/// Validate a request body, returning a parsed + validated value or an error response.
pub fn validate_request_body<T>(
    req: &crate::types::AuthRequest,
) -> Result<T, crate::types::AuthResponse>
where
    T: serde::de::DeserializeOwned + validator::Validate,
{
    let value: T = req.body_as_json().map_err(|e| {
        let message = format!("Invalid JSON: {}", e);
        let code = AuthError::code_from_message(&message);
        crate::types::AuthResponse::json(
            400,
            &crate::types::ErrorCodeMessageResponse { code, message },
        )
        .unwrap_or_else(|_| crate::types::AuthResponse::text(400, "Invalid JSON"))
    })?;

    value
        .validate()
        .map_err(|e| validation_error_response(&e))?;

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_error_preserves_body_headers_and_redacts_diagnostics() {
        let body = serde_json::json!({"code":"RATE_LIMITED", "message":"Rate limit exceeded.", "details":{"tryAgainIn":1234}});
        let mut response = crate::types::AuthResponse::json(429, &body).unwrap();
        response.headers.append("Set-Cookie", "sensitive=first");
        response.headers.append("Set-Cookie", "sensitive=second");
        let error = AuthError::from(response);
        assert_eq!(error.status_code(), 429);
        assert!(!format!("{error:?} {error}").contains("sensitive"));
        assert!(!format!("{error:?} {error}").contains("tryAgainIn"));
        let response = error.to_auth_response();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
            body
        );
        assert_eq!(
            response.headers.get_all("set-cookie").collect::<Vec<_>>(),
            ["sensitive=first", "sensitive=second"]
        );
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn endpoint_error_into_axum_preserves_json_and_repeated_headers() {
        use axum::response::IntoResponse;
        let mut response = crate::types::AuthResponse::json(
            429,
            &serde_json::json!({"details":{"tryAgainIn":1234}}),
        )
        .unwrap();
        response.headers.append("Set-Cookie", "first=1");
        response.headers.append("Set-Cookie", "second=2");
        let output = AuthError::from(response).into_response();
        assert_eq!(output.status(), 429);
        assert_eq!(output.headers().get_all("set-cookie").iter().count(), 2);
        assert_eq!(output.headers()["content-type"], "application/json");
        let body = axum::body::to_bytes(output.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["details"]["tryAgainIn"],
            1234
        );
    }

    // ── status_code ─────────────────────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn bad_request_is_400() {
        assert_eq!(AuthError::bad_request("oops").status_code(), 400);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn invalid_request_is_400() {
        assert_eq!(AuthError::InvalidRequest("x".into()).status_code(), 400);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn validation_is_400() {
        assert_eq!(AuthError::validation("x").status_code(), 400);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn invalid_credentials_is_401() {
        assert_eq!(AuthError::InvalidCredentials.status_code(), 401);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn unauthenticated_is_401() {
        assert_eq!(AuthError::Unauthenticated.status_code(), 401);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn session_not_found_is_401() {
        assert_eq!(AuthError::SessionNotFound.status_code(), 401);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn forbidden_is_403() {
        assert_eq!(AuthError::forbidden("nope").status_code(), 403);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn unauthorized_is_403() {
        assert_eq!(AuthError::Unauthorized.status_code(), 403);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn not_found_is_404() {
        assert_eq!(AuthError::not_found("gone").status_code(), 404);
        assert_eq!(AuthError::UserNotFound.status_code(), 404);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn conflict_is_409() {
        assert_eq!(AuthError::conflict("dup").status_code(), 409);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn unprocessable_entity_is_422() {
        assert_eq!(
            AuthError::UnprocessableEntity("x".into()).status_code(),
            422
        );
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn rate_limited_is_429() {
        assert_eq!(AuthError::RateLimited.status_code(), 429);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn not_implemented_is_501() {
        assert_eq!(AuthError::not_implemented("todo").status_code(), 501);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn internal_errors_are_500() {
        assert_eq!(AuthError::config("bad").status_code(), 500);
        assert_eq!(AuthError::internal("fail").status_code(), 500);
        assert_eq!(AuthError::plugin("p", "m").status_code(), 500);
        assert_eq!(AuthError::PasswordHash("h".into()).status_code(), 500);
        assert_eq!(
            AuthError::Database(DatabaseError::Connection("c".into())).status_code(),
            500
        );
    }

    // ── code_from_message ───────────────────────────────────────────────

    // Upstream reference: BASE_ERROR_CODES in @better-auth/core — a message
    // upstream defines a constant for carries that constant.
    #[test]
    fn code_from_message_returns_the_upstream_constant() {
        assert_eq!(
            AuthError::code_from_message("User not found").as_deref(),
            Some("USER_NOT_FOUND")
        );
    }

    // Upstream reference: packages/core/src/error/index.ts :: `APIError.from`
    // attaches a code, while `new APIError(status, { message })` does not — so
    // a message outside every upstream table has no code on the wire.
    #[test]
    fn code_from_message_is_none_for_unknown_messages() {
        assert_eq!(AuthError::code_from_message("invalid email!"), None);
        assert_eq!(AuthError::code_from_message("Email is the same"), None);
        assert_eq!(AuthError::code_from_message(""), None);
    }

    // Upstream reference: plugin tables built with `defineErrorCodes` are part
    // of the same vocabulary, not just the base set.
    #[test]
    fn code_from_message_covers_plugin_tables() {
        assert_eq!(
            AuthError::code_from_message("Username is already taken. Please try another.")
                .as_deref(),
            Some("USERNAME_IS_ALREADY_TAKEN")
        );
    }

    // Upstream reference: BASE_ERROR_CODES in @better-auth/core ::
    // packages/core/src/error/codes.ts — codes are explicit constants since
    // better-auth 1.5, so these must not be re-derived from the message.
    #[test]
    fn base_error_codes_are_not_derived_from_the_message() {
        for (message, expected) in [
            ("Invalid callbackURL", "INVALID_CALLBACK_URL"),
            ("Invalid redirectURL", "INVALID_REDIRECT_URL"),
            ("Invalid errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"),
            (
                "Invalid newUserCallbackURL",
                "INVALID_NEW_USER_CALLBACK_URL",
            ),
            ("Email is already verified", "EMAIL_ALREADY_VERIFIED"),
            (
                "Verification email isn't enabled",
                "VERIFICATION_EMAIL_NOT_ENABLED",
            ),
            (
                "Session expired. Re-authenticate to perform this action.",
                "SESSION_EXPIRED",
            ),
            (
                "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
                "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
            ),
        ] {
            assert_eq!(
                AuthError::code_from_message(message).as_deref(),
                Some(expected),
                "message {message:?} must carry the upstream constant"
            );
        }
    }

    // ── error_payload ───────────────────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn error_payload_for_client_error() {
        // Not an upstream message, so it goes out without a code.
        let (status, code, message) = AuthError::bad_request("Missing field").error_payload();
        assert_eq!(status, 400);
        assert_eq!(code, None);
        assert_eq!(message, "Missing field");

        let (status, code, message) = AuthError::bad_request("Field is required").error_payload();
        assert_eq!(status, 400);
        assert_eq!(code.as_deref(), Some("MISSING_FIELD"));
        assert_eq!(message, "Field is required");
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn error_payload_for_internal_error_hides_details() {
        let (status, _code, message) = AuthError::internal("secret detail").error_payload();
        assert_eq!(status, 500);
        assert_eq!(message, "Internal server error");
    }

    // ── to_auth_response ────────────────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn to_auth_response_returns_correct_status() {
        let resp = AuthError::bad_request("oops").to_auth_response();
        assert_eq!(resp.status, 400);
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn to_auth_response_body_contains_code_and_message() {
        let resp = AuthError::UserNotFound.to_auth_response();
        assert_eq!(resp.status, 404);
        let body: serde_json::Value = serde_json::from_slice(&resp.body.bytes().unwrap())
            .expect("response body should be valid JSON");
        assert_eq!(body["code"], "USER_NOT_FOUND");
        assert_eq!(body["message"], "User not found");
    }

    // ── constructor helpers ──────────────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn constructor_helpers_produce_correct_variants() {
        // Each helper should produce the expected Display output
        assert_eq!(AuthError::bad_request("x").to_string(), "x");
        assert_eq!(AuthError::forbidden("x").to_string(), "x");
        assert_eq!(AuthError::not_found("x").to_string(), "x");
        assert_eq!(AuthError::conflict("x").to_string(), "x");
        assert_eq!(AuthError::not_implemented("x").to_string(), "x");
        assert_eq!(AuthError::config("x").to_string(), "Configuration error: x");
        assert_eq!(
            AuthError::internal("x").to_string(),
            "Internal server error: x"
        );
        assert_eq!(
            AuthError::validation("x").to_string(),
            "Validation error: x"
        );
        assert_eq!(
            AuthError::plugin("p", "m").to_string(),
            "Plugin error: p - m"
        );
    }

    // ── DatabaseError ───────────────────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn database_error_display() {
        let e = DatabaseError::Connection("timeout".into());
        assert_eq!(e.to_string(), "Connection error: timeout");
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn database_error_converts_to_auth_error() {
        let db_err = DatabaseError::Query("bad sql".into());
        let auth_err: AuthError = db_err.into();
        assert_eq!(auth_err.status_code(), 500);
    }

    // ── validation_error_response ───────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn validation_error_response_serializes_field_errors() {
        let mut errors = validator::ValidationErrors::new();
        let mut error = validator::ValidationError::new("email");
        error.message = Some("Email is invalid".into());
        errors.add("email", error);

        let resp = validation_error_response(&errors);
        assert_eq!(resp.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&resp.body.bytes().unwrap())
            .expect("response body should be valid JSON");
        assert_eq!(body["code"], "VALIDATION_ERROR");
        assert_eq!(body["message"], "[body.email] Email is invalid");
    }

    // ── Display for fixed-message variants ──────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn fixed_message_variants_display() {
        assert_eq!(
            AuthError::InvalidCredentials.to_string(),
            "Invalid email or password"
        );
        assert_eq!(AuthError::Unauthenticated.to_string(), "Unauthorized");
        assert_eq!(
            AuthError::SessionNotFound.to_string(),
            "Session not found or expired"
        );
        assert_eq!(
            AuthError::Unauthorized.to_string(),
            "Insufficient permissions"
        );
        assert_eq!(AuthError::UserNotFound.to_string(), "User not found");
        assert_eq!(AuthError::RateLimited.to_string(), "Too many requests");
    }
}
