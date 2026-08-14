use thiserror::Error;

/// Authentication framework error types.
///
/// Each variant maps to an HTTP status code via [`AuthError::status_code`].
/// Use [`AuthError::to_auth_response`] to produce a standardized JSON response
/// matching the better-auth OpenAPI spec: `{ "message": "..." }`.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    BadRequest(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid email or password")]
    InvalidCredentials,

    #[error("Authentication required")]
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
    UnprocessableEntity(String),

    #[error("Too many requests")]
    RateLimited,

    #[error("{0}")]
    NotImplemented(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Plugin error: {plugin} - {message}")]
    Plugin { plugin: String, message: String },

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl AuthError {
    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
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
            // 422
            Self::UnprocessableEntity(_) => 422,
            // 429
            Self::RateLimited => 429,
            // 501
            Self::NotImplemented(_) => 501,
            // 500
            Self::Config(_)
            | Self::Database(_)
            | Self::Serialization(_)
            | Self::Plugin { .. }
            | Self::Internal(_)
            | Self::PasswordHash(_)
            | Self::Jwt(_) => 500,
        }
    }

    /// Derive the error code from the message, matching the TS better-auth
    /// behavior: `message.toUpperCase().replace(/ /g, "_").replace(/[^A-Z0-9_]/g, "")`.
    pub fn code_from_message(message: &str) -> String {
        message
            .to_uppercase()
            .chars()
            .map(|c| if c == ' ' { '_' } else { c })
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect()
    }

    /// Compute the HTTP status, error code, and user-facing message.
    ///
    /// Internal errors (500) are logged and replaced with a generic message
    /// to avoid leaking details.
    pub fn error_payload(&self) -> (u16, String, String) {
        let status = self.status_code();
        let (code, message) = match self {
            Self::BannedUser(message) => ("BANNED_USER".to_string(), message.clone()),
            _ => {
                let message = match status {
                    500 => {
                        tracing::error!(error = %self, "Internal server error");
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
        let (status, code, message) = self.error_payload();
        crate::types::AuthResponse::json(
            status,
            &crate::types::ErrorCodeMessageResponse {
                code,
                message: message.clone(),
            },
        )
        .unwrap_or_else(|_| crate::types::AuthResponse::text(status, &message))
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

    #[error("Transaction error: {0}")]
    Transaction(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status_u16, code, message) = self.error_payload();
        let status = axum::http::StatusCode::from_u16(status_u16)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            axum::Json(crate::types::ErrorCodeMessageResponse { code, message }),
        )
            .into_response()
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
        code: "VALIDATION_ERROR".to_string(),
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

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn code_from_message_uppercases_and_replaces_spaces() {
        assert_eq!(
            AuthError::code_from_message("User not found"),
            "USER_NOT_FOUND"
        );
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn code_from_message_strips_special_chars() {
        assert_eq!(
            AuthError::code_from_message("invalid email!"),
            "INVALID_EMAIL"
        );
    }

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn code_from_message_empty() {
        assert_eq!(AuthError::code_from_message(""), "");
    }

    // ── error_payload ───────────────────────────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn error_payload_for_client_error() {
        let (status, code, message) = AuthError::bad_request("Missing field").error_payload();
        assert_eq!(status, 400);
        assert_eq!(code, "MISSING_FIELD");
        assert_eq!(message, "Missing field");
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
        let body: serde_json::Value =
            serde_json::from_slice(&resp.body).expect("response body should be valid JSON");
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

    // ── Display for fixed-message variants ──────────────────────────────

    // Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
    #[test]
    fn fixed_message_variants_display() {
        assert_eq!(
            AuthError::InvalidCredentials.to_string(),
            "Invalid email or password"
        );
        assert_eq!(
            AuthError::Unauthenticated.to_string(),
            "Authentication required"
        );
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
