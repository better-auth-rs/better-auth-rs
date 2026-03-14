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

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("{0}")]
    Forbidden(String),

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
            Self::InvalidCredentials | Self::Unauthenticated | Self::SessionNotFound => 401,
            // 403
            Self::Forbidden(_) | Self::Unauthorized => 403,
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
        let message = match status {
            500 => {
                tracing::error!(error = %self, "Internal server error");
                "Internal server error".to_string()
            }
            _ => self.to_string(),
        };
        let code = Self::code_from_message(&message);
        (status, code, message)
    }

    /// Convert this error into a standardized [`AuthResponse`] matching the
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

#[cfg(feature = "sqlx-postgres")]
impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::Database(db_err) => {
                if db_err.is_unique_violation() {
                    DatabaseError::Constraint(db_err.to_string())
                } else {
                    DatabaseError::Query(db_err.to_string())
                }
            }
            sqlx::Error::PoolClosed => DatabaseError::Connection("Pool closed".to_string()),
            sqlx::Error::PoolTimedOut => DatabaseError::Connection("Pool timed out".to_string()),
            _ => DatabaseError::Query(err.to_string()),
        }
    }
}

#[cfg(feature = "sqlx-postgres")]
impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        AuthError::Database(DatabaseError::from(err))
    }
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
