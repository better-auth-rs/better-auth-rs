use thiserror::Error;

/// Authentication framework error types.
///
/// Each variant maps to an HTTP status code via [`AuthError::status_code`].
/// Use [`AuthError::into_response`] to produce a standardized JSON response
/// matching the better-auth OpenAPI spec: `{ "message": "..." }`.
#[derive(Error, Debug)]
pub enum AuthError {
    // --- 400 Bad Request ---
    #[error("{0}")]
    BadRequest(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error: {0}")]
    Validation(String),

    // --- 401 Unauthorized ---
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Authentication required")]
    Unauthenticated,

    #[error("Session not found or expired")]
    SessionNotFound,

    // --- 403 Forbidden ---
    #[error("{0}")]
    Forbidden(String),

    #[error("Insufficient permissions")]
    Unauthorized,

    // --- 404 Not Found ---
    #[error("User not found")]
    UserNotFound,

    #[error("{0}")]
    NotFound(String),

    // --- 409 Conflict ---
    #[error("{0}")]
    Conflict(String),

    // --- 429 Too Many Requests ---
    #[error("Too many requests")]
    RateLimited,

    // --- 501 Not Implemented ---
    #[error("{0}")]
    NotImplemented(String),

    // --- 500 Internal Server Error ---
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
            // 429
            Self::RateLimited => 429,
            // 501
            Self::NotImplemented(_) => 501,
            // 500
            Self::Config(_) | Self::Database(_) | Self::Serialization(_)
            | Self::Plugin { .. } | Self::Internal(_) | Self::PasswordHash(_)
            | Self::Jwt(_) => 500,
        }
    }

    /// Convert this error into a standardized [`AuthResponse`] matching the
    /// better-auth OpenAPI spec: `{ "message": "..." }`.
    ///
    /// Internal errors (500) use a generic message to avoid leaking details.
    pub fn into_response(self) -> crate::types::AuthResponse {
        let status = self.status_code();
        let message = match status {
            500 => "Internal server error".to_string(),
            _ => self.to_string(),
        };

        crate::types::AuthResponse::json(status, &serde_json::json!({
            "message": message
        }))
        .unwrap_or_else(|_| crate::types::AuthResponse::text(status, &message))
    }

    // --- Constructors ---

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

/// Convert `validator::ValidationErrors` into a standardized error response body.
///
/// Returns a 422 response with `{ "code": "VALIDATION_ERROR", "message": "...", "errors": {...} }`.
pub fn validation_error_response(errors: &validator::ValidationErrors) -> crate::types::AuthResponse {
    let field_errors: std::collections::HashMap<&str, Vec<String>> = errors
        .field_errors()
        .into_iter()
        .map(|(field, errs)| {
            let messages: Vec<String> = errs.iter().map(|e| {
                e.message.as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| format!("Invalid value for {}", field))
            }).collect();
            (field, messages)
        })
        .collect();

    let body = serde_json::json!({
        "code": "VALIDATION_ERROR",
        "message": "Validation failed",
        "errors": field_errors,
    });

    crate::types::AuthResponse::json(422, &body)
        .unwrap_or_else(|_| crate::types::AuthResponse::text(422, "Validation failed"))
}

/// Validate a request body, returning a parsed + validated value or an error response.
pub fn validate_request_body<T>(req: &crate::types::AuthRequest) -> Result<T, crate::types::AuthResponse>
where
    T: serde::de::DeserializeOwned + validator::Validate,
{
    let value: T = req.body_as_json().map_err(|e| {
        crate::types::AuthResponse::json(400, &serde_json::json!({
            "message": format!("Invalid JSON: {}", e),
        })).unwrap_or_else(|_| crate::types::AuthResponse::text(400, "Invalid JSON"))
    })?;

    value.validate().map_err(|e| validation_error_response(&e))?;

    Ok(value)
}
