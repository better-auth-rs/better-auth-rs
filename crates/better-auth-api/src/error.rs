use thiserror::Error;

/// Authentication framework error types
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Session not found or expired")]
    SessionNotFound,
    
    #[error("Plugin error: {plugin} - {message}")]
    Plugin { plugin: String, message: String },
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("Authentication required")]
    Unauthenticated,
    
    #[error("Insufficient permissions")]
    Unauthorized,
    
    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Missing capability: {plugin} requires {capability}")]
    MissingCapability { plugin: String, capability: String },
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

impl AuthError {
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

    pub fn missing_capability(plugin: &str, capability: &str) -> Self {
        Self::MissingCapability {
            plugin: plugin.to_string(),
            capability: capability.to_string(),
        }
    }
}
