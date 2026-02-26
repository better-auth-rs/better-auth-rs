use std::sync::Arc;
use chrono::Duration;
use crate::adapters::{DatabaseAdapter, CacheAdapter, MailerAdapter};
use crate::error::AuthError;

/// Main configuration for BetterAuth
#[derive(Clone)]
pub struct AuthConfig {
    /// Secret key for signing tokens and sessions
    pub secret: String,
    
    /// Base URL for the authentication service
    pub base_url: String,
    
    /// Database adapter for persistence
    pub database: Option<Arc<dyn DatabaseAdapter>>,

    /// Optional cache adapter
    pub cache: Option<Arc<dyn CacheAdapter>>,

    /// Optional mailer adapter
    pub mailer: Option<Arc<dyn MailerAdapter>>,
    
    /// Session configuration
    pub session: SessionConfig,
    
    /// JWT configuration
    pub jwt: JwtConfig,
    
    /// Password configuration
    pub password: PasswordConfig,
}

/// Session-specific configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session expiration duration
    pub expires_in: Duration,

    /// How often to refresh the session expiry (as a Duration).
    ///
    /// When set, session expiry is only updated if the session is older than
    /// this duration since the last update. When `None`, every request
    /// refreshes the session (equivalent to the old `update_age: true`).
    pub update_age: Option<Duration>,

    /// If `true`, sessions are never automatically refreshed on access.
    pub disable_session_refresh: bool,

    /// Session freshness window. A session younger than this is considered
    /// "fresh" (useful for step-up auth or sensitive operations).
    pub fresh_age: Option<Duration>,
    
    /// Cookie name for session token
    pub cookie_name: String,
    
    /// Cookie settings
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: SameSite,
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// JWT expiration duration
    pub expires_in: Duration,
    
    /// JWT algorithm
    pub algorithm: String,
    
    /// Issuer claim
    pub issuer: Option<String>,
    
    /// Audience claim
    pub audience: Option<String>,
}

/// Password hashing configuration
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Minimum password length
    pub min_length: usize,
    
    /// Require uppercase letters
    pub require_uppercase: bool,
    
    /// Require lowercase letters
    pub require_lowercase: bool,
    
    /// Require numbers
    pub require_numbers: bool,
    
    /// Require special characters
    pub require_special: bool,
    
    /// Argon2 configuration
    pub argon2_config: Argon2Config,
}

/// Argon2 hashing configuration
#[derive(Debug, Clone)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            base_url: "http://localhost:3000".to_string(),
            database: None,
            cache: None,
            mailer: None,
            session: SessionConfig::default(),
            jwt: JwtConfig::default(),
            password: PasswordConfig::default(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::hours(24 * 7), // 7 days
            update_age: Some(Duration::hours(24)), // refresh once per day
            disable_session_refresh: false,
            fresh_age: None,
            cookie_name: "better-auth.session-token".to_string(),
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: SameSite::Lax,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::hours(24), // 1 day
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
        }
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_numbers: false,
            require_special: false,
            argon2_config: Argon2Config::default(),
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 4096,  // 4MB
            time_cost: 3,       // 3 iterations
            parallelism: 1,     // 1 thread
        }
    }
}

impl AuthConfig {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }
    
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }
    
    pub fn session_expires_in(mut self, duration: Duration) -> Self {
        self.session.expires_in = duration;
        self
    }
    
    pub fn jwt_expires_in(mut self, duration: Duration) -> Self {
        self.jwt.expires_in = duration;
        self
    }
    
    pub fn password_min_length(mut self, length: usize) -> Self {
        self.password.min_length = length;
        self
    }

    pub fn cache<C: CacheAdapter + 'static>(mut self, cache: C) -> Self {
        self.cache = Some(Arc::new(cache));
        self
    }

    pub fn mailer<M: MailerAdapter + 'static>(mut self, mailer: M) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }
    
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.secret.is_empty() {
            return Err(AuthError::config("Secret key cannot be empty"));
        }
        
        if self.secret.len() < 32 {
            return Err(AuthError::config("Secret key must be at least 32 characters"));
        }
        
        if self.database.is_none() {
            return Err(AuthError::config("Database adapter is required"));
        }
        
        Ok(())
    }
}  
