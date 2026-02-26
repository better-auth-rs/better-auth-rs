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

    /// Session refresh policy.
    ///
    /// - `None` disables session refresh entirely (equivalent to TS `disableSessionRefresh: true`)
    /// - `Some(duration)` refreshes the session only when it was last updated more than `duration` ago
    ///
    /// Default: `Some(Duration::days(1))` (86,400 seconds, same as the TS default `updateAge`).
    pub update_age: Option<Duration>,

    /// How long a session is considered "fresh" after creation.
    ///
    /// Plugins that guard sensitive operations (password change, account deletion, …)
    /// can call `SessionManager::is_session_fresh()` to require a recent login.
    ///
    /// Default: 1 day.
    pub fresh_age: Duration,

    /// Cookie name for session token
    pub cookie_name: String,

    /// Cookie settings
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: SameSite,

    /// Optional cookie-based session cache to avoid DB lookups.
    ///
    /// When enabled, session data is cached in a signed/encrypted cookie.
    /// `SessionManager` checks the cookie cache before hitting the database.
    pub cookie_cache: Option<CookieCacheConfig>,
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

/// Configuration for cookie-based session caching.
///
/// When enabled, session data is stored in a signed or encrypted cookie so that
/// subsequent requests can skip the database lookup.
#[derive(Debug, Clone)]
pub struct CookieCacheConfig {
    /// Whether the cookie cache is active.
    pub enabled: bool,

    /// Maximum age of the cached cookie before a fresh DB lookup is required.
    ///
    /// Default: 5 minutes.
    pub max_age: Duration,

    /// Strategy used to protect the cached cookie value.
    pub strategy: CookieCacheStrategy,
}

/// Strategy for signing / encrypting the cookie cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    /// Base64url-encoded payload + HMAC-SHA256 signature.
    Compact,
    /// Standard JWT with HMAC signing.
    Jwt,
    /// JWE with AES-256-GCM encryption.
    Jwe,
}

impl Default for CookieCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: Duration::minutes(5),
            strategy: CookieCacheStrategy::Compact,
        }
    }
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
            update_age: Some(Duration::days(1)), // refresh after 1 day of inactivity
            fresh_age: Duration::days(1),        // session is "fresh" for 1 day
            cookie_name: "better-auth.session-token".to_string(),
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: SameSite::Lax,
            cookie_cache: None,
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

    /// Set the session refresh policy.
    ///
    /// - `Some(duration)` – refresh the session when it was last updated more than `duration` ago.
    /// - `None` – disable session refresh entirely.
    pub fn session_update_age(mut self, update_age: Option<Duration>) -> Self {
        self.session.update_age = update_age;
        self
    }

    /// Backward-compatible helper: `true` ≡ `Some(1 day)`, `false` ≡ `None`.
    pub fn session_refresh_enabled(mut self, enabled: bool) -> Self {
        self.session.update_age = if enabled {
            Some(Duration::days(1))
        } else {
            None
        };
        self
    }

    /// Set the "fresh session" window used by sensitive-operation guards.
    pub fn session_fresh_age(mut self, duration: Duration) -> Self {
        self.session.fresh_age = duration;
        self
    }

    /// Set the cookie cache configuration for sessions.
    pub fn session_cookie_cache(mut self, config: CookieCacheConfig) -> Self {
        self.session.cookie_cache = Some(config);
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
