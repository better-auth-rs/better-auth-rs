use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthApiKey, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute, BeforeRequestAction};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateApiKey, HttpMethod, UpdateApiKey};

// ---------------------------------------------------------------------------
// Error codes -- mirrors the TypeScript `API_KEY_ERROR_CODES`
// ---------------------------------------------------------------------------

/// Dedicated API Key error codes aligned with the TypeScript implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ApiKeyErrorCode {
    #[serde(rename = "INVALID_API_KEY")]
    InvalidApiKey,
    #[serde(rename = "KEY_DISABLED")]
    KeyDisabled,
    #[serde(rename = "KEY_EXPIRED")]
    KeyExpired,
    #[serde(rename = "USAGE_EXCEEDED")]
    UsageExceeded,
    #[serde(rename = "KEY_NOT_FOUND")]
    KeyNotFound,
    #[serde(rename = "RATE_LIMITED")]
    RateLimited,
    #[serde(rename = "UNAUTHORIZED_SESSION")]
    UnauthorizedSession,
    #[serde(rename = "INVALID_PREFIX_LENGTH")]
    InvalidPrefixLength,
    #[serde(rename = "INVALID_NAME_LENGTH")]
    InvalidNameLength,
    #[serde(rename = "METADATA_DISABLED")]
    MetadataDisabled,
    #[serde(rename = "NO_VALUES_TO_UPDATE")]
    NoValuesToUpdate,
    #[serde(rename = "KEY_DISABLED_EXPIRATION")]
    KeyDisabledExpiration,
    #[serde(rename = "EXPIRES_IN_IS_TOO_SMALL")]
    ExpiresInTooSmall,
    #[serde(rename = "EXPIRES_IN_IS_TOO_LARGE")]
    ExpiresInTooLarge,
    #[serde(rename = "INVALID_REMAINING")]
    InvalidRemaining,
    #[serde(rename = "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")]
    RefillAmountAndIntervalRequired,
    #[serde(rename = "NAME_REQUIRED")]
    NameRequired,
    #[serde(rename = "INVALID_USER_ID_FROM_API_KEY")]
    InvalidUserIdFromApiKey,
    #[serde(rename = "SERVER_ONLY_PROPERTY")]
    ServerOnlyProperty,
    #[serde(rename = "FAILED_TO_UPDATE_API_KEY")]
    FailedToUpdateApiKey,
    #[serde(rename = "INVALID_METADATA_TYPE")]
    InvalidMetadataType,
}

impl ApiKeyErrorCode {
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidApiKey => "Invalid API key.",
            Self::KeyDisabled => "API Key is disabled",
            Self::KeyExpired => "API Key has expired",
            Self::UsageExceeded => "API Key has reached its usage limit",
            Self::KeyNotFound => "API Key not found",
            Self::RateLimited => "Rate limit exceeded.",
            Self::UnauthorizedSession => "Unauthorized or invalid session",
            Self::InvalidPrefixLength => "The prefix length is either too large or too small.",
            Self::InvalidNameLength => "The name length is either too large or too small.",
            Self::MetadataDisabled => "Metadata is disabled.",
            Self::NoValuesToUpdate => "No values to update.",
            Self::KeyDisabledExpiration => "Custom key expiration values are disabled.",
            Self::ExpiresInTooSmall => {
                "The expiresIn is smaller than the predefined minimum value."
            }
            Self::ExpiresInTooLarge => "The expiresIn is larger than the predefined maximum value.",
            Self::InvalidRemaining => "The remaining count is either too large or too small.",
            Self::RefillAmountAndIntervalRequired => {
                "refillAmount and refillInterval must both be provided together"
            }
            Self::NameRequired => "API Key name is required.",
            Self::InvalidUserIdFromApiKey => "The user id from the API key is invalid.",
            Self::ServerOnlyProperty => {
                "The property you're trying to set can only be set from the server auth instance only."
            }
            Self::FailedToUpdateApiKey => "Failed to update API key",
            Self::InvalidMetadataType => "metadata must be an object or undefined",
        }
    }
}

fn api_key_error(code: ApiKeyErrorCode) -> AuthError {
    AuthError::bad_request(code.message())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// API Key management plugin.
pub struct ApiKeyPlugin {
    config: ApiKeyConfig,
    /// Throttle for `delete_expired_api_keys` -- stores the last check instant.
    last_expired_check: Mutex<Option<std::time::Instant>>,
}

/// Configuration for the API Key plugin, aligned with the TypeScript `ApiKeyOptions`.
#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    // -- key generation --
    pub key_length: usize,
    pub prefix: Option<String>,
    pub default_remaining: Option<i64>,

    // -- header --
    pub api_key_header: String,

    // -- hashing --
    pub disable_key_hashing: bool,

    // -- starting characters --
    pub starting_characters_length: usize,
    pub store_starting_characters: bool,

    // -- prefix length validation --
    pub max_prefix_length: usize,
    pub min_prefix_length: usize,

    // -- name validation --
    pub max_name_length: usize,
    pub min_name_length: usize,
    pub require_name: bool,

    // -- metadata --
    pub enable_metadata: bool,

    // -- key expiration --
    pub key_expiration: KeyExpirationConfig,

    // -- rate limit defaults --
    pub rate_limit: RateLimitDefaults,

    // -- session emulation --
    pub enable_session_for_api_keys: bool,
}

/// Key expiration constraints.
#[derive(Debug, Clone)]
pub struct KeyExpirationConfig {
    /// Default `expiresIn` (in milliseconds) when none is provided. `None` = no default.
    pub default_expires_in: Option<i64>,
    /// If true, clients cannot set a custom `expiresIn`.
    pub disable_custom_expires_time: bool,
    /// Maximum `expiresIn` in **days**.
    pub max_expires_in: i64,
    /// Minimum `expiresIn` in **days**.
    pub min_expires_in: i64,
}

impl Default for KeyExpirationConfig {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            max_expires_in: 365,
            min_expires_in: 0,
        }
    }
}

/// Global rate-limit defaults applied to newly-created keys.
#[derive(Debug, Clone)]
pub struct RateLimitDefaults {
    pub enabled: bool,
    /// Default time window in milliseconds.
    pub time_window: i64,
    /// Default max requests per window.
    pub max_requests: i64,
}

impl Default for RateLimitDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window: 86_400_000, // 24 hours
            max_requests: 10,
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            key_length: 32,
            prefix: None,
            default_remaining: None,
            api_key_header: "x-api-key".to_string(),
            disable_key_hashing: false,
            starting_characters_length: 6,
            store_starting_characters: true,
            max_prefix_length: 32,
            min_prefix_length: 1,
            max_name_length: 32,
            min_name_length: 1,
            require_name: false,
            enable_metadata: false,
            key_expiration: KeyExpirationConfig::default(),
            rate_limit: RateLimitDefaults::default(),
            enable_session_for_api_keys: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
struct CreateKeyRequest {
    name: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "expiresIn")]
    expires_in: Option<i64>,
    remaining: Option<i64>,
    #[serde(rename = "rateLimitEnabled")]
    rate_limit_enabled: Option<bool>,
    #[serde(rename = "rateLimitTimeWindow")]
    rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    rate_limit_max: Option<i64>,
    #[serde(rename = "refillInterval")]
    refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    refill_amount: Option<i64>,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
struct UpdateKeyRequest {
    #[validate(length(min = 1, message = "Key ID is required"))]
    id: String,
    name: Option<String>,
    enabled: Option<bool>,
    remaining: Option<i64>,
    #[serde(rename = "rateLimitEnabled")]
    rate_limit_enabled: Option<bool>,
    #[serde(rename = "rateLimitTimeWindow")]
    rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    rate_limit_max: Option<i64>,
    #[serde(rename = "refillInterval")]
    refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    refill_amount: Option<i64>,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    #[serde(rename = "expiresIn")]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
struct DeleteKeyRequest {
    #[validate(length(min = 1, message = "Key ID is required"))]
    id: String,
}

#[derive(Debug, Deserialize)]
struct VerifyKeyRequest {
    key: String,
    permissions: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ApiKeyView {
    id: String,
    name: Option<String>,
    start: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "refillInterval")]
    refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    refill_amount: Option<i64>,
    #[serde(rename = "lastRefillAt")]
    last_refill_at: Option<String>,
    enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    rate_limit_max: Option<i64>,
    #[serde(rename = "requestCount")]
    request_count: Option<i64>,
    remaining: Option<i64>,
    #[serde(rename = "lastRequest")]
    last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct CreateKeyResponse {
    key: String,
    #[serde(flatten)]
    api_key: ApiKeyView,
}

#[derive(Debug, Serialize)]
struct VerifyKeyResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<VerifyErrorBody>,
    key: Option<ApiKeyView>,
}

#[derive(Debug, Serialize)]
struct VerifyErrorBody {
    message: String,
    code: String,
}

impl ApiKeyView {
    fn from_entity(ak: &impl AuthApiKey) -> Self {
        Self {
            id: ak.id().to_string(),
            name: ak.name().map(|s| s.to_string()),
            start: ak.start().map(|s| s.to_string()),
            prefix: ak.prefix().map(|s| s.to_string()),
            user_id: ak.user_id().to_string(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at().map(|s| s.to_string()),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request().map(|s| s.to_string()),
            expires_at: ak.expires_at().map(|s| s.to_string()),
            created_at: ak.created_at().to_string(),
            updated_at: ak.updated_at().to_string(),
            permissions: ak.permissions().and_then(|s| serde_json::from_str(s).ok()),
            metadata: ak.metadata().and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limiting helper (pure function, mirrors TS `isRateLimited`)
// ---------------------------------------------------------------------------

struct RateLimitResult {
    success: bool,
    message: Option<String>,
    #[allow(dead_code)]
    try_again_in: Option<i64>,
    update: Option<RateLimitUpdate>,
}

struct RateLimitUpdate {
    last_request: Option<String>,
    request_count: Option<i64>,
}

fn is_rate_limited(api_key: &impl AuthApiKey, global_enabled: bool) -> RateLimitResult {
    let now = chrono::Utc::now();

    // Global rate-limit disabled
    if !global_enabled {
        return RateLimitResult {
            success: true,
            message: None,
            try_again_in: None,
            update: Some(RateLimitUpdate {
                last_request: Some(now.to_rfc3339()),
                request_count: None,
            }),
        };
    }

    // Per-key rate-limit disabled
    if !api_key.rate_limit_enabled() {
        return RateLimitResult {
            success: true,
            message: None,
            try_again_in: None,
            update: Some(RateLimitUpdate {
                last_request: Some(now.to_rfc3339()),
                request_count: None,
            }),
        };
    }

    let rate_limit_time_window = match api_key.rate_limit_time_window() {
        Some(w) => w,
        None => {
            return RateLimitResult {
                success: true,
                message: None,
                try_again_in: None,
                update: None,
            };
        }
    };

    let rate_limit_max = match api_key.rate_limit_max() {
        Some(m) => m,
        None => {
            return RateLimitResult {
                success: true,
                message: None,
                try_again_in: None,
                update: None,
            };
        }
    };

    let last_request = api_key.last_request();
    let request_count = api_key.request_count().unwrap_or(0);

    if last_request.is_none() {
        // First request ever
        return RateLimitResult {
            success: true,
            message: None,
            try_again_in: None,
            update: Some(RateLimitUpdate {
                last_request: Some(now.to_rfc3339()),
                request_count: Some(1),
            }),
        };
    }

    let last_request_time = last_request
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(now);

    let time_since_last = (now - last_request_time).num_milliseconds();

    if time_since_last > rate_limit_time_window {
        // Window expired, reset
        return RateLimitResult {
            success: true,
            message: None,
            try_again_in: None,
            update: Some(RateLimitUpdate {
                last_request: Some(now.to_rfc3339()),
                request_count: Some(1),
            }),
        };
    }

    if request_count >= rate_limit_max {
        // Over limit
        return RateLimitResult {
            success: false,
            message: Some(ApiKeyErrorCode::RateLimited.message().to_string()),
            try_again_in: Some(rate_limit_time_window - time_since_last),
            update: None,
        };
    }

    // Allowed
    RateLimitResult {
        success: true,
        message: None,
        try_again_in: None,
        update: Some(RateLimitUpdate {
            last_request: Some(now.to_rfc3339()),
            request_count: Some(request_count + 1),
        }),
    }
}

// ---------------------------------------------------------------------------
// Permissions verification helper (RBAC)
// ---------------------------------------------------------------------------

/// Check whether `key_permissions` (JSON object mapping role->actions) covers
/// all of the `required_permissions`.
fn check_permissions(key_permissions_json: &str, required: &serde_json::Value) -> bool {
    let key_perms: serde_json::Value = match serde_json::from_str(key_permissions_json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let required_map = match required.as_object() {
        Some(m) => m,
        None => return false,
    };

    let key_map = match key_perms.as_object() {
        Some(m) => m,
        None => return false,
    };

    for (role, actions) in required_map {
        let required_actions = match actions.as_array() {
            Some(a) => a,
            None => continue,
        };

        let key_actions = match key_map.get(role).and_then(|v| v.as_array()) {
            Some(a) => a,
            None => return false, // role not present on key
        };

        for action in required_actions {
            if !key_actions.contains(action) {
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

impl ApiKeyPlugin {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            config: ApiKeyConfig::default(),
            last_expired_check: Mutex::new(None),
        }
    }

    pub fn with_config(config: ApiKeyConfig) -> Self {
        Self {
            config,
            last_expired_check: Mutex::new(None),
        }
    }

    // -- builder methods --

    pub fn key_length(mut self, length: usize) -> Self {
        self.config.key_length = length;
        self
    }

    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.prefix = Some(prefix.into());
        self
    }

    pub fn default_remaining(mut self, remaining: i64) -> Self {
        self.config.default_remaining = Some(remaining);
        self
    }

    pub fn api_key_header(mut self, header: impl Into<String>) -> Self {
        self.config.api_key_header = header.into();
        self
    }

    pub fn disable_key_hashing(mut self, disable: bool) -> Self {
        self.config.disable_key_hashing = disable;
        self
    }

    pub fn starting_characters_length(mut self, len: usize) -> Self {
        self.config.starting_characters_length = len;
        self
    }

    pub fn store_starting_characters(mut self, store: bool) -> Self {
        self.config.store_starting_characters = store;
        self
    }

    pub fn max_prefix_length(mut self, max: usize) -> Self {
        self.config.max_prefix_length = max;
        self
    }

    pub fn min_prefix_length(mut self, min: usize) -> Self {
        self.config.min_prefix_length = min;
        self
    }

    pub fn max_name_length(mut self, max: usize) -> Self {
        self.config.max_name_length = max;
        self
    }

    pub fn min_name_length(mut self, min: usize) -> Self {
        self.config.min_name_length = min;
        self
    }

    pub fn require_name(mut self, require: bool) -> Self {
        self.config.require_name = require;
        self
    }

    pub fn enable_metadata(mut self, enable: bool) -> Self {
        self.config.enable_metadata = enable;
        self
    }

    pub fn key_expiration(mut self, config: KeyExpirationConfig) -> Self {
        self.config.key_expiration = config;
        self
    }

    pub fn rate_limit(mut self, config: RateLimitDefaults) -> Self {
        self.config.rate_limit = config;
        self
    }

    pub fn enable_session_for_api_keys(mut self, enable: bool) -> Self {
        self.config.enable_session_for_api_keys = enable;
        self
    }

    // -- internal helpers --

    fn generate_key(&self, custom_prefix: Option<&str>) -> (String, String, String) {
        let mut bytes = vec![0u8; self.config.key_length];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let raw = URL_SAFE_NO_PAD.encode(&bytes);

        let start_len = self.config.starting_characters_length;
        let start = raw.chars().take(start_len).collect::<String>();

        let prefix = custom_prefix
            .or(self.config.prefix.as_deref())
            .unwrap_or("");
        let full_key = format!("{}{}", prefix, raw);

        let hash = Self::hash_key(&full_key);

        (full_key, hash, start)
    }

    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        URL_SAFE_NO_PAD.encode(digest)
    }

    async fn get_authenticated_user<DB: DatabaseAdapter>(
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<(DB::User, DB::Session)> {
        let token = req
            .headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::Unauthenticated)?;

        let session = ctx
            .database
            .get_session(token)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        if session.expires_at() < chrono::Utc::now() {
            return Err(AuthError::Unauthenticated);
        }

        let user = ctx
            .database
            .get_user_by_id(session.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok((user, session))
    }

    /// Throttled cleanup -- at most once per 10 seconds.
    async fn maybe_delete_expired<DB: DatabaseAdapter>(&self, ctx: &AuthContext<DB>) {
        let should_run = {
            let mut last = self.last_expired_check.lock().unwrap();
            let now = std::time::Instant::now();
            match *last {
                Some(prev) if now.duration_since(prev).as_secs() < 10 => false,
                _ => {
                    *last = Some(now);
                    true
                }
            }
        };
        if should_run {
            let _ = ctx.database.delete_expired_api_keys().await;
        }
    }

    // -- Validation helpers --

    fn validate_prefix(&self, prefix: Option<&str>) -> AuthResult<()> {
        if let Some(p) = prefix {
            let len = p.len();
            if len < self.config.min_prefix_length || len > self.config.max_prefix_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidPrefixLength));
            }
        }
        Ok(())
    }

    fn validate_name(&self, name: Option<&str>) -> AuthResult<()> {
        if self.config.require_name && name.is_none() {
            return Err(api_key_error(ApiKeyErrorCode::NameRequired));
        }
        if let Some(n) = name {
            let len = n.len();
            if len < self.config.min_name_length || len > self.config.max_name_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidNameLength));
            }
        }
        Ok(())
    }

    fn validate_expires_in(&self, expires_in: Option<i64>) -> AuthResult<Option<i64>> {
        let cfg = &self.config.key_expiration;
        if let Some(ms) = expires_in {
            if cfg.disable_custom_expires_time {
                return Err(api_key_error(ApiKeyErrorCode::KeyDisabledExpiration));
            }
            let days = ms as f64 / 86_400_000.0;
            if days < cfg.min_expires_in as f64 {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooSmall));
            }
            if days > cfg.max_expires_in as f64 {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooLarge));
            }
            Ok(Some(ms))
        } else {
            Ok(cfg.default_expires_in)
        }
    }

    fn validate_metadata(&self, metadata: &Option<serde_json::Value>) -> AuthResult<()> {
        if metadata.is_some() && !self.config.enable_metadata {
            return Err(api_key_error(ApiKeyErrorCode::MetadataDisabled));
        }
        if let Some(v) = metadata
            && !v.is_object()
            && !v.is_null()
        {
            return Err(api_key_error(ApiKeyErrorCode::InvalidMetadataType));
        }
        Ok(())
    }

    fn validate_refill(refill_interval: Option<i64>, refill_amount: Option<i64>) -> AuthResult<()> {
        match (refill_interval, refill_amount) {
            (Some(_), None) | (None, Some(_)) => Err(api_key_error(
                ApiKeyErrorCode::RefillAmountAndIntervalRequired,
            )),
            _ => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // Route handlers
    // -----------------------------------------------------------------------

    async fn handle_create<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let create_req: CreateKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validations
        self.validate_prefix(create_req.prefix.as_deref())?;
        self.validate_name(create_req.name.as_deref())?;
        self.validate_metadata(&create_req.metadata)?;
        Self::validate_refill(create_req.refill_interval, create_req.refill_amount)?;

        let effective_expires_in = self.validate_expires_in(create_req.expires_in)?;

        let (full_key, hash, start) = self.generate_key(create_req.prefix.as_deref());

        let expires_at = if let Some(ms) = effective_expires_in {
            let duration = chrono::Duration::try_milliseconds(ms)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            let dt = chrono::Utc::now()
                .checked_add_signed(duration)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            Some(dt.to_rfc3339())
        } else {
            None
        };

        let remaining = create_req.remaining.or(self.config.default_remaining);

        let store_start = if self.config.store_starting_characters {
            Some(start)
        } else {
            None
        };

        let input = CreateApiKey {
            user_id: user.id().to_string(),
            name: create_req.name,
            prefix: create_req.prefix.or_else(|| self.config.prefix.clone()),
            key_hash: hash,
            start: store_start,
            expires_at,
            remaining,
            rate_limit_enabled: create_req.rate_limit_enabled.unwrap_or(false),
            rate_limit_time_window: create_req.rate_limit_time_window,
            rate_limit_max: create_req.rate_limit_max,
            refill_interval: create_req.refill_interval,
            refill_amount: create_req.refill_amount,
            permissions: create_req
                .permissions
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            metadata: create_req
                .metadata
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            enabled: true,
        };

        let api_key = ctx.database.create_api_key(input).await?;

        // Throttled cleanup
        self.maybe_delete_expired(ctx).await;

        let response = CreateKeyResponse {
            key: full_key,
            api_key: ApiKeyView::from_entity(&api_key),
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_get<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let id = req
            .query
            .get("id")
            .ok_or_else(|| AuthError::bad_request("Query parameter 'id' is required"))?;

        let api_key = ctx
            .database
            .get_api_key_by_id(id)
            .await?
            .ok_or_else(|| AuthError::not_found("API key not found"))?;

        if api_key.user_id() != user.id() {
            return Err(AuthError::not_found("API key not found"));
        }

        self.maybe_delete_expired(ctx).await;

        Ok(AuthResponse::json(200, &ApiKeyView::from_entity(&api_key))?)
    }

    async fn handle_list<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let keys = ctx.database.list_api_keys_by_user(user.id()).await?;

        let views: Vec<ApiKeyView> = keys.iter().map(ApiKeyView::from_entity).collect();

        self.maybe_delete_expired(ctx).await;

        Ok(AuthResponse::json(200, &views)?)
    }

    async fn handle_update<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let update_req: UpdateKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validations
        self.validate_name(update_req.name.as_deref())?;
        self.validate_metadata(&update_req.metadata)?;
        Self::validate_refill(update_req.refill_interval, update_req.refill_amount)?;

        // Ownership check
        let existing = ctx
            .database
            .get_api_key_by_id(&update_req.id)
            .await?
            .ok_or_else(|| AuthError::not_found("API key not found"))?;

        if existing.user_id() != user.id() {
            return Err(AuthError::not_found("API key not found"));
        }

        // Build expires_at if expiresIn is provided
        let expires_at = if let Some(ms) = update_req.expires_in {
            let effective_ms = self.validate_expires_in(Some(ms))?;
            if let Some(ms_val) = effective_ms {
                let duration = chrono::Duration::try_milliseconds(ms_val)
                    .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
                let dt = chrono::Utc::now()
                    .checked_add_signed(duration)
                    .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
                Some(Some(dt.to_rfc3339()))
            } else {
                None
            }
        } else {
            None
        };

        let update = UpdateApiKey {
            name: update_req.name,
            enabled: update_req.enabled,
            remaining: update_req.remaining,
            rate_limit_enabled: update_req.rate_limit_enabled,
            rate_limit_time_window: update_req.rate_limit_time_window,
            rate_limit_max: update_req.rate_limit_max,
            refill_interval: update_req.refill_interval,
            refill_amount: update_req.refill_amount,
            permissions: update_req
                .permissions
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            metadata: update_req
                .metadata
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            expires_at,
            last_request: None,
            request_count: None,
            last_refill_at: None,
        };

        let updated = ctx.database.update_api_key(&update_req.id, update).await?;

        self.maybe_delete_expired(ctx).await;

        Ok(AuthResponse::json(200, &ApiKeyView::from_entity(&updated))?)
    }

    async fn handle_delete<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let delete_req: DeleteKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Ownership check
        let existing = ctx
            .database
            .get_api_key_by_id(&delete_req.id)
            .await?
            .ok_or_else(|| AuthError::not_found("API key not found"))?;

        if existing.user_id() != user.id() {
            return Err(AuthError::not_found("API key not found"));
        }

        ctx.database.delete_api_key(&delete_req.id).await?;

        Ok(AuthResponse::json(
            200,
            &serde_json::json!({ "status": true }),
        )?)
    }

    // -----------------------------------------------------------------------
    // POST /api-key/verify -- core verification endpoint
    // -----------------------------------------------------------------------

    async fn handle_verify<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let verify_req: VerifyKeyRequest = req
            .body_as_json()
            .map_err(|_| AuthError::bad_request("Invalid JSON body"))?;

        let result = self
            .validate_api_key(ctx, &verify_req.key, verify_req.permissions.as_ref())
            .await;

        match result {
            Ok(view) => Ok(AuthResponse::json(
                200,
                &VerifyKeyResponse {
                    valid: true,
                    error: None,
                    key: Some(view),
                },
            )?),
            Err(err) => {
                // Return structured error instead of propagating
                let (code_str, message) = extract_error_info(&err);
                Ok(AuthResponse::json(
                    200,
                    &VerifyKeyResponse {
                        valid: false,
                        error: Some(VerifyErrorBody {
                            message,
                            code: code_str,
                        }),
                        key: None,
                    },
                )?)
            }
        }
    }

    /// Core validation logic shared by `handle_verify` and `before_request`.
    ///
    /// Validation chain: exists -> disabled -> expired -> permissions ->
    /// remaining/refill -> rate limit.
    /// Returns the (updated) API key view on success.
    async fn validate_api_key<DB: DatabaseAdapter>(
        &self,
        ctx: &AuthContext<DB>,
        raw_key: &str,
        required_permissions: Option<&serde_json::Value>,
    ) -> AuthResult<ApiKeyView> {
        // Hash the key (or use as-is if hashing is disabled)
        let hashed = if self.config.disable_key_hashing {
            raw_key.to_string()
        } else {
            Self::hash_key(raw_key)
        };

        // Look up by hash
        let api_key = ctx
            .database
            .get_api_key_by_hash(&hashed)
            .await?
            .ok_or_else(|| api_key_error(ApiKeyErrorCode::InvalidApiKey))?;

        // 1. Disabled?
        if !api_key.enabled() {
            return Err(api_key_error(ApiKeyErrorCode::KeyDisabled));
        }

        // 2. Expired?
        if let Some(expires_at_str) = api_key.expires_at()
            && let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str)
            && chrono::Utc::now() > expires_at
        {
            // Delete expired key
            let _ = ctx.database.delete_api_key(api_key.id()).await;
            return Err(api_key_error(ApiKeyErrorCode::KeyExpired));
        }

        // 3. Permissions check
        if let Some(required) = required_permissions {
            let key_perms_str = api_key.permissions().unwrap_or("");
            if key_perms_str.is_empty() {
                return Err(api_key_error(ApiKeyErrorCode::KeyNotFound));
            }
            if !check_permissions(key_perms_str, required) {
                return Err(api_key_error(ApiKeyErrorCode::KeyNotFound));
            }
        }

        // 4. Remaining / refill
        let mut new_remaining = api_key.remaining();
        let mut new_last_refill_at: Option<String> =
            api_key.last_refill_at().map(|s| s.to_string());

        if let Some(0) = api_key.remaining()
            && api_key.refill_amount().is_none()
        {
            // Usage exhausted, no refill configured -- delete key
            let _ = ctx.database.delete_api_key(api_key.id()).await;
            return Err(api_key_error(ApiKeyErrorCode::UsageExceeded));
        }

        if let Some(remaining) = api_key.remaining() {
            let refill_interval = api_key.refill_interval();
            let refill_amount = api_key.refill_amount();
            let mut current_remaining = remaining;

            if let (Some(interval), Some(amount)) = (refill_interval, refill_amount) {
                let now = chrono::Utc::now();
                let last_time_str = api_key
                    .last_refill_at()
                    .or_else(|| Some(api_key.created_at()));
                if let Some(last_str) = last_time_str
                    && let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(last_str)
                {
                    let elapsed_ms = (now - last_dt.with_timezone(&chrono::Utc)).num_milliseconds();
                    if elapsed_ms > interval {
                        current_remaining = amount;
                        new_last_refill_at = Some(now.to_rfc3339());
                    }
                }
            }

            if current_remaining <= 0 {
                return Err(api_key_error(ApiKeyErrorCode::UsageExceeded));
            }

            new_remaining = Some(current_remaining - 1);
        }

        // 5. Rate limiting
        let rl = is_rate_limited(&api_key, self.config.rate_limit.enabled);
        if !rl.success {
            return Err(AuthError::bad_request(
                rl.message
                    .as_deref()
                    .unwrap_or(ApiKeyErrorCode::RateLimited.message()),
            ));
        }

        // 6. Build update
        let mut update = UpdateApiKey {
            remaining: new_remaining,
            ..Default::default()
        };
        if new_last_refill_at != api_key.last_refill_at().map(|s| s.to_string()) {
            update.last_refill_at = Some(new_last_refill_at);
        }
        if let Some(rl_update) = rl.update {
            if let Some(lr) = rl_update.last_request {
                update.last_request = Some(Some(lr));
            }
            if let Some(rc) = rl_update.request_count {
                update.request_count = Some(rc);
            }
        }

        let updated = ctx
            .database
            .update_api_key(api_key.id(), update)
            .await
            .map_err(|_| api_key_error(ApiKeyErrorCode::FailedToUpdateApiKey))?;

        // Throttled cleanup
        self.maybe_delete_expired(ctx).await;

        Ok(ApiKeyView::from_entity(&updated))
    }

    // -----------------------------------------------------------------------
    // POST /api-key/delete-all-expired-api-keys
    // -----------------------------------------------------------------------

    async fn handle_delete_all_expired<DB: DatabaseAdapter>(
        &self,
        _req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let count = ctx.database.delete_expired_api_keys().await?;
        Ok(AuthResponse::json(
            200,
            &serde_json::json!({ "deleted": count }),
        )?)
    }
}

/// Extract a human-readable error code + message from an `AuthError`.
fn extract_error_info(err: &AuthError) -> (String, String) {
    let msg = err.to_string();
    // Try to map known messages back to error codes
    let code = if msg.contains("Invalid API key") {
        "INVALID_API_KEY"
    } else if msg.contains("disabled") {
        "KEY_DISABLED"
    } else if msg.contains("expired") {
        "KEY_EXPIRED"
    } else if msg.contains("usage limit") {
        "USAGE_EXCEEDED"
    } else if msg.contains("not found") {
        "KEY_NOT_FOUND"
    } else if msg.contains("Rate limit") {
        "RATE_LIMITED"
    } else {
        "INVALID_API_KEY"
    };
    (code.to_string(), msg)
}

// ---------------------------------------------------------------------------
// AuthPlugin trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for ApiKeyPlugin {
    fn name(&self) -> &'static str {
        "api-key"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/api-key/create", "api_key_create"),
            AuthRoute::get("/api-key/get", "api_key_get"),
            AuthRoute::post("/api-key/update", "api_key_update"),
            AuthRoute::post("/api-key/delete", "api_key_delete"),
            AuthRoute::get("/api-key/list", "api_key_list"),
            AuthRoute::post("/api-key/verify", "api_key_verify"),
            AuthRoute::post(
                "/api-key/delete-all-expired-api-keys",
                "api_key_delete_all_expired",
            ),
        ]
    }

    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if !self.config.enable_session_for_api_keys {
            return Ok(None);
        }

        // Check for API key in the configured header
        let raw_key = match req.headers.get(&self.config.api_key_header) {
            Some(k) if !k.is_empty() => k.clone(),
            _ => return Ok(None),
        };

        // Validate the key (reuses the full verify logic)
        let view = self.validate_api_key(ctx, &raw_key, None).await?;

        // Look up the user
        let user = ctx
            .database
            .get_user_by_id(&view.user_id)
            .await?
            .ok_or_else(|| api_key_error(ApiKeyErrorCode::InvalidUserIdFromApiKey))?;

        // Build a virtual session response for `/get-session`
        if req.path() == "/get-session" {
            let session_json = serde_json::json!({
                "user": {
                    "id": user.id(),
                    "email": user.email(),
                    "name": user.name(),
                },
                "session": {
                    "id": view.id,
                    "token": raw_key,
                    "userId": view.user_id,
                }
            });
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &session_json,
            )?)));
        }

        // For all other routes, inject the session
        Ok(Some(BeforeRequestAction::InjectSession {
            user_id: view.user_id,
            session_token: raw_key,
        }))
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/api-key/create") => Ok(Some(self.handle_create(req, ctx).await?)),
            (HttpMethod::Get, "/api-key/get") => Ok(Some(self.handle_get(req, ctx).await?)),
            (HttpMethod::Post, "/api-key/update") => Ok(Some(self.handle_update(req, ctx).await?)),
            (HttpMethod::Post, "/api-key/delete") => Ok(Some(self.handle_delete(req, ctx).await?)),
            (HttpMethod::Get, "/api-key/list") => Ok(Some(self.handle_list(req, ctx).await?)),
            (HttpMethod::Post, "/api-key/verify") => Ok(Some(self.handle_verify(req, ctx).await?)),
            (HttpMethod::Post, "/api-key/delete-all-expired-api-keys") => {
                Ok(Some(self.handle_delete_all_expired(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapters::{ApiKeyOps, MemoryDatabaseAdapter, SessionOps, UserOps};
    use better_auth_core::{CreateSession, CreateUser, Session, User};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn create_test_context_with_user() -> (AuthContext<MemoryDatabaseAdapter>, User, Session)
    {
        let config = Arc::new(better_auth_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config, database.clone());

        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("test@example.com")
                    .with_name("Test User"),
            )
            .await
            .unwrap();

        let session = database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        (ctx, user, session)
    }

    async fn create_user_with_session(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        email: &str,
    ) -> (User, Session) {
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email(email.to_string())
                    .with_name("Another User"),
            )
            .await
            .unwrap();

        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        (user, session)
    }

    fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        query: Option<HashMap<String, String>>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }

        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body: body.map(|b| serde_json::to_vec(&b).unwrap()),
            query: query.unwrap_or_default(),
        }
    }

    fn json_body(response: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    async fn create_key_and_get_id(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        token: &str,
        name: &str,
    ) -> String {
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(token),
            Some(serde_json::json!({ "name": name })),
            None,
        );
        let response = plugin.handle_create(&req, ctx).await.unwrap();
        assert_eq!(response.status, 200);
        json_body(&response)["id"].as_str().unwrap().to_string()
    }

    /// Helper: create a key and return (id, raw_key)
    async fn create_key_and_get_raw(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        token: &str,
        body: serde_json::Value,
    ) -> (String, String) {
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(token),
            Some(body),
            None,
        );
        let response = plugin.handle_create(&req, ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let b = json_body(&response);
        (
            b["id"].as_str().unwrap().to_string(),
            b["key"].as_str().unwrap().to_string(),
        )
    }

    // -----------------------------------------------------------------------
    // Existing tests (kept)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_and_get_do_not_expose_hash() {
        let plugin = ApiKeyPlugin::new().prefix("ba_");
        let (ctx, _user, session) = create_test_context_with_user().await;

        let create_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "primary" })),
            None,
        );
        let create_response = plugin.handle_create(&create_req, &ctx).await.unwrap();
        assert_eq!(create_response.status, 200);

        let body = json_body(&create_response);
        assert!(body.get("key").is_some());
        assert!(body.get("key_hash").is_none());
        assert!(body.get("hash").is_none());

        let id = body["id"].as_str().unwrap();
        let mut query = HashMap::new();
        query.insert("id".to_string(), id.to_string());

        let get_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/get",
            Some(&session.token),
            None,
            Some(query),
        );
        let get_response = plugin.handle_get(&get_req, &ctx).await.unwrap();
        assert_eq!(get_response.status, 200);

        let get_body = json_body(&get_response);
        assert!(get_body.get("key").is_none());
        assert!(get_body.get("key_hash").is_none());
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_expires_in() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "expiresIn": -1 })),
            None,
        );
        let response = plugin.handle_create(&req, &ctx).await;
        // Should be rejected due to validation (negative expires_in)
        assert!(response.is_err() || response.unwrap().status != 200);
    }

    #[tokio::test]
    async fn test_get_update_delete_return_404_for_non_owner() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user1, session1) = create_test_context_with_user().await;
        let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session1.token, "owner-key").await;

        let mut get_query = HashMap::new();
        get_query.insert("id".to_string(), key_id.clone());
        let get_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/get",
            Some(&session2.token),
            None,
            Some(get_query),
        );
        let get_err = plugin.handle_get(&get_req, &ctx).await.unwrap_err();
        assert_eq!(get_err.status_code(), 404);

        let update_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/update",
            Some(&session2.token),
            Some(serde_json::json!({ "id": key_id, "name": "new-name" })),
            None,
        );
        let update_err = plugin.handle_update(&update_req, &ctx).await.unwrap_err();
        assert_eq!(update_err.status_code(), 404);

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(&session2.token),
            Some(serde_json::json!({ "id": key_id })),
            None,
        );
        let delete_err = plugin.handle_delete(&delete_req, &ctx).await.unwrap_err();
        assert_eq!(delete_err.status_code(), 404);
    }

    #[tokio::test]
    async fn test_list_returns_only_user_keys() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, user1, session1) = create_test_context_with_user().await;
        let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;

        let _ = create_key_and_get_id(&plugin, &ctx, &session1.token, "u1-key").await;
        let _ = create_key_and_get_id(&plugin, &ctx, &session2.token, "u2-key").await;

        let list_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/list",
            Some(&session1.token),
            None,
            None,
        );
        let list_response = plugin.handle_list(&list_req, &ctx).await.unwrap();
        assert_eq!(list_response.status, 200);

        let list_body = json_body(&list_response);
        let list = list_body.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["userId"].as_str().unwrap(), user1.id);
        assert!(list[0].get("key").is_none());
        assert!(list[0].get("key_hash").is_none());
    }

    #[tokio::test]
    async fn test_owner_can_delete_key() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "to-delete").await;

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(&session.token),
            Some(serde_json::json!({ "id": key_id })),
            None,
        );
        let delete_response = plugin.handle_delete(&delete_req, &ctx).await.unwrap();
        assert_eq!(delete_response.status, 200);

        let deleted = ctx.database.get_api_key_by_id(&key_id).await.unwrap();
        assert!(deleted.is_none());
    }

    // -----------------------------------------------------------------------
    // New tests: verify, rate-limit, remaining/refill, delete expired, config
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_valid_key() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "verify-test" }),
        )
        .await;

        let verify_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({ "key": raw_key })),
            None,
        );
        let resp = plugin.handle_verify(&verify_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["valid"], true);
        assert!(body["key"].is_object());
    }

    #[tokio::test]
    async fn test_verify_invalid_key() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let verify_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({ "key": "definitely-not-a-valid-key" })),
            None,
        );
        let resp = plugin.handle_verify(&verify_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["valid"], false);
        assert!(body["error"].is_object());
    }

    #[tokio::test]
    async fn test_verify_disabled_key() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "disable-test" }),
        )
        .await;

        // Disable the key
        let update = UpdateApiKey {
            enabled: Some(false),
            ..Default::default()
        };
        ctx.database.update_api_key(&id, update).await.unwrap();

        let verify_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({ "key": raw_key })),
            None,
        );
        let resp = plugin.handle_verify(&verify_req, &ctx).await.unwrap();
        let body = json_body(&resp);
        assert_eq!(body["valid"], false);
        assert_eq!(body["error"]["code"], "KEY_DISABLED");
    }

    #[tokio::test]
    async fn test_verify_expired_key() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "expire-test" }),
        )
        .await;

        // Set expiration to the past
        let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
        let update = UpdateApiKey {
            expires_at: Some(Some(past)),
            ..Default::default()
        };
        ctx.database.update_api_key(&id, update).await.unwrap();

        let verify_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({ "key": raw_key })),
            None,
        );
        let resp = plugin.handle_verify(&verify_req, &ctx).await.unwrap();
        let body = json_body(&resp);
        assert_eq!(body["valid"], false);
        assert_eq!(body["error"]["code"], "KEY_EXPIRED");

        // The key should have been deleted
        let deleted = ctx.database.get_api_key_by_id(&id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_verify_remaining_consumption() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "remain-test", "remaining": 2 }),
        )
        .await;

        let make_verify = |key: &str| {
            create_auth_request(
                HttpMethod::Post,
                "/api-key/verify",
                None,
                Some(serde_json::json!({ "key": key })),
                None,
            )
        };

        // First verify - remaining goes from 2 to 1
        let resp1 = plugin
            .handle_verify(&make_verify(&raw_key), &ctx)
            .await
            .unwrap();
        assert_eq!(json_body(&resp1)["valid"], true);
        assert_eq!(json_body(&resp1)["key"]["remaining"], 1);

        // Second verify - remaining goes from 1 to 0
        let resp2 = plugin
            .handle_verify(&make_verify(&raw_key), &ctx)
            .await
            .unwrap();
        assert_eq!(json_body(&resp2)["valid"], true);
        assert_eq!(json_body(&resp2)["key"]["remaining"], 0);

        // Third verify - should fail (usage exceeded)
        let resp3 = plugin
            .handle_verify(&make_verify(&raw_key), &ctx)
            .await
            .unwrap();
        let body3 = json_body(&resp3);
        assert_eq!(body3["valid"], false);
        assert_eq!(body3["error"]["code"], "USAGE_EXCEEDED");
    }

    #[tokio::test]
    async fn test_verify_rate_limiting() {
        let plugin = ApiKeyPlugin::new().rate_limit(RateLimitDefaults {
            enabled: true,
            time_window: 60_000,
            max_requests: 2,
        });
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({
                "name": "rl-test",
                "rateLimitEnabled": true,
                "rateLimitTimeWindow": 60000,
                "rateLimitMax": 2
            }),
        )
        .await;

        let make_verify = |key: &str| {
            create_auth_request(
                HttpMethod::Post,
                "/api-key/verify",
                None,
                Some(serde_json::json!({ "key": key })),
                None,
            )
        };

        // First two should succeed
        let r1 = plugin
            .handle_verify(&make_verify(&raw_key), &ctx)
            .await
            .unwrap();
        assert_eq!(json_body(&r1)["valid"], true);

        let r2 = plugin
            .handle_verify(&make_verify(&raw_key), &ctx)
            .await
            .unwrap();
        assert_eq!(json_body(&r2)["valid"], true);

        // Third should fail with rate limit
        let r3 = plugin
            .handle_verify(&make_verify(&raw_key), &ctx)
            .await
            .unwrap();
        let b3 = json_body(&r3);
        assert_eq!(b3["valid"], false);
        assert_eq!(b3["error"]["code"], "RATE_LIMITED");
    }

    #[tokio::test]
    async fn test_delete_all_expired() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Create two keys
        let (id1, _) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "will-expire" }),
        )
        .await;
        let (_id2, _) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "wont-expire" }),
        )
        .await;

        // Expire the first key
        let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
        ctx.database
            .update_api_key(
                &id1,
                UpdateApiKey {
                    expires_at: Some(Some(past)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete-all-expired-api-keys",
            None,
            None,
            None,
        );
        let resp = plugin
            .handle_delete_all_expired(&delete_req, &ctx)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["deleted"], 1);

        // Only the non-expired key should remain
        let remaining_keys = ctx.database.list_api_keys_by_user(&_user.id).await.unwrap();
        assert_eq!(remaining_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_verify_permissions() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({
                "name": "perm-test",
                "permissions": { "admin": ["read", "write"], "user": ["read"] }
            }),
        )
        .await;

        // Verify with matching permissions -> should pass
        let verify_ok = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({
                "key": raw_key,
                "permissions": { "admin": ["read"] }
            })),
            None,
        );
        let r1 = plugin.handle_verify(&verify_ok, &ctx).await.unwrap();
        assert_eq!(json_body(&r1)["valid"], true);

        // Verify with non-matching permissions -> should fail
        let verify_fail = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({
                "key": raw_key,
                "permissions": { "superadmin": ["delete"] }
            })),
            None,
        );
        let r2 = plugin.handle_verify(&verify_fail, &ctx).await.unwrap();
        assert_eq!(json_body(&r2)["valid"], false);
    }

    #[tokio::test]
    async fn test_config_validation_prefix_length() {
        let plugin = ApiKeyPlugin::new()
            .min_prefix_length(2)
            .max_prefix_length(5);
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Too short prefix
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "prefix": "a" })),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("prefix length"));

        // Too long prefix
        let req2 = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "prefix": "toolong" })),
            None,
        );
        let err2 = plugin.handle_create(&req2, &ctx).await.unwrap_err();
        assert!(err2.to_string().contains("prefix length"));
    }

    #[tokio::test]
    async fn test_config_require_name() {
        let plugin = ApiKeyPlugin::new().require_name(true);
        let (ctx, _user, session) = create_test_context_with_user().await;

        // No name provided -> should fail
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({})),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("name is required"));
    }

    #[tokio::test]
    async fn test_config_metadata_disabled() {
        let plugin = ApiKeyPlugin::new(); // enable_metadata defaults to false
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "metadata": { "env": "prod" } })),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("Metadata is disabled"));
    }

    #[tokio::test]
    async fn test_config_metadata_enabled() {
        let plugin = ApiKeyPlugin::new().enable_metadata(true);
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "metadata": { "env": "prod" } })),
            None,
        );
        let resp = plugin.handle_create(&req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(body["metadata"]["env"], "prod");
    }

    #[tokio::test]
    async fn test_update_with_expires_in() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "update-exp").await;

        let update_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/update",
            Some(&session.token),
            Some(serde_json::json!({
                "id": key_id,
                "expiresIn": 86400000
            })),
            None,
        );
        let resp = plugin.handle_update(&update_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert!(body["expiresAt"].is_string());
    }

    #[tokio::test]
    async fn test_on_request_dispatches_verify() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "dispatch-test" }),
        )
        .await;

        let verify_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/verify",
            None,
            Some(serde_json::json!({ "key": raw_key })),
            None,
        );
        let resp = plugin.on_request(&verify_req, &ctx).await.unwrap();
        assert!(resp.is_some());
        let body = json_body(&resp.unwrap());
        assert_eq!(body["valid"], true);
    }

    #[tokio::test]
    async fn test_on_request_dispatches_delete_all_expired() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete-all-expired-api-keys",
            None,
            None,
            None,
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(resp.is_some());
        let body = json_body(&resp.unwrap());
        assert_eq!(body["deleted"], 0);
    }

    #[tokio::test]
    async fn test_refill_logic() {
        // Ensure refillInterval + refillAmount require each other
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({
                "name": "refill-missing",
                "refillInterval": 60000
            })),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("refillAmount"));
    }
}
