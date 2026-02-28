use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthApiKey, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute, BeforeRequestAction};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod, UpdateApiKey};

pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

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
    /// Return the SCREAMING_SNAKE_CASE string for this error code.
    /// Used by `handle_verify` to produce the structured JSON error response.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidApiKey => "INVALID_API_KEY",
            Self::KeyDisabled => "KEY_DISABLED",
            Self::KeyExpired => "KEY_EXPIRED",
            Self::UsageExceeded => "USAGE_EXCEEDED",
            Self::KeyNotFound => "KEY_NOT_FOUND",
            Self::RateLimited => "RATE_LIMITED",
            Self::UnauthorizedSession => "UNAUTHORIZED_SESSION",
            Self::InvalidPrefixLength => "INVALID_PREFIX_LENGTH",
            Self::InvalidNameLength => "INVALID_NAME_LENGTH",
            Self::MetadataDisabled => "METADATA_DISABLED",
            Self::NoValuesToUpdate => "NO_VALUES_TO_UPDATE",
            Self::KeyDisabledExpiration => "KEY_DISABLED_EXPIRATION",
            Self::ExpiresInTooSmall => "EXPIRES_IN_IS_TOO_SMALL",
            Self::ExpiresInTooLarge => "EXPIRES_IN_IS_TOO_LARGE",
            Self::InvalidRemaining => "INVALID_REMAINING",
            Self::RefillAmountAndIntervalRequired => "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
            Self::NameRequired => "NAME_REQUIRED",
            Self::InvalidUserIdFromApiKey => "INVALID_USER_ID_FROM_API_KEY",
            Self::ServerOnlyProperty => "SERVER_ONLY_PROPERTY",
            Self::FailedToUpdateApiKey => "FAILED_TO_UPDATE_API_KEY",
            Self::InvalidMetadataType => "INVALID_METADATA_TYPE",
        }
    }

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

/// Structured error returned by `validate_api_key` so that `handle_verify`
/// can extract the error code without fragile string matching.
struct ApiKeyValidationError {
    code: ApiKeyErrorCode,
    message: String,
}

impl ApiKeyValidationError {
    fn new(code: ApiKeyErrorCode) -> Self {
        Self {
            message: code.message().to_string(),
            code,
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// API Key management plugin.
pub struct ApiKeyPlugin {
    pub(super) config: ApiKeyConfig,
    /// Throttle for `delete_expired_api_keys` -- stores the last check instant.
    last_expired_check: Mutex<Option<std::time::Instant>>,
    /// Per-key in-memory rate limiters backed by the `governor` crate.
    /// Key: API key ID -> governor rate limiter.
    pub(super) rate_limiters: Mutex<HashMap<String, std::sync::Arc<GovernorLimiter>>>,
}

/// Type alias for the governor rate limiter we use (not keyed, in-memory, default clock).
type GovernorLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

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
// Plugin implementation
// ---------------------------------------------------------------------------

/// Builder for [`ApiKeyPlugin`] powered by the `bon` crate.
///
/// Usage:
/// ```ignore
/// let plugin = ApiKeyPlugin::builder()
///     .key_length(48)
///     .prefix("ba_".to_string())
///     .enable_metadata(true)
///     .rate_limit(RateLimitDefaults { enabled: true, time_window: 60_000, max_requests: 5 })
///     .build();
/// ```
#[bon::bon]
impl ApiKeyPlugin {
    #[builder]
    pub fn new(
        #[builder(default = 32)] key_length: usize,
        prefix: Option<String>,
        default_remaining: Option<i64>,
        #[builder(default = "x-api-key".to_string())] api_key_header: String,
        #[builder(default = false)] disable_key_hashing: bool,
        #[builder(default = 6)] starting_characters_length: usize,
        #[builder(default = true)] store_starting_characters: bool,
        #[builder(default = 32)] max_prefix_length: usize,
        #[builder(default = 1)] min_prefix_length: usize,
        #[builder(default = 32)] max_name_length: usize,
        #[builder(default = 1)] min_name_length: usize,
        #[builder(default = false)] require_name: bool,
        #[builder(default = false)] enable_metadata: bool,
        #[builder(default)] key_expiration: KeyExpirationConfig,
        #[builder(default)] rate_limit: RateLimitDefaults,
        #[builder(default = false)] enable_session_for_api_keys: bool,
    ) -> Self {
        Self {
            config: ApiKeyConfig {
                key_length,
                prefix,
                default_remaining,
                api_key_header,
                disable_key_hashing,
                starting_characters_length,
                store_starting_characters,
                max_prefix_length,
                min_prefix_length,
                max_name_length,
                min_name_length,
                require_name,
                enable_metadata,
                key_expiration,
                rate_limit,
                enable_session_for_api_keys,
            },
            last_expired_check: Mutex::new(None),
            rate_limiters: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_config(config: ApiKeyConfig) -> Self {
        Self {
            config,
            last_expired_check: Mutex::new(None),
            rate_limiters: Mutex::new(HashMap::new()),
        }
    }

    // -- internal helpers --

    pub(super) fn generate_key(&self, custom_prefix: Option<&str>) -> (String, String, String) {
        let mut bytes = vec![0u8; self.config.key_length];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let raw = URL_SAFE_NO_PAD.encode(&bytes);

        let start_len = self.config.starting_characters_length;
        let start = raw.chars().take(start_len).collect::<String>();

        let prefix = custom_prefix
            .or(self.config.prefix.as_deref())
            .unwrap_or("");
        let full_key = format!("{}{}", prefix, raw);

        let hash = if self.config.disable_key_hashing {
            full_key.clone()
        } else {
            Self::hash_key(&full_key)
        };

        (full_key, hash, start)
    }

    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Throttled cleanup -- at most once per 10 seconds.
    pub(super) async fn maybe_delete_expired<DB: DatabaseAdapter>(&self, ctx: &AuthContext<DB>) {
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

    pub(super) fn validate_prefix(&self, prefix: Option<&str>) -> AuthResult<()> {
        if let Some(p) = prefix {
            let len = p.len();
            if len < self.config.min_prefix_length || len > self.config.max_prefix_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidPrefixLength));
            }
        }
        Ok(())
    }

    /// Validate the `name` field.
    ///
    /// When `is_create` is true, `require_name` is enforced (name must be
    /// present).  On updates `require_name` is **not** enforced -- the
    /// caller may be updating unrelated fields without resending the name.
    pub(super) fn validate_name(&self, name: Option<&str>, is_create: bool) -> AuthResult<()> {
        if is_create && self.config.require_name && name.is_none() {
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

    pub(super) fn validate_expires_in(&self, expires_in: Option<i64>) -> AuthResult<Option<i64>> {
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

    pub(super) fn validate_metadata(&self, metadata: &Option<serde_json::Value>) -> AuthResult<()> {
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

    pub(super) fn validate_refill(
        refill_interval: Option<i64>,
        refill_amount: Option<i64>,
    ) -> AuthResult<()> {
        match (refill_interval, refill_amount) {
            (Some(_), None) | (None, Some(_)) => Err(api_key_error(
                ApiKeyErrorCode::RefillAmountAndIntervalRequired,
            )),
            _ => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // Route handlers (old -- delegate to core functions)
    // -----------------------------------------------------------------------

    async fn handle_create<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: CreateKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = create_key_core(&body, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_get<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let id = req
            .query
            .get("id")
            .ok_or_else(|| AuthError::bad_request("Query parameter 'id' is required"))?;
        let response = get_key_core(id, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_list<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let response = list_keys_core(user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_update<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: UpdateKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = update_key_core(&body, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_delete<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: DeleteKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = delete_key_core(&body, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    // -----------------------------------------------------------------------
    // POST /api-key/verify -- core verification endpoint
    // -----------------------------------------------------------------------

    async fn handle_verify<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let verify_req: VerifyKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = verify_key_core(&verify_req, self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    /// Core validation logic shared by `handle_verify` and `before_request`.
    ///
    /// Validation chain: exists -> disabled -> expired -> permissions ->
    /// remaining/refill -> rate limit.
    ///
    /// Returns `Ok(ApiKeyView)` on success, or `Err(ApiKeyValidationError)` with
    /// a structured error code (no fragile string matching needed).
    async fn validate_api_key<DB: DatabaseAdapter>(
        &self,
        ctx: &AuthContext<DB>,
        raw_key: &str,
        required_permissions: Option<&serde_json::Value>,
    ) -> Result<ApiKeyView, ApiKeyValidationError> {
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
            .await
            .map_err(|_| ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey))?
            .ok_or_else(|| ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey))?;

        // 1. Disabled?
        if !api_key.enabled() {
            return Err(ApiKeyValidationError::new(ApiKeyErrorCode::KeyDisabled));
        }

        // 2. Expired?
        if let Some(expires_at_str) = api_key.expires_at()
            && let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str)
            && chrono::Utc::now() > expires_at
        {
            // Delete expired key and evict its cached rate limiter
            let _ = ctx.database.delete_api_key(api_key.id()).await;
            self.rate_limiters
                .lock()
                .expect("rate_limiters mutex poisoned")
                .remove(api_key.id());
            return Err(ApiKeyValidationError::new(ApiKeyErrorCode::KeyExpired));
        }

        // 3. Permissions check
        if let Some(required) = required_permissions {
            let key_perms_str = api_key.permissions().unwrap_or("");
            if key_perms_str.is_empty() {
                return Err(ApiKeyValidationError::new(ApiKeyErrorCode::KeyNotFound));
            }
            if !check_permissions(key_perms_str, required) {
                return Err(ApiKeyValidationError::new(ApiKeyErrorCode::KeyNotFound));
            }
        }

        // 4. Remaining / refill
        let mut new_remaining = api_key.remaining();
        let mut new_last_refill_at: Option<String> =
            api_key.last_refill_at().map(|s| s.to_string());

        if let Some(0) = api_key.remaining()
            && api_key.refill_amount().is_none()
        {
            // Usage exhausted, no refill configured -- delete key and evict cache
            let _ = ctx.database.delete_api_key(api_key.id()).await;
            self.rate_limiters
                .lock()
                .expect("rate_limiters mutex poisoned")
                .remove(api_key.id());
            return Err(ApiKeyValidationError::new(ApiKeyErrorCode::UsageExceeded));
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
                return Err(ApiKeyValidationError::new(ApiKeyErrorCode::UsageExceeded));
            }

            new_remaining = Some(current_remaining - 1);
        }

        // 5. Rate limiting via `governor` crate
        self.check_rate_limit_governor(&api_key)?;

        // 6. Build update
        let mut update = UpdateApiKey {
            remaining: new_remaining,
            ..Default::default()
        };
        if new_last_refill_at != api_key.last_refill_at().map(|s| s.to_string()) {
            update.last_refill_at = Some(new_last_refill_at);
        }

        let updated = ctx
            .database
            .update_api_key(api_key.id(), update)
            .await
            .map_err(|_| ApiKeyValidationError::new(ApiKeyErrorCode::FailedToUpdateApiKey))?;

        // Throttled cleanup
        self.maybe_delete_expired(ctx).await;

        Ok(ApiKeyView::from_entity(&updated))
    }

    /// Check rate limiting for an API key using the `governor` crate.
    ///
    /// Creates or retrieves a per-key in-memory rate limiter backed by GCRA
    /// (Generic Cell Rate Algorithm), which is thread-safe and lock-free on
    /// the hot path.
    fn check_rate_limit_governor(
        &self,
        api_key: &impl AuthApiKey,
    ) -> Result<(), ApiKeyValidationError> {
        // Determine if rate limiting is enabled for this key.
        let key_has_explicit_setting =
            api_key.rate_limit_time_window().is_some() || api_key.rate_limit_max().is_some();
        let key_enabled = api_key.rate_limit_enabled();

        if !key_enabled {
            // Key explicitly disabled rate limiting -- skip.
            if key_has_explicit_setting {
                return Ok(());
            }
            // Key has no explicit setting and global is also off -- skip.
            if !self.config.rate_limit.enabled {
                return Ok(());
            }
        }

        let time_window_ms = api_key
            .rate_limit_time_window()
            .unwrap_or(self.config.rate_limit.time_window);
        let max_requests = api_key
            .rate_limit_max()
            .unwrap_or(self.config.rate_limit.max_requests);

        if time_window_ms <= 0 || max_requests <= 0 {
            return Ok(());
        }

        let key_id = api_key.id().to_string();

        // Get or create the rate limiter for this key
        let limiter = {
            let mut limiters = self
                .rate_limiters
                .lock()
                .expect("rate_limiters mutex poisoned");
            limiters
                .entry(key_id)
                .or_insert_with(|| {
                    let max = NonZeroU32::new(max_requests as u32).unwrap_or(NonZeroU32::MIN);
                    let period_ms = (time_window_ms as u64)
                        .checked_div(max_requests as u64)
                        .unwrap_or(0);
                    // Guard against zero-period panic (e.g. time_window_ms < max_requests)
                    let period = std::time::Duration::from_millis(period_ms.max(1));
                    let quota = Quota::with_period(period)
                        .expect("period >= 1ms is always valid")
                        .allow_burst(max);
                    std::sync::Arc::new(RateLimiter::direct(quota))
                })
                .clone()
        };

        match limiter.check() {
            Ok(()) => Ok(()),
            Err(_not_until) => Err(ApiKeyValidationError::new(ApiKeyErrorCode::RateLimited)),
        }
    }

    // -----------------------------------------------------------------------
    // POST /api-key/delete-all-expired-api-keys
    // -----------------------------------------------------------------------

    async fn handle_delete_all_expired<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let response = delete_all_expired_core(user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
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

        // Skip session emulation for API-key management routes to avoid
        // double-validating the key (before_request + handle_verify both
        // call validate_api_key, consuming usage/rate-limit budget twice).
        if req.path().starts_with("/api-key/") {
            return Ok(None);
        }

        // Validate the key (reuses the full verify logic)
        let view = self
            .validate_api_key(ctx, &raw_key, None)
            .await
            .map_err(|e| AuthError::bad_request(e.message))?;

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

// ---------------------------------------------------------------------------
// Axum integration
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::Extension;
    use axum::extract::{Query, State};
    use better_auth_core::{AuthState, CurrentSession, ValidatedJson};
    use serde::Deserialize;

    /// Query parameters for GET /api-key/get
    #[derive(Debug, Deserialize)]
    struct GetKeyQuery {
        id: String,
    }

    async fn handle_create<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<CreateKeyRequest>,
    ) -> Result<Json<CreateKeyResponse>, AuthError> {
        let ctx = state.to_context();
        let response = create_key_core(&body, user.id(), &plugin, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_get<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        Query(query): Query<GetKeyQuery>,
    ) -> Result<Json<ApiKeyView>, AuthError> {
        let ctx = state.to_context();
        let response = get_key_core(&query.id, user.id(), &plugin, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_list<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<Vec<ApiKeyView>>, AuthError> {
        let ctx = state.to_context();
        let response = list_keys_core(user.id(), &plugin, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_update<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<UpdateKeyRequest>,
    ) -> Result<Json<ApiKeyView>, AuthError> {
        let ctx = state.to_context();
        let response = update_key_core(&body, user.id(), &plugin, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_delete<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<DeleteKeyRequest>,
    ) -> Result<Json<serde_json::Value>, AuthError> {
        let ctx = state.to_context();
        let response = delete_key_core(&body, user.id(), &plugin, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_verify<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        Json(body): Json<VerifyKeyRequest>,
    ) -> Result<Json<VerifyKeyResponse>, AuthError> {
        let ctx = state.to_context();
        let response = verify_key_core(&body, &plugin, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_delete_all_expired<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(plugin): Extension<Arc<ApiKeyPlugin>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<serde_json::Value>, AuthError> {
        let ctx = state.to_context();
        let response = delete_all_expired_core(user.id(), &plugin, &ctx).await?;
        Ok(Json(response))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for ApiKeyPlugin {
        fn name(&self) -> &'static str {
            "api-key"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin = Arc::new(ApiKeyPlugin::with_config(self.config.clone()));
            axum::Router::new()
                .route("/api-key/create", post(handle_create::<DB>))
                .route("/api-key/get", get(handle_get::<DB>))
                .route("/api-key/update", post(handle_update::<DB>))
                .route("/api-key/delete", post(handle_delete::<DB>))
                .route("/api-key/list", get(handle_list::<DB>))
                .route("/api-key/verify", post(handle_verify::<DB>))
                .route(
                    "/api-key/delete-all-expired-api-keys",
                    post(handle_delete_all_expired::<DB>),
                )
                .layer(Extension(plugin))
        }
    }
}
