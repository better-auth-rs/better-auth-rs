use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

use better_auth_core::entity::AuthUser;
use better_auth_core::{AuthContext, AuthError, AuthResult, BeforeRequestAction};
use better_auth_core::{AuthRequest, AuthResponse};

pub(super) mod handlers;
pub(crate) mod storage;
pub use storage::ApiKeyStorage;
mod callbacks;
mod metadata;
mod permissions;
mod request;
pub(super) mod types;
mod verification;

pub use callbacks::{
    ApiKeyDefaultPermissions, ApiKeyEndpoint, ApiKeyGenerator, ApiKeyGetter, ApiKeyPermissions,
    ApiKeyValidator,
};

pub use verification::{
    ApiKeyErrorDetails, ApiKeyErrorMessage, ApiKeyValidationError, ApiKeyVerificationError,
    VerifyApiKey,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod crud_tests;

#[cfg(test)]
mod expiration_tests;

use handlers::*;
use types::*;
pub use types::{CreateKeyRequest, CreateKeyResponse, UpdateKeyRequest};

// ---------------------------------------------------------------------------
// Error codes -- mirrors the TypeScript `API_KEY_ERROR_CODES`
// ---------------------------------------------------------------------------

/// Dedicated API Key error codes aligned with the TypeScript `API_KEY_ERROR_CODES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyErrorCode {
    InvalidApiKey,
    KeyDisabled,
    KeyExpired,
    UsageExceeded,
    KeyNotFound,
    RateLimited,
    UnauthorizedSession,
    InvalidPrefixLength,
    InvalidNameLength,
    MetadataDisabled,
    NoValuesToUpdate,
    KeyDisabledExpiration,
    ExpiresInTooSmall,
    ExpiresInTooLarge,
    InvalidRemaining,
    RefillAmountAndIntervalRequired,
    RefillIntervalAndAmountRequired,
    NameRequired,
    InvalidUserIdFromApiKey,
    InvalidReferenceIdFromApiKey,
    NoDefaultConfiguration,
    OrganizationIdRequired,
    OrganizationPluginRequired,
    UserNotMemberOfOrganization,
    InsufficientApiKeyPermissions,
    ServerOnlyProperty,
    FailedToUpdateApiKey,
    InvalidMetadataType,
}

impl ApiKeyErrorCode {
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
            Self::RefillIntervalAndAmountRequired => "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
            Self::NameRequired => "NAME_REQUIRED",
            Self::InvalidUserIdFromApiKey => "INVALID_USER_ID_FROM_API_KEY",
            Self::InvalidReferenceIdFromApiKey => "INVALID_REFERENCE_ID_FROM_API_KEY",
            Self::NoDefaultConfiguration => "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
            Self::OrganizationIdRequired => "ORGANIZATION_ID_REQUIRED",
            Self::OrganizationPluginRequired => "ORGANIZATION_PLUGIN_REQUIRED",
            Self::UserNotMemberOfOrganization => "USER_NOT_MEMBER_OF_ORGANIZATION",
            Self::InsufficientApiKeyPermissions => "INSUFFICIENT_API_KEY_PERMISSIONS",
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
                "refillAmount is required when refillInterval is provided"
            }
            Self::RefillIntervalAndAmountRequired => {
                "refillInterval is required when refillAmount is provided"
            }
            Self::NameRequired => "API Key name is required.",
            Self::InvalidUserIdFromApiKey => "The user id from the API key is invalid.",
            Self::InvalidReferenceIdFromApiKey => "The reference id from the API key is invalid.",
            Self::NoDefaultConfiguration => "No default api-key configuration found.",
            Self::OrganizationIdRequired => {
                "Organization ID is required for organization-owned API keys."
            }
            Self::OrganizationPluginRequired => {
                "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin."
            }
            Self::UserNotMemberOfOrganization => {
                "You are not a member of the organization that owns this API key."
            }
            Self::InsufficientApiKeyPermissions => {
                "You do not have permission to perform this action on organization API keys."
            }
            Self::ServerOnlyProperty => {
                "The property you're trying to set can only be set from the server auth instance only."
            }
            Self::FailedToUpdateApiKey => "Failed to update API key",
            Self::InvalidMetadataType => "metadata must be an object or undefined",
        }
    }
}

impl serde::Serialize for ApiKeyErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

pub(super) fn api_key_error(code: ApiKeyErrorCode) -> AuthError {
    let status = match code {
        ApiKeyErrorCode::UnauthorizedSession => 401,
        ApiKeyErrorCode::OrganizationPluginRequired => 500,
        ApiKeyErrorCode::UserNotMemberOfOrganization
        | ApiKeyErrorCode::InsufficientApiKeyPermissions => 403,
        _ => 400,
    };
    AuthError::Upstream {
        status,
        code: code.as_str(),
        message: code.message(),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Which kind of entity a configuration's keys belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApiKeyReferences {
    /// Keys are owned by the signed-in user.
    #[default]
    User,
    /// Keys are owned by an organization; callers pass `organizationId` and
    /// must hold the matching `apiKey` permission in that organization.
    Organization,
}

/// API Key management plugin.
#[derive(Clone)]
pub struct ApiKeyPlugin {
    /// Registered configurations. Unscoped requests use the default configuration.
    pub(super) configurations: Vec<ApiKeyConfig>,
    /// Throttle for `delete_expired_api_keys` -- stores the last check instant.
    last_expired_check: Arc<Mutex<Option<std::time::Instant>>>,
}

impl ApiKeyPlugin {
    /// Register an additional named configuration.
    ///
    /// Upstream allows several api-key configurations side by side, each with
    /// its own `config_id`, ownership model and limits.
    pub fn configuration(mut self, config: ApiKeyConfig) -> Self {
        self.configurations.push(config.normalized());
        self
    }

    /// Pick the configuration a request addressed, mirroring upstream's
    /// `resolveConfiguration`: an unknown or absent `config_id` falls back to
    /// the default one, and a missing default is a client error.
    pub(super) fn resolve_configuration(
        &self,
        config_id: Option<&str>,
    ) -> AuthResult<&ApiKeyConfig> {
        if let Some(config_id) = config_id
            && let Some(found) = self
                .configurations
                .iter()
                .find(|config| config.config_id == config_id)
        {
            return Ok(found);
        }

        self.configurations
            .iter()
            .find(|config| is_default_config_id(&config.config_id))
            .ok_or_else(|| api_key_error(ApiKeyErrorCode::NoDefaultConfiguration))
    }
}

/// Keys written before `config_id` existed carry no value, so absent and
/// `"default"` denote the same configuration.
pub(super) fn is_default_config_id(config_id: &str) -> bool {
    config_id.is_empty() || config_id == "default"
}

/// Whether a stored key belongs to the addressed configuration.
pub(super) fn config_id_matches(
    key_config_id: &better_auth_core::SchemaValue<String>,
    expected: &str,
) -> bool {
    let value = key_config_id.field_value();
    if (!value.is_truthy() || key_config_id == "default") && is_default_config_id(expected) {
        return true;
    }
    key_config_id.field_value().strict_equals(&expected.into())
}

/// Configuration for the API Key plugin, aligned with the TypeScript `ApiKeyOptions`.
#[derive(Clone)]
pub struct ApiKeyConfig {
    /// Name of this configuration, stored on every key it creates.
    /// Upstream defaults it to `"default"`.
    pub config_id: String,
    /// Whether keys from this configuration belong to a user or to an
    /// organization.
    pub references: ApiKeyReferences,

    // -- key generation --
    /// Random characters per key. Zero selects the upstream default of 64.
    pub key_length: usize,
    pub prefix: Option<String>,
    /// Permissions applied when creation does not supply explicit permissions.
    pub default_permissions: Option<std::collections::HashMap<String, Vec<String>>>,
    /// Custom credential generator, receiving the resolved length and prefix.
    pub custom_key_generator: Option<Arc<dyn ApiKeyGenerator>>,
    /// Dynamic defaults, evaluated even when creation supplies explicit permissions.
    pub default_permissions_callback: Option<Arc<dyn ApiKeyDefaultPermissions>>,

    // -- header --
    pub api_key_headers: Vec<String>,
    /// Overrides header extraction for session emulation.
    pub custom_api_key_getter: Option<Arc<dyn ApiKeyGetter>>,
    /// Validates the presented plaintext credential before normal key validation.
    pub custom_api_key_validator: Option<Arc<dyn ApiKeyValidator>>,

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
    /// Persistence mode. Custom storage overrides the global secondary storage.
    pub storage: ApiKeyStorage,
    pub custom_storage: Option<Arc<dyn better_auth_core::store::SecondaryStorage>>,
    /// Keep database rows authoritative and repopulate cache misses.
    pub fallback_to_database: bool,
    /// Defer secondary-only usage writes and expired/exhausted key deletion.
    pub defer_updates: bool,
}

impl ApiKeyConfig {
    fn normalized(mut self) -> Self {
        if self.key_length == 0 {
            self.key_length = 64;
        }
        self
    }
}

impl std::fmt::Debug for ApiKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyConfig")
            .field("config_id", &self.config_id)
            .field("references", &self.references)
            .field("key_length", &self.key_length)
            .field("prefix", &self.prefix)
            .field("default_permissions", &self.default_permissions)
            .field("custom_key_generator", &self.custom_key_generator.is_some())
            .field(
                "default_permissions_callback",
                &self.default_permissions_callback.is_some(),
            )
            .field(
                "custom_api_key_getter",
                &self.custom_api_key_getter.is_some(),
            )
            .field(
                "custom_api_key_validator",
                &self.custom_api_key_validator.is_some(),
            )
            .field("api_key_headers", &self.api_key_headers)
            .field("disable_key_hashing", &self.disable_key_hashing)
            .field(
                "starting_characters_length",
                &self.starting_characters_length,
            )
            .field("store_starting_characters", &self.store_starting_characters)
            .field("max_prefix_length", &self.max_prefix_length)
            .field("min_prefix_length", &self.min_prefix_length)
            .field("max_name_length", &self.max_name_length)
            .field("min_name_length", &self.min_name_length)
            .field("require_name", &self.require_name)
            .field("enable_metadata", &self.enable_metadata)
            .field("key_expiration", &self.key_expiration)
            .field("rate_limit", &self.rate_limit)
            .field(
                "enable_session_for_api_keys",
                &self.enable_session_for_api_keys,
            )
            .field("storage", &self.storage)
            .field("custom_storage", &self.custom_storage.is_some())
            .field("fallback_to_database", &self.fallback_to_database)
            .field("defer_updates", &self.defer_updates)
            .finish_non_exhaustive()
    }
}

/// Key expiration constraints.
#[derive(Debug, Clone)]
pub struct KeyExpirationConfig {
    /// Default `expiresIn` (in seconds) when none is provided. `None` = no default.
    pub default_expires_in: Option<f64>,
    /// If true, clients cannot set a custom `expiresIn`.
    pub disable_custom_expires_time: bool,
    /// Maximum `expiresIn` in **days**.
    pub max_expires_in: f64,
    /// Minimum `expiresIn` in **days**.
    pub min_expires_in: f64,
}

impl Default for KeyExpirationConfig {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            max_expires_in: 365.0,
            min_expires_in: 1.0,
        }
    }
}

/// Global rate-limit defaults applied to newly-created keys.
#[derive(Debug, Clone)]
pub struct RateLimitDefaults {
    pub enabled: bool,
    /// Default time window in milliseconds.
    pub time_window: f64,
    /// Default max requests per window.
    pub max_requests: f64,
}

impl Default for RateLimitDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window: 86_400_000.0, // 24 hours
            max_requests: 10.0,
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            config_id: "default".to_string(),
            references: ApiKeyReferences::default(),
            key_length: 64,
            prefix: None,
            default_permissions: None,
            custom_key_generator: None,
            default_permissions_callback: None,
            api_key_headers: vec!["x-api-key".to_string()],
            custom_api_key_getter: None,
            custom_api_key_validator: None,
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
            storage: ApiKeyStorage::Database,
            custom_storage: None,
            fallback_to_database: false,
            defer_updates: false,
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
///     .rate_limit(RateLimitDefaults { enabled: true, time_window: 60_000.0, max_requests: 5.0 })
///     .build();
/// ```
#[bon::bon]
impl ApiKeyPlugin {
    #[builder]
    pub fn new(
        #[builder(default = "default".to_string())] config_id: String,
        #[builder(default)] references: ApiKeyReferences,
        #[builder(default = 64)] key_length: usize,
        prefix: Option<String>,
        default_permissions: Option<std::collections::HashMap<String, Vec<String>>>,
        custom_key_generator: Option<Arc<dyn ApiKeyGenerator>>,
        default_permissions_callback: Option<Arc<dyn ApiKeyDefaultPermissions>>,
        #[builder(default = vec!["x-api-key".to_string()])] api_key_headers: Vec<String>,
        custom_api_key_getter: Option<Arc<dyn ApiKeyGetter>>,
        custom_api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
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
        #[builder(default)] storage: ApiKeyStorage,
        custom_storage: Option<Arc<dyn better_auth_core::store::SecondaryStorage>>,
        #[builder(default)] fallback_to_database: bool,
        #[builder(default)] defer_updates: bool,
    ) -> Self {
        Self {
            configurations: vec![
                ApiKeyConfig {
                    config_id,
                    references,
                    key_length,
                    prefix,
                    default_permissions,
                    custom_key_generator,
                    default_permissions_callback,
                    api_key_headers,
                    custom_api_key_getter,
                    custom_api_key_validator,
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
                    storage,
                    custom_storage,
                    fallback_to_database,
                    defer_updates,
                }
                .normalized(),
            ],
            last_expired_check: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_config(config: ApiKeyConfig) -> Self {
        Self {
            configurations: vec![config.normalized()],
            last_expired_check: Arc::new(Mutex::new(None)),
        }
    }

    // -- internal helpers --

    pub(super) fn generate_key(
        config: &ApiKeyConfig,
        custom_prefix: Option<&str>,
    ) -> (String, String) {
        // Match TS: generateRandomString(length, "a-z", "A-Z") — alpha only
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut rng = rand::thread_rng();
        let raw: String = (0..config.key_length)
            .map(|_| {
                ALPHABET
                    .choose(&mut rng)
                    .copied()
                    .map(char::from)
                    .unwrap_or('a')
            })
            .collect();

        let prefix = custom_prefix.or(config.prefix.as_deref()).unwrap_or("");
        let full_key = format!("{}{}", prefix, raw);

        let hash = if config.disable_key_hashing {
            full_key.clone()
        } else {
            Self::hash_key(&full_key)
        };

        (full_key, hash)
    }

    pub(super) fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Throttled cleanup -- at most once per 10 seconds.
    pub(super) async fn maybe_delete_expired(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) {
        let should_run = {
            let mut last = self
                .last_expired_check
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let now = std::time::Instant::now();
            match *last {
                Some(prev) if now.duration_since(prev).as_secs() < 10 => false,
                _ => {
                    *last = Some(now);
                    true
                }
            }
        };
        if should_run && let Err(error) = ctx.database.delete_expired_api_keys().await {
            better_auth_core::observability::logger::current().error(
                "Failed to delete expired API keys",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
        }
    }

    // -- Validation helpers --

    pub(super) fn validate_prefix(config: &ApiKeyConfig, prefix: Option<&str>) -> AuthResult<()> {
        if let Some(p) = prefix.filter(|prefix| !prefix.is_empty()) {
            let len = p.encode_utf16().count();
            if len < config.min_prefix_length || len > config.max_prefix_length {
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
    pub(super) fn validate_name(
        config: &ApiKeyConfig,
        name: Option<&str>,
        is_create: bool,
    ) -> AuthResult<()> {
        if is_create && config.require_name && name.is_none_or(str::is_empty) {
            return Err(api_key_error(ApiKeyErrorCode::NameRequired));
        }
        if let Some(n) = name.filter(|name| !is_create || !name.is_empty()) {
            let len = n.encode_utf16().count();
            if len < config.min_name_length || len > config.max_name_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidNameLength));
            }
        }
        Ok(())
    }

    pub(super) fn validate_expires_in(
        config: &ApiKeyConfig,
        expires_in: Option<f64>,
    ) -> AuthResult<Option<f64>> {
        let cfg = &config.key_expiration;
        if let Some(secs) = expires_in {
            if cfg.disable_custom_expires_time {
                return Err(api_key_error(ApiKeyErrorCode::KeyDisabledExpiration));
            }
            // expiresIn is in seconds; min/max are in days
            let days = secs / 86_400.0;
            if days < cfg.min_expires_in {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooSmall));
            }
            if days > cfg.max_expires_in {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooLarge));
            }
            Ok(Some(secs))
        } else {
            Ok(cfg.default_expires_in)
        }
    }

    pub(super) fn validate_metadata(
        config: &ApiKeyConfig,
        metadata: &Option<serde_json::Value>,
    ) -> AuthResult<()> {
        if let Some(value) = metadata.as_ref().filter(|value| match value {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::Number(value) => value.as_f64() != Some(0.0),
            serde_json::Value::String(value) => !value.is_empty(),
            _ => true,
        }) {
            if !config.enable_metadata {
                return Err(api_key_error(ApiKeyErrorCode::MetadataDisabled));
            }
            if !value.is_object() && !value.is_array() {
                return Err(api_key_error(ApiKeyErrorCode::InvalidMetadataType));
            }
        }
        Ok(())
    }

    pub(super) fn validate_refill(
        refill_interval: Option<f64>,
        refill_amount: Option<f64>,
    ) -> AuthResult<()> {
        match (
            refill_interval.filter(|value| *value != 0.0),
            refill_amount.filter(|value| *value != 0.0),
        ) {
            (None, Some(_)) => Err(api_key_error(
                ApiKeyErrorCode::RefillAmountAndIntervalRequired,
            )),
            (Some(_), None) => Err(api_key_error(
                ApiKeyErrorCode::RefillIntervalAndAmountRequired,
            )),
            _ => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // Route handlers
    // -----------------------------------------------------------------------

    async fn handle_create(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: CreateKeyRequest = request::read(req)?;
        let config = self.resolve_configuration(body.config_id.as_deref())?;
        let session = ctx
            .session_manager()
            .resolve(req, better_auth_core::session::SessionRead::Authoritative)
            .await?
            .data;
        let original = req.original_request().or_else(|| {
            better_auth_core::hooks::current_request_hook_context()
                .is_some_and(|context| context.is_http)
                .then_some(req)
        });
        let client = req.endpoint_headers().is_some() || original.is_some();
        if client {
            validate_client_create(&body)?;
        }
        if original.is_some() && body.user_id.is_some() {
            return Err(api_key_error(ApiKeyErrorCode::UnauthorizedSession));
        }
        let actor = session
            .as_ref()
            .and_then(|data| data.user.id.as_str())
            .or_else(|| {
                (!client || config.references == ApiKeyReferences::Organization)
                    .then_some(body.user_id.as_deref())
                    .flatten()
            })
            .filter(|id| !id.is_empty());
        if config.references == ApiKeyReferences::User
            && !client
            && session.is_some()
            && body
                .user_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .is_some_and(|id| Some(id) != actor)
        {
            return Err(api_key_error(ApiKeyErrorCode::UnauthorizedSession));
        }
        // Organization selection precedes the actor check in the upstream handler.
        if config.references == ApiKeyReferences::Organization
            && body.organization_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(api_key_error(ApiKeyErrorCode::OrganizationIdRequired));
        }
        let actor = actor.ok_or_else(|| api_key_error(ApiKeyErrorCode::UnauthorizedSession))?;
        let response = create_key_for_user(&body, actor, self, ctx, original).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_get(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let id = req
            .query_string("id")?
            .ok_or_else(|| AuthError::bad_request("Query parameter 'id' is required"))?;
        let config_id = req.query_string("configId")?;
        let response = get_key_core(id, config_id, user.id().typed()?, self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_list(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let query = ListKeysQuery::from_request(req)?;
        let response = list_keys_core(user.id().typed()?, &query, self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_update(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UpdateKeyRequest = request::read(req)?;
        let session = ctx
            .session_manager()
            .resolve(req, better_auth_core::session::SessionRead::Authoritative)
            .await?
            .data;
        let client = req.endpoint_headers().is_some()
            || req.original_request().is_some()
            || better_auth_core::hooks::current_request_hook_context()
                .is_some_and(|context| context.is_http);
        let actor = session
            .as_ref()
            .and_then(|data| data.user.id.as_str())
            .or_else(|| (!client).then_some(body.user_id.as_deref()).flatten())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| api_key_error(ApiKeyErrorCode::UnauthorizedSession))?;
        if session.is_some()
            && body
                .user_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .is_some_and(|id| id != actor)
        {
            return Err(api_key_error(ApiKeyErrorCode::UnauthorizedSession));
        }
        let response = if client {
            update_key_core(&body, actor, self, ctx).await?
        } else {
            update_key_for_user(&body, actor, self, ctx).await?
        };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_delete(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: DeleteKeyRequest = request::read(req)?;
        let (user, _session) = ctx.require_session(req).await?;
        if user.banned() {
            return Err(AuthError::authentication_failed("User is banned"));
        }
        let response = delete_key_core(&body, user.id().typed()?, self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

// ---------------------------------------------------------------------------
// AuthPlugin trait implementation
// ---------------------------------------------------------------------------

better_auth_core::impl_auth_plugin! {
    ApiKeyPlugin, "api-key";
    routes {
        post "/api-key/create"                    => handle_create,             "createApiKey", body = request::validate;
        get  "/api-key/get"                       => handle_get,                "getApiKey", query = crate::plugins::query_input::api_key_get;
        post "/api-key/update"                    => handle_update,             "updateApiKey", body = request::validate;
        post "/api-key/delete"                    => handle_delete,             "deleteApiKey", body = request::validate;
        get  "/api-key/list"                      => handle_list,               "listApiKeys", query = crate::plugins::query_input::api_key_list;
    }
    extra {
        fn openapi(&self) -> AuthResult<better_auth_core::openapi::OpenApiPluginMetadata> {
            let mut metadata = better_auth_core::openapi::OpenApiPluginMetadata::from_routes(
                <Self as better_auth_core::AuthPlugin<S>>::name(self),
                <Self as better_auth_core::AuthPlugin<S>>::routes(self),
            )?;
            if let [config] = self.configurations.as_slice() {
                metadata = metadata
                    .model_default("apikey", "rateLimitMax", serde_json::json!(config.rate_limit.max_requests))?
                    .model_default("apikey", "rateLimitTimeWindow", serde_json::json!(config.rate_limit.time_window))?;
            }
            Ok(metadata)
        }

        async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
            if self.configurations.len() > 1 {
                let mut ids = std::collections::HashSet::new();
                for config in &self.configurations {
                    if config.config_id.is_empty() {
                        return Err(AuthError::config("configId is required for each API key configuration in the api-key plugin."));
                    }
                    if !ids.insert(&config.config_id) {
                        return Err(AuthError::config("configId must be unique for each API key configuration in the api-key plugin."));
                    }
                }
            }
            let mut fields = better_auth_core::plugin_runtime::ModelFields::plugin_native_fields(
                better_auth_core::store::schema::EntityRole::ApiKey,
            );
            if let [config] = self.configurations.as_slice() {
                for (name, value) in [
                    ("rateLimitMax", config.rate_limit.max_requests),
                    ("rateLimitTimeWindow", config.rate_limit.time_window),
                ] {
                    if let Some(field) = fields.fields_mut().get_mut(name) {
                        field.default_value = Some(value.into());
                    }
                }
            }
            ctx.register_model_fields(better_auth_core::store::schema::EntityRole::ApiKey, fields)?;
            Ok(())
        }

        async fn before_request(
            &self,
            req: &AuthRequest,
            ctx: &AuthContext<S>,
        ) -> AuthResult<Option<BeforeRequestAction>> {
            self.api_key_session(req, ctx).await
        }
    }
}
