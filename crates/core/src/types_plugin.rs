use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::entity::{AuthApiKey, AuthPasskey, AuthTwoFactor};

/// Two-factor authentication response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub id: String,
    pub secret: String,
    #[serde(rename = "backupCodes")]
    pub backup_codes: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Two-factor authentication creation data.
#[derive(Debug, Clone)]
pub struct CreateTwoFactor {
    pub user_id: String,
    pub secret: String,
    pub backup_codes: String,
}

/// Passkey response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub credential: String,
}

/// Input for creating a new passkey.
#[derive(Debug, Clone)]
pub struct CreatePasskey {
    pub user_id: String,
    pub name: Option<String>,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub credential: String,
    pub aaguid: Option<String>,
}

/// Input for updating a passkey.
#[derive(Debug, Clone)]
pub struct UpdatePasskey {
    pub name: Option<String>,
}

/// Input for updating stored passkey credential state after authentication.
#[derive(Debug, Clone)]
pub struct UpdatePasskeyAuthentication {
    pub credential: String,
    pub counter: u64,
    pub backed_up: bool,
    pub device_type: String,
}

/// Device authorization code storage shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCode {
    pub id: String,
    #[serde(rename = "deviceCode")]
    pub device_code: String,
    #[serde(rename = "userCode")]
    pub user_code: String,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub status: String,
    #[serde(rename = "lastPolledAt", skip_serializing_if = "Option::is_none")]
    pub last_polled_at: Option<DateTime<Utc>>,
    #[serde(rename = "pollingInterval", skip_serializing_if = "Option::is_none")]
    pub polling_interval: Option<i64>,
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Input for creating a new device authorization code.
#[derive(Debug, Clone)]
pub struct CreateDeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub polling_interval: Option<i64>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

/// Input for updating an existing device authorization code.
#[derive(Debug, Clone, Default)]
pub struct UpdateDeviceCode {
    /// Update the status. `None` leaves it unchanged.
    pub status: Option<String>,
    /// Update the approving/denying user. `Some(None)` clears it, `None` leaves
    /// it unchanged.
    pub user_id: Option<Option<String>>,
    /// Update the last poll timestamp. `Some(None)` clears it, `None` leaves it
    /// unchanged.
    pub last_polled_at: Option<Option<DateTime<Utc>>>,
}

/// API key response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    /// SHA-256 hash of the key (column name: `key` in SQL)
    #[serde(rename = "key")]
    pub key_hash: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<i64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<i64>,
    #[serde(rename = "requestCount")]
    pub request_count: Option<i64>,
    pub remaining: Option<i64>,
    #[serde(rename = "lastRequest")]
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

/// API key creation data.
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    pub user_id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub key_hash: String,
    pub start: Option<String>,
    pub expires_at: Option<String>,
    pub remaining: Option<i64>,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    pub enabled: bool,
}

/// API key update data.
#[derive(Debug, Clone, Default)]
pub struct UpdateApiKey {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    /// Update the expiration time. `Some(Some("..."))` sets a new value,
    /// `Some(None)` clears it, `None` leaves it unchanged.
    pub expires_at: Option<Option<String>>,
    /// Last request timestamp (updated during verify).
    pub last_request: Option<Option<String>>,
    /// Request count within the current rate-limit window.
    pub request_count: Option<i64>,
    /// Last refill timestamp (updated during verify).
    pub last_refill_at: Option<Option<String>>,
}

impl AuthTwoFactor for TwoFactor {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn secret(&self) -> &str {
        &self.secret
    }
    fn backup_codes(&self) -> &str {
        &self.backup_codes
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl<T: AuthTwoFactor> From<&T> for TwoFactor {
    fn from(two_factor: &T) -> Self {
        Self {
            id: two_factor.id().into_owned(),
            secret: two_factor.secret().to_owned(),
            backup_codes: two_factor.backup_codes().to_owned(),
            user_id: two_factor.user_id().into_owned(),
            created_at: two_factor.created_at(),
            updated_at: two_factor.updated_at(),
        }
    }
}

impl AuthApiKey for ApiKey {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn start(&self) -> Option<&str> {
        self.start.as_deref()
    }
    fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    fn key_hash(&self) -> &str {
        &self.key_hash
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn refill_interval(&self) -> Option<i64> {
        self.refill_interval
    }
    fn refill_amount(&self) -> Option<i64> {
        self.refill_amount
    }
    fn last_refill_at(&self) -> Option<&str> {
        self.last_refill_at.as_deref()
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn rate_limit_enabled(&self) -> bool {
        self.rate_limit_enabled
    }
    fn rate_limit_time_window(&self) -> Option<i64> {
        self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> Option<i64> {
        self.rate_limit_max
    }
    fn request_count(&self) -> Option<i64> {
        self.request_count
    }
    fn remaining(&self) -> Option<i64> {
        self.remaining
    }
    fn last_request(&self) -> Option<&str> {
        self.last_request.as_deref()
    }
    fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
    fn created_at(&self) -> &str {
        &self.created_at
    }
    fn updated_at(&self) -> &str {
        &self.updated_at
    }
    fn permissions(&self) -> Option<&str> {
        self.permissions.as_deref()
    }
    fn metadata(&self) -> Option<&str> {
        self.metadata.as_deref()
    }
}

impl<T: AuthApiKey> From<&T> for ApiKey {
    fn from(api_key: &T) -> Self {
        Self {
            id: api_key.id().into_owned(),
            name: api_key.name().map(str::to_owned),
            start: api_key.start().map(str::to_owned),
            prefix: api_key.prefix().map(str::to_owned),
            key_hash: api_key.key_hash().to_owned(),
            user_id: api_key.user_id().into_owned(),
            refill_interval: api_key.refill_interval(),
            refill_amount: api_key.refill_amount(),
            last_refill_at: api_key.last_refill_at().map(str::to_owned),
            enabled: api_key.enabled(),
            rate_limit_enabled: api_key.rate_limit_enabled(),
            rate_limit_time_window: api_key.rate_limit_time_window(),
            rate_limit_max: api_key.rate_limit_max(),
            request_count: api_key.request_count(),
            remaining: api_key.remaining(),
            last_request: api_key.last_request().map(str::to_owned),
            expires_at: api_key.expires_at().map(str::to_owned),
            created_at: api_key.created_at().to_owned(),
            updated_at: api_key.updated_at().to_owned(),
            permissions: api_key.permissions().map(str::to_owned),
            metadata: api_key.metadata().map(str::to_owned),
        }
    }
}

impl AuthPasskey for Passkey {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn public_key(&self) -> &str {
        &self.public_key
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn credential_id(&self) -> &str {
        &self.credential_id
    }
    fn counter(&self) -> u64 {
        self.counter
    }
    fn device_type(&self) -> &str {
        &self.device_type
    }
    fn backed_up(&self) -> bool {
        self.backed_up
    }
    fn transports(&self) -> Option<&str> {
        self.transports.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn aaguid(&self) -> Option<&str> {
        self.aaguid.as_deref()
    }
    fn credential(&self) -> &str {
        &self.credential
    }
}

impl<T: AuthPasskey> From<&T> for Passkey {
    fn from(passkey: &T) -> Self {
        Self {
            id: passkey.id().into_owned(),
            name: passkey.name().map(str::to_owned),
            public_key: passkey.public_key().to_owned(),
            user_id: passkey.user_id().into_owned(),
            credential_id: passkey.credential_id().to_owned(),
            counter: passkey.counter(),
            device_type: passkey.device_type().to_owned(),
            backed_up: passkey.backed_up(),
            transports: passkey.transports().map(str::to_owned),
            created_at: passkey.created_at(),
            updated_at: passkey.updated_at(),
            aaguid: passkey.aaguid().map(str::to_owned),
            credential: passkey.credential().to_owned(),
        }
    }
}
