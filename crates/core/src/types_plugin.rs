use crate::SchemaValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::entity::{AuthApiKey, AuthPasskey, AuthTwoFactor};

pub(crate) fn deserialize_display_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SchemaValue<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(SchemaValue::Typed)
}

/// Two-factor authentication response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TwoFactor {
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    pub secret: String,
    #[serde(rename = "backupCodes")]
    pub backup_codes: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    /// Whether the authenticator secret has completed enrollment.
    pub verified: Option<bool>,
    /// Consecutive failed sign-in verifications across factors and challenges.
    #[serde(rename = "failedVerificationCount")]
    pub failed_verification_count: Option<i64>,
    /// End of the account-level verification lock.
    #[serde(rename = "lockedUntil")]
    #[serde(serialize_with = "crate::utils::date::serialize_option")]
    pub locked_until: Option<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    pub created_at: SchemaValue<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    pub updated_at: SchemaValue<DateTime<Utc>>,
    /// Declared application fields after adapter output projection.
    #[serde(flatten, default)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// Two-factor persistence representation selected by the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorStorage {
    /// Store the upstream columns without creation or update timestamps.
    Native,
    /// Preserve the legacy creation and update timestamps.
    Legacy,
}

/// Two-factor authentication creation data.
#[derive(Debug, Clone)]
pub struct CreateTwoFactor {
    /// Declared application fields before adapter input policies.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub user_id: String,
    pub secret: String,
    pub backup_codes: String,
    /// Whether enrollment verification may be skipped.
    pub verified: bool,
}

/// Fields changed when an existing authenticator enrollment is completed or replaced.
#[derive(Debug, Default)]
pub struct UpdateTwoFactor {
    /// Declared application fields to update; omitted keys retain their stored values.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    /// Replacement encrypted authenticator secret.
    pub secret: Option<String>,
    /// Replacement encrypted backup codes.
    pub backup_codes: Option<String>,
    /// Enrollment verification state.
    pub verified: Option<bool>,
}

/// Passkey persistence representation selected by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyStorage {
    /// Store the upstream standard columns without an opaque credential envelope.
    Native,
    /// Preserve the opaque credential envelope and the legacy update timestamp.
    Legacy,
}

/// Credential state supplied when creating a passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyCredentialState {
    /// The standard columns contain the credential state.
    Native,
    /// Preserve these opaque bytes in the legacy credential column.
    Legacy(String),
}

impl From<String> for PasskeyCredentialState {
    fn from(value: String) -> Self {
        Self::Legacy(value)
    }
}

impl From<&str> for PasskeyCredentialState {
    fn from(value: &str) -> Self {
        Self::Legacy(value.to_owned())
    }
}

/// Passkey response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Passkey {
    /// Declared application fields after adapter output projection.
    #[serde(flatten, default)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "deserialize_display_string")]
    pub name: SchemaValue<Option<String>>,
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
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(serialize_with = "crate::schema_value::serialize_optional_date")]
    pub created_at: SchemaValue<Option<DateTime<Utc>>>,
    #[serde(rename = "updatedAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    pub updated_at: SchemaValue<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "deserialize_display_string")]
    pub aaguid: SchemaValue<Option<String>>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub credential: SchemaValue<String>,
}

/// Input for creating a new passkey.
#[derive(Debug, Clone)]
pub struct CreatePasskey {
    /// Declared application fields before adapter input policies.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub user_id: String,
    /// Omission and explicit null remain distinct during field input transforms.
    pub name: SchemaValue<Option<String>>,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub credential: PasskeyCredentialState,
    /// Omission and explicit null remain distinct during field input transforms.
    pub aaguid: SchemaValue<Option<String>>,
}

/// Input for updating a passkey.
#[derive(Debug, Clone)]
pub struct UpdatePasskey {
    pub name: Option<String>,
}

/// Input for updating stored passkey credential state after authentication.
#[derive(Debug, Clone)]
pub enum UpdatePasskeyAuthentication {
    /// Update only the counter in an upstream standard record.
    Native { counter: u64 },
    /// Preserve the legacy opaque credential and metadata update contract.
    Legacy {
        credential: String,
        counter: u64,
        backed_up: bool,
        device_type: String,
    },
}

/// Device authorization code storage shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceCode {
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(rename = "deviceCode")]
    pub device_code: String,
    #[serde(rename = "userCode")]
    pub user_code: String,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub expires_at: DateTime<Utc>,
    pub status: String,
    #[serde(rename = "lastPolledAt")]
    #[serde(serialize_with = "crate::utils::date::serialize_option")]
    pub last_polled_at: Option<DateTime<Utc>>,
    #[serde(rename = "pollingInterval", skip_serializing_if = "Option::is_none")]
    pub polling_interval: Option<f64>,
    #[serde(
        default,
        rename = "clientId",
        skip_serializing_if = "crate::SchemaValue::is_undefined"
    )]
    pub client_id: crate::SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub scope: crate::SchemaValue<Option<String>>,
    /// Declared application fields after adapter output projection.
    #[serde(flatten, default)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// Issuer ownership required by atomic device-code consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCodeOwnership {
    /// Require the stored client binding to equal this client identifier.
    ClientId(String),
    /// Match native `scope` or a declared string, number, or boolean field without a reference.
    /// This condition uses `eq`, `AND`, and case-sensitive comparison.
    /// Other operators, connectors, and field types are not supported.
    FieldEquals {
        /// Native `scope`, a registered logical field name, or a configured storage field name.
        field: String,
        /// Scalar null, string, number, or boolean query value.
        value: serde_json::Value,
    },
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
    pub polling_interval: Option<f64>,
    pub client_id: Option<String>,
    /// Omit with `Undefined`, clear with `Typed(None)`, or supply a string.
    pub scope: crate::SchemaValue<Option<String>>,
    /// Declared application fields before adapter input policies.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// Input for updating an existing device authorization code.
#[derive(Debug, Clone, Default)]
pub struct UpdateDeviceCode {
    /// Declared application fields to update; omitted keys retain their stored values.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    /// Omit with `Undefined`; supplied null and string values pass through field policies.
    pub scope: crate::SchemaValue<Option<String>>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKey {
    /// Declared application fields after adapter output projection.
    #[serde(flatten, default)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "deserialize_display_string")]
    pub name: SchemaValue<Option<String>>,
    pub start: Option<crate::ApiKeyStart>,
    pub prefix: Option<String>,
    /// SHA-256 hash of the key (column name: `key` in SQL)
    #[serde(rename = "key")]
    pub key_hash: String,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "configId")]
    pub config_id: String,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<f64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<f64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<f64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<f64>,
    #[serde(rename = "requestCount")]
    pub request_count: Option<f64>,
    pub remaining: Option<f64>,
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
    /// Declared application fields before adapter input policies.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    /// Owner of the key — a user id, or an organization id when the key's
    /// configuration references organizations.
    pub reference_id: String,
    /// Name of the API-key configuration this key belongs to.
    pub config_id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub key_hash: String,
    pub start: Option<crate::ApiKeyStart>,
    pub expires_at: Option<String>,
    pub remaining: Option<f64>,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    pub enabled: bool,
}

/// API key update data.
#[derive(Debug, Clone, Default)]
pub struct UpdateApiKey {
    /// Declared application field patch before adapter input policies.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<f64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    /// Update the expiration time. `Some(Some("..."))` sets a new value,
    /// `Some(None)` clears it, `None` leaves it unchanged.
    pub expires_at: Option<Option<String>>,
    /// Last request timestamp (updated during verify).
    pub last_request: Option<Option<String>>,
    /// Request count within the current rate-limit window.
    pub request_count: Option<f64>,
    /// Last refill timestamp (updated during verify).
    pub last_refill_at: Option<Option<String>>,
}

impl AuthTwoFactor for TwoFactor {
    fn additional_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        Some(&self.additional_fields)
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
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
    fn verified(&self) -> Option<bool> {
        self.verified
    }
    fn failed_verification_count(&self) -> Option<i64> {
        self.failed_verification_count
    }
    fn locked_until(&self) -> Option<DateTime<Utc>> {
        self.locked_until
    }
    fn created_at(&self) -> &SchemaValue<DateTime<Utc>> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<DateTime<Utc>> {
        &self.updated_at
    }
}

impl<T: AuthTwoFactor> From<&T> for TwoFactor {
    fn from(two_factor: &T) -> Self {
        Self {
            additional_fields: two_factor.additional_fields().cloned().unwrap_or_default(),
            id: two_factor.id().into_owned(),
            secret: two_factor.secret().to_owned(),
            backup_codes: two_factor.backup_codes().to_owned(),
            user_id: two_factor.user_id().into_owned(),
            verified: two_factor.verified(),
            failed_verification_count: two_factor.failed_verification_count(),
            locked_until: two_factor.locked_until(),
            created_at: two_factor.created_at().clone(),
            updated_at: two_factor.updated_at().clone(),
        }
    }
}

impl AuthApiKey for ApiKey {
    fn additional_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        Some(&self.additional_fields)
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn name(&self) -> &SchemaValue<Option<String>> {
        &self.name
    }
    fn start(&self) -> Option<Cow<'_, crate::ApiKeyStart>> {
        self.start.as_ref().map(Cow::Borrowed)
    }
    fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    fn key_hash(&self) -> &str {
        &self.key_hash
    }
    fn reference_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.reference_id)
    }
    fn config_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.config_id)
    }
    fn refill_interval(&self) -> Option<f64> {
        self.refill_interval
    }
    fn refill_amount(&self) -> Option<f64> {
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
    fn rate_limit_time_window(&self) -> Option<f64> {
        self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> Option<f64> {
        self.rate_limit_max
    }
    fn request_count(&self) -> Option<f64> {
        self.request_count
    }
    fn remaining(&self) -> Option<f64> {
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
            additional_fields: api_key.additional_fields().cloned().unwrap_or_default(),
            id: api_key.id().into_owned(),
            name: api_key.name().clone(),
            start: api_key.start().map(Cow::into_owned),
            prefix: api_key.prefix().map(str::to_owned),
            key_hash: api_key.key_hash().to_owned(),
            reference_id: api_key.reference_id().into_owned(),
            config_id: api_key.config_id().into_owned(),
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
    fn additional_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        Some(&self.additional_fields)
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn name(&self) -> &SchemaValue<Option<String>> {
        &self.name
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
    fn created_at(&self) -> &SchemaValue<Option<DateTime<Utc>>> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<DateTime<Utc>> {
        &self.updated_at
    }
    fn aaguid(&self) -> &SchemaValue<Option<String>> {
        &self.aaguid
    }
    fn credential(&self) -> &SchemaValue<String> {
        &self.credential
    }
}

impl<T: AuthPasskey> From<&T> for Passkey {
    fn from(passkey: &T) -> Self {
        Self {
            additional_fields: passkey.additional_fields().cloned().unwrap_or_default(),
            id: passkey.id().into_owned(),
            name: passkey.name().clone(),
            public_key: passkey.public_key().to_owned(),
            user_id: passkey.user_id().into_owned(),
            credential_id: passkey.credential_id().to_owned(),
            counter: passkey.counter(),
            device_type: passkey.device_type().to_owned(),
            backed_up: passkey.backed_up(),
            transports: passkey.transports().map(str::to_owned),
            created_at: passkey.created_at().clone(),
            updated_at: passkey.updated_at().clone(),
            aaguid: passkey.aaguid().clone(),
            credential: passkey.credential().to_owned(),
        }
    }
}

/// Persisted SIWE wallet identity. Multiple chains can belong to one user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletAddress {
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    pub user_id: String,
    pub address: String,
    pub chain_id: i64,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    /// Declared application fields returned by the adapter.
    #[serde(default, flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// SIWE wallet creation data. The adapter generates the model ID.
#[derive(Debug, Clone)]
pub struct CreateWalletAddress {
    pub user_id: String,
    pub address: String,
    pub chain_id: i64,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    /// Logical application fields consumed by registered adapter policies.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}
