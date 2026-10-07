use crate::SchemaValue;
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
    #[serde(default, with = "crate::field_value::serde::optional_date")]
    pub locked_until: Option<crate::FieldDate>,
    #[serde(rename = "createdAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    pub created_at: SchemaValue<crate::FieldDate>,
    #[serde(rename = "updatedAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    pub updated_at: SchemaValue<crate::FieldDate>,
    /// Declared application fields after adapter output projection.
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: crate::FieldMap,
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
    pub additional_fields: crate::FieldMap,
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
    pub additional_fields: crate::FieldMap,
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
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: crate::FieldMap,
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
    #[serde(with = "crate::field_value::serde::optional_schema_date")]
    pub created_at: SchemaValue<Option<crate::FieldDate>>,
    #[serde(rename = "updatedAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    pub updated_at: SchemaValue<crate::FieldDate>,
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
    pub additional_fields: crate::FieldMap,
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
    #[serde(with = "crate::field_value::serde::date")]
    pub expires_at: crate::FieldDate,
    pub status: String,
    #[serde(rename = "lastPolledAt")]
    #[serde(default, with = "crate::field_value::serde::optional_date")]
    pub last_polled_at: Option<crate::FieldDate>,
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
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: crate::FieldMap,
}

/// Issuer ownership required by atomic device-code consumption.
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceCodeOwnership {
    /// Require the stored client binding to equal this client identifier.
    ClientId(String),
    /// Match native `scope` or a declared string, number, or boolean field without a reference.
    /// This condition uses `eq`, `AND`, and case-sensitive comparison.
    /// Other connectors and field types are not supported by this variant.
    FieldEquals {
        /// Native `scope`, a registered logical field name, or a configured storage field name.
        field: String,
        /// Scalar null, string, number, or boolean query value.
        value: crate::FieldValue,
    },
    /// Require membership in a candidate set with `AND` and case-sensitive comparison.
    FieldIn {
        /// Native `scope`, or a registered string or number field without a reference.
        /// Configured storage field names are accepted.
        field: String,
        /// Null, string, or number candidates. An empty set never matches.
        values: Vec<crate::FieldValue>,
    },
    /// Exclude a candidate set with `AND` and the selected adapter's null semantics.
    FieldNotIn {
        /// Native `scope`, or a registered string or number field without a reference.
        /// Configured storage field names are accepted.
        field: String,
        /// Null, string, or number candidates. An empty set matches every bound row.
        values: Vec<crate::FieldValue>,
    },
    /// Apply a typed `AND` condition while retaining the selected code and owner bindings.
    Where(DeviceCodeWhere),
}

/// A DeviceCode ownership condition over scope or a declared field.
/// String fields that reference `id` support Serial ID generation.
/// Other references require their adapter-specific query binding.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCodeWhere {
    /// Native `scope`, a registered logical field name, or a configured storage field name.
    pub field: String,
    /// Comparison operator. The default is equality.
    pub operator: WhereOperator,
    /// Native operand, retaining Date and array identity and non-finite numbers.
    /// The selected adapter determines comparison, conversion, and binding errors.
    pub value: crate::FieldValue,
    /// String comparison mode. Range comparisons ignore this setting.
    pub mode: WhereMode,
}

impl DeviceCodeWhere {
    /// Construct a case-sensitive equality condition.
    pub fn new(field: impl Into<String>, value: impl Into<crate::FieldValue>) -> Self {
        Self {
            field: field.into(),
            operator: WhereOperator::Eq,
            value: value.into(),
            mode: WhereMode::Sensitive,
        }
    }
}

/// Operators accepted by the upstream adapter's Where condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhereOperator {
    /// Equal to the query value.
    #[default]
    Eq,
    /// Not equal to the query value.
    Ne,
    /// Less than the query value.
    Lt,
    /// Less than or equal to the query value.
    Lte,
    /// Greater than the query value.
    Gt,
    /// Greater than or equal to the query value.
    Gte,
    /// Included in the query candidates.
    In,
    /// Excluded from the query candidates.
    NotIn,
    /// Contain the query value with the selected adapter's pattern semantics.
    Contains,
    /// Start with the query value with the selected adapter's pattern semantics.
    StartsWith,
    /// End with the query value with the selected adapter's pattern semantics.
    EndsWith,
}

/// Case handling for string equality, membership, and pattern comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhereMode {
    /// Retain the selected adapter's ordinary comparison behavior.
    #[default]
    Sensitive,
    /// Use the selected adapter's case-insensitive string comparison behavior.
    Insensitive,
}

/// Input for creating a new device authorization code.
#[derive(Debug, Clone)]
pub struct CreateDeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: crate::FieldDate,
    pub status: String,
    pub last_polled_at: Option<crate::FieldDate>,
    pub polling_interval: Option<f64>,
    pub client_id: Option<String>,
    /// Omit with `Undefined`, clear with `Typed(None)`, or supply a string.
    pub scope: crate::SchemaValue<Option<String>>,
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
}

/// Input for updating an existing device authorization code.
#[derive(Debug, Clone, Default)]
pub struct UpdateDeviceCode {
    /// Declared application fields to update; omitted keys retain their stored values.
    pub additional_fields: crate::FieldMap,
    /// Omit with `Undefined`; supplied null and string values pass through field policies.
    pub scope: crate::SchemaValue<Option<String>>,
    /// Update the status. `None` leaves it unchanged.
    pub status: Option<String>,
    /// Update the approving/denying user. `Some(None)` clears it, `None` leaves
    /// it unchanged.
    pub user_id: Option<Option<String>>,
    /// Update the last poll timestamp. `Some(None)` clears it, `None` leaves it
    /// unchanged.
    pub last_polled_at: Option<Option<crate::FieldDate>>,
}

/// API key response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKey {
    /// Declared application fields after adapter output projection.
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: crate::FieldMap,
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
    #[serde(with = "crate::field_value::serde::optional_date", default)]
    pub last_refill_at: Option<crate::FieldDate>,
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
    #[serde(with = "crate::field_value::serde::optional_date", default)]
    pub last_request: Option<crate::FieldDate>,
    #[serde(rename = "expiresAt")]
    #[serde(with = "crate::field_value::serde::optional_date", default)]
    pub expires_at: Option<crate::FieldDate>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::date")]
    pub created_at: crate::FieldDate,
    #[serde(rename = "updatedAt")]
    #[serde(with = "crate::field_value::serde::date")]
    pub updated_at: crate::FieldDate,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

/// API key creation data.
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
    /// Owner of the key — a user id, or an organization id when the key's
    /// configuration references organizations.
    pub reference_id: String,
    /// Name of the API-key configuration this key belongs to.
    pub config_id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub key_hash: String,
    pub start: Option<crate::ApiKeyStart>,
    pub expires_at: Option<crate::FieldDate>,
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
    pub additional_fields: crate::FieldMap,
    pub name: Option<SchemaValue<Option<String>>>,
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
    pub expires_at: Option<Option<crate::FieldDate>>,
    /// Last request timestamp (updated during verify).
    pub last_request: Option<Option<crate::FieldDate>>,
    /// Request count within the current rate-limit window.
    pub request_count: Option<f64>,
    /// Last refill timestamp (updated during verify).
    pub last_refill_at: Option<Option<crate::FieldDate>>,
}

impl AuthTwoFactor for TwoFactor {
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
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
    fn locked_until(&self) -> Option<crate::FieldDate> {
        self.locked_until.clone()
    }
    fn created_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate> {
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
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
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
    fn last_refill_at(&self) -> Option<crate::FieldDate> {
        self.last_refill_at.clone()
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
    fn last_request(&self) -> Option<crate::FieldDate> {
        self.last_request.clone()
    }
    fn expires_at(&self) -> Option<crate::FieldDate> {
        self.expires_at.clone()
    }
    fn created_at(&self) -> crate::FieldDate {
        self.created_at.clone()
    }
    fn updated_at(&self) -> crate::FieldDate {
        self.updated_at.clone()
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
            last_refill_at: api_key.last_refill_at(),
            enabled: api_key.enabled(),
            rate_limit_enabled: api_key.rate_limit_enabled(),
            rate_limit_time_window: api_key.rate_limit_time_window(),
            rate_limit_max: api_key.rate_limit_max(),
            request_count: api_key.request_count(),
            remaining: api_key.remaining(),
            last_request: api_key.last_request(),
            expires_at: api_key.expires_at(),
            created_at: api_key.created_at().to_owned(),
            updated_at: api_key.updated_at().to_owned(),
            permissions: api_key.permissions().map(str::to_owned),
            metadata: api_key.metadata().map(str::to_owned),
        }
    }
}

impl AuthPasskey for Passkey {
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
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
    fn created_at(&self) -> &SchemaValue<Option<crate::FieldDate>> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate> {
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
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub user_id: SchemaValue<String>,
    pub address: String,
    pub chain_id: i64,
    pub is_primary: bool,
    #[serde(with = "crate::field_value::serde::date")]
    pub created_at: crate::FieldDate,
    /// Declared application fields returned by the adapter.
    #[serde(with = "crate::field_value::serde::map", default, flatten)]
    pub additional_fields: crate::FieldMap,
}

/// SIWE wallet creation data. The adapter generates the model ID.
#[derive(Debug, Clone)]
pub struct CreateWalletAddress {
    pub user_id: String,
    pub address: String,
    pub chain_id: i64,
    pub is_primary: bool,
    pub created_at: crate::FieldDate,
    /// Logical application fields consumed by registered adapter policies.
    pub additional_fields: crate::FieldMap,
}
