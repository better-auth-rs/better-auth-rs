//! Persisted signing keys for the JWT plugin.

use crate::SchemaValue;

/// A persisted signing key. Private key material must never enter an HTTP response.
#[derive(Clone, PartialEq)]
pub struct Jwk {
    /// Stable identifier used by the JWT `kid` header.
    pub id: SchemaValue<String>,
    /// Serialized public JWK.
    pub public_key: String,
    /// Serialized private JWK, encrypted unless explicitly configured otherwise.
    pub private_key: String,
    /// Creation time used to select the newest live key.
    pub created_at: crate::FieldDate,
    /// Time after which this key stops signing new tokens.
    pub expires_at: Option<crate::FieldDate>,
    /// Signing algorithm; absent on legacy rows.
    pub alg: Option<String>,
    /// Elliptic curve identifier, when applicable.
    pub crv: Option<String>,
    /// Declared application fields returned by the adapter; excluded from public JWKS discovery.
    pub additional_fields: crate::FieldMap,
}

/// Key material to persist after generation.
pub struct CreateJwk {
    /// Generation time supplied to a custom key-persistence callback.
    #[serde(with = "crate::field_value::serde::date")]
    pub created_at: crate::FieldDate,
    /// Serialized public JWK.
    pub public_key: String,
    /// Serialized or encrypted private JWK.
    pub private_key: String,
    /// Signing expiration time.
    #[serde(with = "crate::field_value::serde::optional_date", default)]
    pub expires_at: Option<crate::FieldDate>,
    /// Signing algorithm.
    pub alg: String,
    /// Elliptic curve identifier, when applicable.
    pub crv: Option<String>,
    /// Logical application fields consumed by registered adapter policies.
    pub additional_fields: crate::FieldMap,
}
