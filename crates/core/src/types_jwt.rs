//! Persisted signing keys for the JWT plugin.

use chrono::{DateTime, Utc};

/// A persisted signing key. Private key material must never enter an HTTP response.
#[derive(Clone, PartialEq)]
pub struct Jwk {
    /// Stable identifier used by the JWT `kid` header.
    pub id: String,
    /// Serialized public JWK.
    pub public_key: String,
    /// Serialized private JWK, encrypted unless explicitly configured otherwise.
    pub private_key: String,
    /// Creation time used to select the newest live key.
    pub created_at: DateTime<Utc>,
    /// Time after which this key stops signing new tokens.
    pub expires_at: Option<DateTime<Utc>>,
    /// Signing algorithm; absent on legacy rows.
    pub alg: Option<String>,
    /// Elliptic curve identifier, when applicable.
    pub crv: Option<String>,
}

/// Key material to persist after generation.
pub struct CreateJwk {
    /// Serialized public JWK.
    pub public_key: String,
    /// Serialized or encrypted private JWK.
    pub private_key: String,
    /// Signing expiration time.
    pub expires_at: Option<DateTime<Utc>>,
    /// Signing algorithm.
    pub alg: String,
    /// Elliptic curve identifier, when applicable.
    pub crv: Option<String>,
}
