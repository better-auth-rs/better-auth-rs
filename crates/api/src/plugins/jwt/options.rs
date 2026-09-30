use super::*;
use std::{future::Future, pin::Pin, sync::Arc};

/// Expected token recipients, preserving the string or array claim representation.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(untagged)]
pub enum JwtAudience {
    /// One recipient encoded as a string.
    Single(String),
    /// Recipients encoded as an array, including an explicit empty array.
    Multiple(Vec<String>),
}

impl From<String> for JwtAudience {
    fn from(value: String) -> Self {
        Self::Single(value)
    }
}

impl From<&str> for JwtAudience {
    fn from(value: &str) -> Self {
        Self::Single(value.into())
    }
}

impl From<Vec<String>> for JwtAudience {
    fn from(value: Vec<String>) -> Self {
        Self::Multiple(value)
    }
}

impl JwtAudience {
    pub(super) fn recipients(&self) -> Vec<&str> {
        match self {
            Self::Single(value) => vec![value],
            Self::Multiple(values) => values.iter().map(String::as_str).collect(),
        }
    }
}

/// Default expiration when a payload does not supply its own `exp` claim.
#[derive(Clone, Debug)]
pub enum JwtExpiration {
    /// Lifetime relative to the payload's issue time, or the current time when omitted.
    After(Duration),
    /// Absolute NumericDate in seconds. Fractional values remain observable.
    At(serde_json::Number),
}

impl From<Duration> for JwtExpiration {
    fn from(value: Duration) -> Self {
        Self::After(value)
    }
}

impl From<chrono::DateTime<Utc>> for JwtExpiration {
    fn from(value: chrono::DateTime<Utc>) -> Self {
        Self::At(value.timestamp().into())
    }
}

impl From<i64> for JwtExpiration {
    fn from(value: i64) -> Self {
        Self::At(value.into())
    }
}

impl JwtExpiration {
    pub(super) fn claim(&self, issued: f64) -> Value {
        match self {
            Self::At(value) => Value::Number(value.clone()),
            Self::After(duration) => {
                let seconds =
                    duration.num_seconds() as f64 + f64::from(duration.subsec_nanos()) / 1e9;
                let expires = issued + (seconds + 0.5).floor();
                // Preserve integer NumericDates for typed JWT consumers, as JSON.stringify does.
                if expires.fract() == 0.0
                    && (i64::MIN as f64..-(i64::MIN as f64)).contains(&expires)
                {
                    Value::from(expires as i64)
                } else {
                    Value::from(expires)
                }
            }
        }
    }
}

/// An asynchronous application callback result.
pub type JwtCallbackFuture<T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send>>;
/// Define claims from the complete authenticated session and user object.
pub type JwtDefinePayload =
    Arc<dyn Fn(Value) -> JwtCallbackFuture<Map<String, Value>> + Send + Sync>;
/// Select a subject from the complete authenticated session and user object.
pub type JwtGetSubject = Arc<dyn Fn(Value) -> JwtCallbackFuture<String> + Send + Sync>;
/// Sign with application-managed keys. The callback must set `alg` and `kid`.
pub type JwtCustomSign =
    Arc<dyn Fn(Map<String, Value>, JwtSigningOptions) -> JwtCallbackFuture<String> + Send + Sync>;

/// Per-call protected headers and key selection, matching upstream signing overrides.
#[derive(Clone, Debug, Default)]
pub struct JwtSigningOptions {
    /// Pin a previously provisioned key. Missing or expired keys fail.
    pub key_id: Option<String>,
    /// Pin an algorithm. Only configured algorithms can be provisioned lazily.
    pub algorithm: Option<JwtAlgorithm>,
    /// Additional protected headers. Local signing always supplies `alg` and `kid`.
    pub header: Map<String, Value>,
}

/// Parameters for primary or lazily provisioned additional signing keys.
#[derive(Clone, Copy, Debug)]
pub struct JwtKeyPairConfig {
    /// Signing algorithm.
    pub algorithm: JwtAlgorithm,
    /// RSA modulus length for RS256 and PS256. Defaults to 2048 bits.
    pub modulus_length: u32,
}

impl JwtKeyPairConfig {
    /// Use the upstream default key parameters for an algorithm.
    pub fn new(algorithm: JwtAlgorithm) -> Self {
        Self {
            algorithm,
            modulus_length: 2048,
        }
    }
}
