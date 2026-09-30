use super::*;
use std::{future::Future, pin::Pin, sync::Arc};

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
