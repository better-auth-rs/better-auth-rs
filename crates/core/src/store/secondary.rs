//! Runtime session and verification storage over the configured database and secondary backend.

mod forward;
mod runtime;
mod sessions;
mod transactions;
mod users;
mod verifications;

use super::{AuthStore, SecondaryStorage};
use crate::entity::{AuthSession, AuthVerification};
use crate::plugin::MetadataMap;
use crate::{AuthConfig, AuthError, AuthResult, AuthSchema};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::sync::Arc;

/// Install secondary session and verification behavior without changing application stores.
/// Construct this facade after plugins register their schemas.
pub struct SecondaryStore<S: AuthSchema> {
    inner: Arc<dyn AuthStore<S>>,
    storage: Option<Arc<dyn SecondaryStorage>>,
    config: Arc<AuthConfig>,
    metadata: MetadataMap,
}

impl<S: AuthSchema> Clone for SecondaryStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            storage: self.storage.clone(),
            config: self.config.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl<S: AuthSchema> SecondaryStore<S> {
    /// Validate model hydration before secondary storage serves requests.
    pub fn new(
        inner: Arc<dyn AuthStore<S>>,
        storage: Arc<dyn SecondaryStorage>,
        config: Arc<AuthConfig>,
        metadata: MetadataMap,
    ) -> AuthResult<Self> {
        if !S::Session::SUPPORTS_RUNTIME_HYDRATION || !S::Verification::SUPPORTS_RUNTIME_HYDRATION {
            return Err(AuthError::config(
                "Secondary storage requires AuthSession and AuthVerification runtime hydration; derive AuthEntity or implement from_runtime_fields",
            ));
        }
        Ok(Self {
            inner,
            storage: Some(storage),
            config,
            metadata,
        })
    }

    /// Apply verification identifier policies without a secondary backend.
    pub fn without_secondary(
        inner: Arc<dyn AuthStore<S>>,
        config: Arc<AuthConfig>,
        metadata: MetadataMap,
    ) -> Self {
        Self {
            inner,
            storage: None,
            config,
            metadata,
        }
    }

    fn database_sessions(&self) -> bool {
        self.storage.is_none() || self.config.session.store_session_in_database
    }

    fn database_verifications(&self) -> bool {
        self.storage.is_none() || self.config.verification.store_in_database
    }

    fn secondary(&self) -> AuthResult<&dyn SecondaryStorage> {
        self.storage.as_deref().ok_or_else(|| {
            AuthError::internal("Secondary storage operation requires an installed backend")
        })
    }
}

fn ttl(expires: DateTime<Utc>) -> u64 {
    u64::try_from((expires - Utc::now()).num_seconds()).unwrap_or(0)
}

// Upstream safeJSONParse treats invalid cached JSON as a cache miss. Backend I/O errors still propagate.
fn decode(value: Option<Value>) -> Option<Value> {
    match value? {
        Value::String(value) => serde_json::from_str(&value).ok(),
        value => Some(value),
    }
}

fn object(value: Value) -> AuthResult<Map<String, Value>> {
    match value {
        Value::Object(value) => Ok(value),
        _ => Err(AuthError::internal(
            "Secondary storage record must be an object",
        )),
    }
}
