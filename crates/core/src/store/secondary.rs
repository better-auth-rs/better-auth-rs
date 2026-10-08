//! Runtime session and verification storage over the configured database and secondary backend.

mod cache;
mod forward;
mod runtime;
mod session_tokens;
mod sessions;
mod transactions;
mod users;
mod verifications;

use super::{AuthStore, SecondaryStorage};
use crate::plugin::MetadataMap;
use crate::{AuthConfig, AuthError, AuthResult, AuthSchema};
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Install secondary session and verification behavior without changing application stores.
/// Construct this facade after plugins register their schemas.
pub struct SecondaryStore<S: AuthSchema> {
    inner: Arc<dyn AuthStore<S>>,
    storage: Option<Arc<dyn SecondaryStorage>>,
    config: Arc<AuthConfig>,
    metadata: MetadataMap,
    schema_validation: Option<super::schema::SchemaValidation>,
    clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl<S: AuthSchema> Clone for SecondaryStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            storage: self.storage.clone(),
            config: self.config.clone(),
            metadata: self.metadata.clone(),
            schema_validation: self.schema_validation.clone(),
            clock: self.clock.clone(),
        }
    }
}

impl<S: AuthSchema> SecondaryStore<S> {
    /// Install the secondary backend while retaining canonical runtime records.
    pub fn new(
        inner: Arc<dyn AuthStore<S>>,
        storage: Arc<dyn SecondaryStorage>,
        config: Arc<AuthConfig>,
        metadata: MetadataMap,
    ) -> AuthResult<Self> {
        Ok(Self {
            inner,
            storage: Some(storage),
            config,
            metadata,
            schema_validation: None,
            clock: Arc::new(Utc::now),
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
            schema_validation: None,
            clock: Arc::new(Utc::now),
        }
    }

    /// Set the wall clock for this facade's timestamps, expiration checks, and cache TTLs.
    /// Clones, runtime views, and deferred writes retain the same clock.
    /// Underlying stores and storage backends retain their own clocks.
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Attach this auth instance's explicit and automatic schema check.
    pub fn with_schema_validation(
        mut self,
        validation: Option<super::schema::SchemaValidation>,
    ) -> Self {
        self.schema_validation = validation;
        self
    }

    fn database_sessions(&self) -> bool {
        self.storage.is_none() || self.config.session.store_session_in_database()
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
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
