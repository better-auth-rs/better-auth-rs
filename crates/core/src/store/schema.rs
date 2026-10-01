//! Cached runtime validation of the physical schema an adapter writes.

mod check;
mod diff;

pub use better_auth_schema_registry::{EntityRole, core_fields, plugin_schemas};
pub use check::{SchemaCheck, SchemaCheckError, SchemaInspector, SchemaValidation};
pub use diff::{SchemaColumn, SchemaFinding, SchemaMismatch, SchemaTable, StoredSchemaTable, diff};

use crate::{AuthConfig, plugin::MetadataMap};
use std::sync::Arc;

/// Final persistence configuration. Documentation schemas are not database requirements.
pub struct SchemaConfiguration {
    pub config: Arc<AuthConfig>,
    pub plugins: Vec<&'static str>,
    pub metadata: MetadataMap,
    pub secondary_storage: bool,
    pub database_rate_limit: bool,
}

impl SchemaConfiguration {
    pub fn database_sessions(&self) -> bool {
        !self.secondary_storage || self.config.session.store_session_in_database()
    }

    pub fn database_verifications(&self) -> bool {
        !self.secondary_storage || self.config.verification.store_in_database
    }

    pub fn metadata_flag(&self, key: &str) -> bool {
        self.metadata.get(key).and_then(serde_json::Value::as_bool) == Some(true)
    }
}
