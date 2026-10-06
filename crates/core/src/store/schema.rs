//! Cached runtime validation of the physical schema an adapter writes.

mod check;
mod diff;

pub use better_auth_schema_registry::{
    EntityRole, core_fields, plugin_schemas, resolve_field_name,
};
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
    /// Select persisted model roles and their upstream logical names from the final configuration.
    pub fn models(&self) -> Vec<(EntityRole, &'static str)> {
        let mut models = vec![(EntityRole::User, "user")];
        if self.database_sessions() {
            models.push((EntityRole::Session, "session"));
        }
        models.push((EntityRole::Account, "account"));
        if self.database_verifications() {
            models.push((EntityRole::Verification, "verification"));
        }
        for name in &self.plugins {
            match *name {
                "organization" => {
                    models.extend([
                        (EntityRole::Organization, "organization"),
                        (EntityRole::Member, "member"),
                        (EntityRole::Invitation, "invitation"),
                    ]);
                    if self.metadata_flag("organization.teams_enabled") {
                        models.extend([
                            (EntityRole::Team, "team"),
                            (EntityRole::TeamMember, "teamMember"),
                        ]);
                    }
                    if self.metadata_flag("organization.dynamic_access_control") {
                        models.push((EntityRole::OrganizationRole, "organizationRole"));
                    }
                }
                "api-key" => models.push((EntityRole::ApiKey, "apikey")),
                "device-authorization" => models.push((EntityRole::DeviceCode, "deviceCode")),
                "passkey" => models.push((EntityRole::Passkey, "passkey")),
                "two-factor" => models.push((EntityRole::TwoFactor, "twoFactor")),
                "jwt" => models.push((EntityRole::Jwk, "jwks")),
                "siwe" => models.push((EntityRole::WalletAddress, "walletAddress")),
                _ => {}
            }
        }
        if self.database_rate_limit {
            models.push((EntityRole::RateLimit, "rateLimit"));
        }
        models
    }

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
