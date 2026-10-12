//! Resolve complete adapter declarations from the configuration owner without changing runtime history.

use super::{ModelFields, ModelKey};
use crate::{
    AuthConfig, AuthResult, FieldMap, config::SessionConfig,
    organization_fields::OrganizationFields, store::schema::EntityRole, user_fields::UserConfig,
};

#[cfg(test)]
mod tests;

/// Complete field policies bound to an adapter's resolved configuration.
/// Native defaults remain lazy callbacks; ID replacement stays in the adapter operation history.
#[doc(hidden)]
pub struct ModelFieldBinding<'a> {
    runtime: &'a ModelFields,
    config: &'a AuthConfig,
    session: &'a SessionConfig,
}

impl ModelFields {
    /// Bind resolved adapter options without copying declarations into a second model registry.
    #[doc(hidden)]
    pub fn bind<'a>(&'a self, config: &'a AuthConfig) -> ModelFieldBinding<'a> {
        ModelFieldBinding {
            runtime: self,
            config,
            session: &config.session,
        }
    }
}

impl<'a> ModelFieldBinding<'a> {
    /// Retain a Memory adapter's separately owned Session configuration.
    pub fn with_session_config(mut self, config: &'a SessionConfig) -> Self {
        self.session = config;
        self
    }

    /// Read complete User policies, including active plugin declarations.
    pub fn user(&self) -> UserConfig {
        self.config
            .user
            .user_field_schema_with_plugins(self.runtime.user_plugin_fields())
    }

    /// Read complete Session policies with legacy input-only fields in their original positions.
    pub fn session(&self, input: &FieldMap) -> UserConfig {
        crate::store::session_field_schema(self.session, input)
    }

    /// Read complete Account policies.
    pub fn account(&self) -> UserConfig {
        self.config.account.field_schema()
    }

    /// Read complete Verification policies.
    pub fn verification(&self) -> UserConfig {
        self.config.verification.field_schema()
    }

    /// Resolve one complete declaration before operation-specific ID replacement.
    /// Read Organization policies from their current owner only for an Organization model.
    pub fn fields(
        &self,
        model: impl Into<ModelKey>,
        organization: impl FnOnce() -> AuthResult<OrganizationFields>,
    ) -> AuthResult<UserConfig> {
        match model.into() {
            ModelKey::Native(EntityRole::User) => Ok(self.user()),
            ModelKey::Native(EntityRole::Session) => Ok(self.session(&FieldMap::new())),
            ModelKey::Native(EntityRole::Account) => Ok(self.account()),
            ModelKey::Native(EntityRole::Verification) => Ok(self.verification()),
            ModelKey::Native(
                role @ (EntityRole::Organization
                | EntityRole::Member
                | EntityRole::Invitation
                | EntityRole::Team
                | EntityRole::OrganizationRole),
            ) => organization()?.fields_for(role).cloned(),
            ModelKey::Native(role) => Ok(self.runtime.plugin_fields(role)),
            model @ ModelKey::Custom(_) => self.runtime.declared_fields(&model).cloned(),
        }
    }
}
