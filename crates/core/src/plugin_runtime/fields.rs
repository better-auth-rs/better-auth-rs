mod declarations;
mod device;
mod input;
mod models;
mod record;

use crate::id::AdapterIdInput;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{AdapterRecord, UserConfig, UserFieldType};
use crate::{AuthConfig, AuthError, AuthResult, FieldMap, FieldValue as Value};
use indexmap::{IndexMap, IndexSet};
use std::sync::{Arc, LazyLock, Mutex};

/// Plugin field policies consumed by the selected adapter during auth initialization.
#[derive(Clone, Default)]
pub struct ModelFields {
    models: IndexMap<EntityRole, UserConfig>,
    schema_models: Option<Vec<(EntityRole, &'static str)>>,
    custom_models: IndexMap<String, (String, UserConfig)>,
    user_plugin_fields: Vec<&'static str>,
    session_plugin_fields: Vec<&'static str>,
    native_fields: IndexMap<EntityRole, IndexSet<String>>,
    organization_output_order: IndexMap<EntityRole, Vec<String>>,
    organization: Option<crate::organization_fields::OrganizationFields>,
    id_history: Arc<Mutex<IdHistory>>,
}

#[derive(Default)]
struct IdHistory {
    canonical: IndexSet<EntityRole>,
    input: IndexMap<EntityRole, AdapterIdInput>,
}

impl ModelFields {
    /// Start an adapter runtime with the same policies and no operation history.
    #[doc(hidden)]
    pub fn fresh_runtime(&self) -> Self {
        Self {
            id_history: Arc::default(),
            ..self.clone()
        }
    }

    /// Retain the upstream primary-key replacement across calls on this adapter runtime.
    #[doc(hidden)]
    pub fn canonicalize_id(&self, role: EntityRole) -> AuthResult<()> {
        let _ = self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?
            .canonical
            .insert(role);
        Ok(())
    }

    /// Install the ID input policy before create or update field conversion.
    #[doc(hidden)]
    pub fn begin_id_input(&self, role: EntityRole, policy: AdapterIdInput) -> AuthResult<()> {
        let mut history = self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?;
        let _ = history.canonical.insert(role);
        let _ = history.input.insert(role, policy);
        Ok(())
    }

    /// Field-attribute lookup installs an unforced ID policy without native UUID support.
    #[doc(hidden)]
    pub fn begin_id_query(&self, role: EntityRole) -> AuthResult<()> {
        self.begin_id_input(role, AdapterIdInput::default())
    }

    /// Replace the ID input policy when a nonempty output conversion starts.
    #[doc(hidden)]
    pub fn begin_id_output(&self, role: EntityRole) -> AuthResult<()> {
        let mut history = self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?;
        let _ = history.canonical.insert(role);
        let _ = history.input.shift_remove(&role);
        Ok(())
    }

    /// Read the current ID policy after preceding field callbacks have completed.
    #[doc(hidden)]
    pub fn id_input_active(&self, role: EntityRole) -> AuthResult<bool> {
        Ok(self.id_input_policy(role)?.is_some())
    }

    /// Read the complete input policy after preceding field callbacks have completed.
    #[doc(hidden)]
    pub fn id_input_policy(&self, role: EntityRole) -> AuthResult<Option<AdapterIdInput>> {
        Ok(self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?
            .input
            .get(&role)
            .copied())
    }

    pub(crate) fn runtime_fields(
        &self,
        role: EntityRole,
        configured: &UserConfig,
    ) -> AuthResult<UserConfig> {
        let mut fields = configured.clone();
        if self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?
            .canonical
            .contains(&role)
        {
            let _ = fields.fields_mut().insert("id".into(), Default::default());
        }
        Ok(fields)
    }

    /// Retain the same active logical models used by runtime schema validation.
    pub fn set_schema_configuration(&mut self, config: &crate::store::schema::SchemaConfiguration) {
        self.schema_models = Some(config.models());
        self.user_plugin_fields =
            crate::wire::UserView::active_plugin_fields(&config.metadata).collect();
        self.session_plugin_fields =
            crate::wire::SessionView::active_plugin_fields(&config.metadata).collect();
    }

    /// Read native User fields owned by active plugins before adapter output projection.
    #[doc(hidden)]
    pub fn user_plugin_fields(&self) -> &[&'static str] {
        &self.user_plugin_fields
    }

    /// Read native Session fields owned by active plugins before adapter output projection.
    #[doc(hidden)]
    pub fn session_plugin_fields(&self) -> &[&'static str] {
        &self.session_plugin_fields
    }

    pub(crate) fn organization_join_schema(&self, config: &AuthConfig) -> Self {
        let mut schema = self.clone();
        if schema.schema_models.is_none() {
            // Direct OrganizationStore calls support every organization model before plugin initialization.
            schema.set_schema_configuration(&crate::store::schema::SchemaConfiguration {
                config: Arc::new(config.clone()),
                plugins: vec!["organization"],
                metadata: [
                    (
                        "organization.teams_enabled".into(),
                        serde_json::Value::Bool(true),
                    ),
                    (
                        "organization.dynamic_access_control".into(),
                        serde_json::Value::Bool(true),
                    ),
                ]
                .into_iter()
                .collect(),
                secondary_storage: false,
                database_rate_limit: false,
            });
        }
        schema
    }

    pub(crate) fn register(&mut self, role: EntityRole, fields: UserConfig) -> AuthResult<()> {
        match role {
            EntityRole::ApiKey
            | EntityRole::Passkey
            | EntityRole::DeviceCode
            | EntityRole::TwoFactor
            | EntityRole::Jwk
            | EntityRole::WalletAddress => {}
            EntityRole::User
            | EntityRole::Session
            | EntityRole::Account
            | EntityRole::Verification
            | EntityRole::Organization
            | EntityRole::Team => {}
            _ => {
                return Err(AuthError::config(format!(
                    "Plugin field registration does not support {role:?}"
                )));
            }
        }
        self.extend(role, fields);
        Ok(())
    }

    pub(crate) fn extend(&mut self, role: EntityRole, fields: UserConfig) {
        if let Some(fields) = fields.additional_fields {
            if let Some(native) = self.native_fields.get_mut(&role) {
                native.retain(|name| !fields.contains_key(name));
            }
            self.models
                .entry(role)
                .or_default()
                .fields_mut()
                .extend(fields);
        }
    }

    pub(crate) fn register_organization_schema(
        &mut self,
        fields: &crate::organization_fields::OrganizationFields,
        teams_enabled: bool,
    ) {
        self.organization = Some(fields.clone());
        self.declare_native_fields(EntityRole::Organization, fields.organization.clone());
        if teams_enabled {
            self.declare_native_fields(EntityRole::Team, fields.team.clone());
        }
        self.declare_native_fields(EntityRole::Member, fields.member.clone());
        self.declare_native_fields(EntityRole::Invitation, fields.invitation.clone());
        self.declare_native_fields(
            EntityRole::OrganizationRole,
            fields.organization_role.clone(),
        );
    }

    fn declare_native_fields(&mut self, role: EntityRole, fields: UserConfig) {
        let registered = self.models.entry(role).or_default().fields_mut();
        let native = self.native_fields.entry(role).or_default();
        for (name, declaration) in Self::plugin_native_fields(role).fields() {
            let _ = registered.insert(name.clone(), declaration.clone());
            let _ = native.insert(name.clone());
        }
        self.extend(role, fields);
    }

    /// Resolve Organization model policies without replacing adapter-owned native defaults.
    pub fn organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> crate::organization_fields::OrganizationFields {
        let mut fields = self.organization.clone().unwrap_or(fields);
        for (role, schema) in [
            (EntityRole::Organization, &mut fields.organization),
            (EntityRole::Team, &mut fields.team),
            (EntityRole::Member, &mut fields.member),
            (EntityRole::Invitation, &mut fields.invitation),
            (EntityRole::OrganizationRole, &mut fields.organization_role),
        ] {
            let Some(registered) = self.models.get(&role) else {
                continue;
            };
            let mut resolved = registered.clone();
            for (name, field) in schema.fields() {
                let _ = resolved
                    .fields_mut()
                    .entry(name.clone())
                    .or_insert_with(|| field.clone());
            }
            if let Some(native) = self.native_fields.get(&role) {
                resolved
                    .fields_mut()
                    .retain(|name, _| !native.contains(name));
            }
            *schema = resolved;
        }
        // Upstream initializes the dynamic-role update schema eagerly as partial.
        for field in fields.organization_role.fields_mut().values_mut() {
            field.required = Some(false);
        }
        fields
    }

    /// Read the adapter policies for one supported model.
    pub fn fields(&self, role: EntityRole) -> &UserConfig {
        static EMPTY: LazyLock<UserConfig> = LazyLock::new(UserConfig::default);
        self.models.get(&role).unwrap_or(&EMPTY)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (EntityRole, &UserConfig)> {
        self.models.iter().map(|(role, fields)| (*role, fields))
    }

    pub(crate) fn organization_output_field_names(
        &self,
        role: EntityRole,
        policies: &UserConfig,
    ) -> Vec<String> {
        let mut names = self
            .organization_output_order
            .get(&role)
            .cloned()
            .unwrap_or_else(|| {
                let mut fields = Self::default();
                fields.register_organization_schema(&Default::default(), true);
                fields.fields(role).fields().keys().cloned().collect()
            });
        for name in policies.fields().keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names.retain(|name| name != "id");
        names.push("id".into());
        names
    }

    /// Merge core policies and retain plugin-table policies for `RuntimeStore::with_runtime`.
    /// Application fields win at the adapter; plugin fields win at existing endpoint parsers.
    pub fn resolve(mut self, application: &AuthConfig) -> (AuthConfig, AuthConfig, Self) {
        let mut adapter = application.clone();
        let mut endpoint = application.clone();
        let mut resolve = |role, configured| {
            let fields = self.models.shift_remove(&role).unwrap_or_default();
            super::resolve_user_fields(&configured, fields)
        };
        (adapter.user, endpoint.user) = resolve(EntityRole::User, application.user.clone());
        let (stored, public) = resolve(EntityRole::Session, application.session.field_schema());
        // Initial defaults use input precedence; adapter policies retain application precedence.
        adapter.session_input_fields = Some(public.clone());
        adapter.session.additional_fields = stored.additional_fields;
        endpoint.session.additional_fields = public.additional_fields;
        let (stored, public) = resolve(
            EntityRole::Account,
            UserConfig {
                additional_fields: Some(application.account.additional_fields.clone()),
            },
        );
        adapter.account.additional_fields = stored.additional_fields.unwrap_or_default();
        endpoint.account.additional_fields = public.additional_fields.unwrap_or_default();
        let (stored, public) = resolve(
            EntityRole::Verification,
            UserConfig {
                additional_fields: Some(application.verification.additional_fields.clone()),
            },
        );
        adapter.verification.additional_fields = stored.additional_fields.unwrap_or_default();
        endpoint.verification.additional_fields = public.additional_fields.unwrap_or_default();
        for (role, native) in &self.native_fields {
            if let Some(fields) = self.models.get_mut(role) {
                // Native slots determine read timing but are not configured adapter policies.
                let _ = self
                    .organization_output_order
                    .insert(*role, fields.fields().keys().cloned().collect());
                fields.fields_mut().retain(|name, _| !native.contains(name));
            }
        }
        (adapter, endpoint, self)
    }
}
