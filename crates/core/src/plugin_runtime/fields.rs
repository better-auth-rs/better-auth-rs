#[cfg(test)]
mod availability_tests;
mod binding;
mod declarations;
mod device;
#[cfg(test)]
mod id_scope_tests;
mod input;
mod models;
#[cfg(test)]
mod rate_limit_tests;
mod record;
mod registration;

use crate::id::AdapterIdInput;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{AdapterRecord, UserConfig, UserFieldType};
use crate::{AuthConfig, AuthError, AuthResult, FieldMap, FieldValue as Value};
pub use binding::ModelFieldBinding;
use indexmap::{IndexMap, IndexSet};
pub use models::ModelKey;
use parking_lot::ReentrantMutex;
use std::future::{Future, poll_fn};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

/// Plugin field policies consumed by the selected adapter during auth initialization.
#[derive(Clone, Default)]
pub struct ModelFields {
    models: IndexMap<EntityRole, UserConfig>,
    schema_models: Option<Vec<(EntityRole, &'static str)>>,
    declarations: IndexMap<ModelKey, Option<String>>,
    registered_declarations: Vec<(ModelKey, Vec<String>)>,
    custom_models: IndexMap<String, UserConfig>,
    user_plugin_fields: Vec<&'static str>,
    session_plugin_fields: Vec<&'static str>,
    organization: Option<crate::organization_fields::OrganizationFields>,
    organization_teams_enabled: Option<bool>,
    id_history: Arc<Mutex<IdHistory>>,
    execution: Arc<OnceLock<Arc<ReentrantMutex<()>>>>,
}

#[derive(Default)]
struct IdHistory {
    canonical: IndexSet<ModelKey>,
    input: IndexMap<ModelKey, AdapterIdInput>,
}

impl ModelFields {
    pub(crate) fn execution_gate(&self) -> &Arc<ReentrantMutex<()>> {
        self.execution.get_or_init(Arc::default)
    }

    pub(crate) fn bind_execution_gate(&self, gate: Arc<ReentrantMutex<()>>) -> AuthResult<()> {
        let bound = self.execution.get_or_init(|| gate.clone());
        if !Arc::ptr_eq(bound, &gate) {
            return Err(AuthError::config(
                "Adapter field runtime is already bound to another Memory synchronization domain",
            ));
        }
        Ok(())
    }

    /// Run each synchronous input segment without another thread replacing its ID policy.
    /// Pending callbacks release the gate; resumed callbacks observe the current shared policy.
    #[doc(hidden)]
    pub async fn with_id_input<T>(
        &self,
        model: impl Into<ModelKey>,
        policy: AdapterIdInput,
        convert: impl Future<Output = AuthResult<T>>,
    ) -> AuthResult<T> {
        let mut convert = std::pin::pin!(async {
            self.begin_id_input(model, policy)?;
            convert.await
        });
        poll_fn(|context| {
            let _execution = self.execution_gate().lock();
            convert.as_mut().poll(context)
        })
        .await
    }

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
    pub fn canonicalize_id(&self, model: impl Into<ModelKey>) -> AuthResult<()> {
        let _execution = self.execution_gate().lock();
        let _ = self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?
            .canonical
            .insert(model.into());
        Ok(())
    }

    /// Install the ID input policy before create or update field conversion.
    #[doc(hidden)]
    pub fn begin_id_input(
        &self,
        model: impl Into<ModelKey>,
        policy: AdapterIdInput,
    ) -> AuthResult<()> {
        let _execution = self.execution_gate().lock();
        let mut history = self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?;
        let model = model.into();
        let _ = history.canonical.insert(model.clone());
        let _ = history.input.insert(model, policy);
        Ok(())
    }

    /// Field-attribute lookup installs an unforced ID policy without native UUID support.
    #[doc(hidden)]
    pub fn begin_id_query(&self, model: impl Into<ModelKey>) -> AuthResult<()> {
        self.begin_id_input(model, AdapterIdInput::default())
    }

    /// Replace the ID input policy when a nonempty output conversion starts.
    #[doc(hidden)]
    pub fn begin_id_output(&self, model: impl Into<ModelKey>) -> AuthResult<()> {
        let _execution = self.execution_gate().lock();
        begin_id_output(&self.id_history, model.into())
    }

    pub(crate) fn id_output_initializer(
        &self,
        model: impl Into<ModelKey>,
    ) -> Box<dyn FnOnce() -> AuthResult<()> + Send + Sync> {
        let model = model.into();
        let history = self.id_history.clone();
        let execution = self.execution_gate().clone();
        Box::new(move || {
            let _execution = execution.lock();
            begin_id_output(&history, model)
        })
    }

    /// Read the current ID policy after preceding field callbacks have completed.
    #[doc(hidden)]
    pub fn id_input_active(&self, model: impl Into<ModelKey>) -> AuthResult<bool> {
        Ok(self.id_input_policy(model)?.is_some())
    }

    /// Read the complete input policy after preceding field callbacks have completed.
    #[doc(hidden)]
    pub fn id_input_policy(
        &self,
        model: impl Into<ModelKey>,
    ) -> AuthResult<Option<AdapterIdInput>> {
        Ok(self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?
            .input
            .get(&model.into())
            .copied())
    }

    /// Read declarations with the primary-key policy installed by preceding adapter operations.
    #[doc(hidden)]
    pub fn runtime_fields(
        &self,
        model: impl Into<ModelKey>,
        configured: &UserConfig,
    ) -> AuthResult<UserConfig> {
        let mut fields = configured.clone();
        if self
            .id_history
            .lock()
            .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?
            .canonical
            .contains(&model.into())
        {
            let _ = fields.fields_mut().insert("id".into(), Default::default());
        }
        Ok(fields)
    }

    /// Install core persistence selection and the final database rate-limit declaration.
    pub fn set_schema_configuration(&mut self, config: &crate::store::schema::SchemaConfiguration) {
        if config.rate_limit.storage == Some(crate::middleware::RateLimitStorageKind::Database) {
            // getAuthTables replaces the complete plugin model after plugin declarations merge.
            let mut fields = Self::plugin_native_fields(EntityRole::RateLimit);
            for (name, field) in fields.fields_mut() {
                field.field_name = Some(
                    crate::store::schema::resolve_field_name(
                        config
                            .rate_limit
                            .fields
                            .as_ref()
                            .and_then(|fields| fields.get(name))
                            .map(String::as_str),
                        name,
                    )
                    .to_owned(),
                );
            }
            let _ = self.models.insert(EntityRole::RateLimit, fields);
            let model_name = config.rate_limit.model_name.as_deref().map(|name| {
                crate::store::schema::resolve_field_name(Some(name), "rateLimit").to_owned()
            });
            let _ = self
                .declarations
                .insert(ModelKey::Native(EntityRole::RateLimit), model_name);
        }
        self.schema_models = Some(config.core_models());
        self.set_plugin_metadata(&config.metadata);
    }

    /// Activate native public fields without rebuilding declarations or adapter operation history.
    #[doc(hidden)]
    pub fn set_plugin_metadata(&mut self, metadata: &crate::plugin::MetadataMap) {
        for name in crate::wire::UserView::active_plugin_fields(metadata) {
            if !self.user_plugin_fields.contains(&name) {
                self.user_plugin_fields.push(name);
            }
        }
        for name in crate::wire::SessionView::active_plugin_fields(metadata) {
            if !self.session_plugin_fields.contains(&name) {
                self.session_plugin_fields.push(name);
            }
        }
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

    /// Resolve standalone Organization store relationships without changing configured plugin model availability.
    #[doc(hidden)]
    pub fn organization_join_schema(&self) -> Self {
        let mut schema = self.clone();
        if schema.schema_models.is_none() {
            // Direct OrganizationStore calls support every organization model before plugin initialization.
            static DEFAULTS: LazyLock<ModelFields> = LazyLock::new(|| {
                let mut fields = ModelFields::default();
                fields.register_organization_schema(&Default::default(), true, true);
                fields
            });
            for (declaration, physical) in &DEFAULTS.declarations {
                let _ = schema
                    .declarations
                    .entry(declaration.clone())
                    .or_insert_with(|| physical.clone());
            }
        }
        schema
    }

    pub(crate) fn register(&mut self, role: EntityRole, fields: UserConfig) {
        self.extend(role, fields);
        let _ = self.declarations.insert(ModelKey::Native(role), None);
    }

    pub(crate) fn extend(&mut self, role: EntityRole, fields: UserConfig) {
        let _ = self.declarations.entry(ModelKey::Native(role)).or_default();
        self.registered_declarations.push((
            ModelKey::Native(role),
            fields.fields().keys().cloned().collect(),
        ));
        if let Some(fields) = fields.additional_fields {
            self.models
                .entry(role)
                .or_default()
                .fields_mut()
                .extend(fields);
        }
    }

    /// Declare enabled Organization models in upstream schema order.
    #[doc(hidden)]
    pub fn register_organization_schema(
        &mut self,
        fields: &crate::organization_fields::OrganizationFields,
        teams_enabled: bool,
        dynamic_access_control: bool,
    ) {
        let fields = fields.initialized_options();
        self.organization = Some(fields.clone());
        self.organization_teams_enabled = Some(teams_enabled);
        self.declare_native_fields(EntityRole::Organization, fields.organization.clone());
        if dynamic_access_control {
            self.declare_native_fields(
                EntityRole::OrganizationRole,
                fields.organization_role.clone(),
            );
        }
        if teams_enabled {
            self.declare_native_fields(EntityRole::Team, fields.team.clone());
            self.declare_native_fields(EntityRole::TeamMember, UserConfig::default());
        }
        self.declare_native_fields(EntityRole::Member, fields.member.clone());
        self.declare_native_fields(EntityRole::Invitation, fields.invitation.clone());
    }

    fn declare_native_fields(&mut self, role: EntityRole, fields: UserConfig) {
        let mut declarations = Self::plugin_native_fields(role);
        declarations.fields_mut().extend(fields.fields().clone());
        self.register(role, declarations);
    }

    /// Read the configured Organization teams option.
    /// Standalone OrganizationStore calls keep team support enabled.
    #[doc(hidden)]
    pub fn organization_teams_enabled(&self) -> bool {
        self.organization_teams_enabled.unwrap_or(true)
    }

    /// Resolve final Organization declarations once before adapter field reads and writes.
    /// Standalone adapters retain native defaults; initialized adapters use exactly the registered declarations.
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
            if self.schema_models.is_some() {
                *schema = self.fields(role).ordered_declarations(&[]);
                continue;
            }
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
            *schema = resolved;
        }
        fields
    }

    /// Read the adapter policies for one supported model.
    pub fn fields(&self, role: EntityRole) -> &UserConfig {
        static EMPTY: LazyLock<UserConfig> = LazyLock::new(UserConfig::default);
        self.models.get(&role).unwrap_or(&EMPTY)
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
        (adapter, endpoint, self)
    }
}

fn begin_id_output(history: &Mutex<IdHistory>, model: ModelKey) -> AuthResult<()> {
    let mut history = history
        .lock()
        .map_err(|_| AuthError::internal("Adapter schema history lock poisoned"))?;
    let _ = history.canonical.insert(model.clone());
    let _ = history.input.shift_remove(&model);
    Ok(())
}
