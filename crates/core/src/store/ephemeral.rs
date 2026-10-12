//! Process-local adapter used when an application does not configure a database.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::{AuthRecordFields, FieldMap, FieldValue as Value, FromFieldMap, SchemaField};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
#[cfg(test)]
use indexmap::IndexMap;

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::store::{
    AccountStore, AuthTransaction, DeviceCodeStore, InvitationStore, ListOrganizationMembersParams,
    MemberStore, OrganizationStore, PasskeyStore, SessionStore, TransactionStore, TwoFactorStore,
    UserStore, VerificationStore,
};
use crate::types::{
    CreateAccount, CreateDeviceCode, CreateInvitation, CreateMember, CreateOrganization,
    CreatePasskey, CreateSession, CreateTwoFactor, CreateUser, CreateVerification, DeviceCode,
    Invitation, InvitationStatus, ListUsersParams, Member, Organization, Passkey, TwoFactor,
    UpdateAccount, UpdateDeviceCode, UpdateOrganization, UpdateUser,
};
use crate::wire::{AccountView, SessionView, UserView, VerificationView};

mod account_joins;
mod accounts;
mod api_keys;
mod device_codes;
mod field_bindings;
mod fields;
#[cfg(test)]
mod graph_clone_contract_tests;
#[cfg(test)]
mod history_tests;
mod hooks;
#[cfg(test)]
mod id_slot_tests;
#[cfg(test)]
mod initial_storage_tests;
mod invitation_accept;
#[cfg(test)]
mod invitation_team_projection_tests;
mod joins;
mod jwks;
#[cfg(test)]
mod lifecycle_tests;
mod member_delete;
#[cfg(test)]
mod memory_json_tests;
#[cfg(test)]
mod memory_query_tests;
#[cfg(test)]
mod native_join_grouping_tests;
mod native_joins;
#[cfg(test)]
mod native_relation_property_tests;
#[cfg(test)]
mod native_sort_tests;
#[cfg(test)]
mod native_storage_tests;
mod operation;
#[cfg(test)]
mod operation_contract_tests;
mod organization;
#[cfg(test)]
mod organization_async_tests;
mod organization_joins;
#[cfg(test)]
mod organization_parent_tests;
#[cfg(test)]
mod organization_physical_tests;
mod organization_rows;
mod passkeys;
#[cfg(test)]
mod plugin_display_json_tests;
mod plugin_records;
#[cfg(test)]
mod protected_function_tests;
mod rate_limits;
mod raw_records;
mod record_projection;
#[cfg(test)]
mod root_join_contract_tests;
mod rows;
mod runtime;
#[cfg(test)]
mod serial_primary_tests;
mod session_hooks;
mod sessions;
#[cfg(test)]
mod shared_column_contract_tests;
mod state;
mod table;
mod team_capacity;
mod teams;
#[cfg(test)]
mod test_support;
mod transactions;
mod two_factor;
#[cfg(test)]
mod user_runtime_input_tests;
#[cfg(test)]
mod user_serial_tests;
mod users;
mod verification_hooks;
#[cfg(test)]
mod verification_live_output_tests;
mod verifications;
mod wallets;

use crate::store::database_hooks::DatabaseHooks;
use hooks::{PendingHook, PendingHookQueue};
use operation::{MemoryGate, MemoryOperation};
#[cfg(test)]
use organization_rows::OrganizationRows;
#[cfg(test)]
use organization_rows::id as organization_id;
use organization_rows::value as organization_value;
use state::State;
use transactions::EphemeralTransaction;

/// Bundled runtime records for authentication without an application-owned database schema.
pub struct StatelessSchema;

impl AuthSchema for StatelessSchema {
    type User = UserView;
    type Session = SessionView;
    type Account = AccountView;
    type Verification = VerificationView;
}

/// Non-durable adapter with isolated transactions and insertion-ordered records.
#[derive(Clone)]
pub struct EphemeralStore {
    config: Arc<AuthConfig>,
    model_fields: crate::plugin_runtime::ModelFields,
    state: Arc<Mutex<State>>,
    operations: MemoryGate,
    rate_limit_operations: Arc<tokio::sync::Mutex<()>>,
    verification_locks: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
    device_code_transaction: Option<Arc<Mutex<device_codes::DeviceCodeTransaction>>>,
    session_config: crate::config::SessionConfig,
    passkey_storage: crate::PasskeyStorage,
    organization_fields: Arc<RwLock<crate::organization_fields::OrganizationFields>>,
    hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>>,
    pending_hooks: Option<Weak<PendingHookQueue>>,
}

impl Default for EphemeralStore {
    fn default() -> Self {
        Self::new(Arc::new(AuthConfig::default()))
    }
}

impl EphemeralStore {
    fn next_serial_id(&self, row_count: usize) -> Option<Value> {
        matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        )
        .then(|| Value::Number((row_count + 1) as f64))
    }

    /// Construct a standalone adapter with empty tables for every native logical model.
    /// Use `empty` for an explicit empty Memory root, or `from_schema` for auth initialization.
    /// Restarting the process discards all records.
    pub fn new(config: Arc<AuthConfig>) -> Self {
        let mut store = Self::empty(config);
        store.state = Arc::new(Mutex::new(State::with_models(
            store.operations.clone(),
            crate::plugin_runtime::ModelFields::all_native_model_names(),
        )));
        store
    }

    /// Construct an explicit empty Memory root. Native nonserial creation adds physical tables lazily.
    pub fn empty(config: Arc<AuthConfig>) -> Self {
        let model_fields = crate::plugin_runtime::ModelFields::default();
        let operations = model_fields.execution_gate().clone();
        Self {
            model_fields,
            session_config: config.session.clone(),
            passkey_storage: crate::PasskeyStorage::Native,
            config,
            state: Arc::new(Mutex::new(State::default())),
            operations,
            rate_limit_operations: Arc::default(),
            verification_locks: Arc::default(),
            device_code_transaction: None,
            organization_fields: Arc::new(RwLock::new(
                crate::organization_fields::OrganizationFields::default().into_storage(),
            )),
            hooks: Vec::new(),
            pending_hooks: None,
        }
    }

    /// Initialize owned physical tables without applying field policies or lifecycle hooks.
    /// Rows retain field order, missing values, null, undefined, and nested native handles.
    /// Table arrays are new allocations; this constructor does not retain external array identities.
    pub fn from_storage(
        config: Arc<AuthConfig>,
        tables: impl IntoIterator<Item = (String, Vec<FieldMap>)>,
    ) -> AuthResult<Self> {
        Self::from_storage_objects(
            config,
            tables.into_iter().map(|(name, rows)| {
                (
                    name,
                    rows.into_iter().map(crate::FieldObject::from).collect(),
                )
            }),
        )
    }

    /// Initialize physical tables with native record handles without reading their properties.
    /// Reads and writes retain accessors, receiver identity, and aliases between rows.
    /// Table arrays are new allocations; this constructor retains the supplied record objects.
    pub fn from_storage_objects(
        config: Arc<AuthConfig>,
        tables: impl IntoIterator<Item = (String, Vec<crate::FieldObject>)>,
    ) -> AuthResult<Self> {
        let store = Self::empty(config);
        store.operation(|operation| {
            for (name, rows) in tables {
                let table = table::TableRef::new(store.operations.clone());
                for row in rows {
                    let _ = table.push_object(row)?;
                }
                operation.replace_physical_table(name, Some(table))?;
            }
            Ok(())
        })?;
        Ok(store)
    }

    /// Construct the default no-database root from resolved logical schema keys.
    /// Physical model aliases do not change the initial root keys.
    pub fn from_schema(
        config: Arc<AuthConfig>,
        fields: &crate::plugin_runtime::ModelFields,
    ) -> Self {
        let mut store = Self::empty(config);
        store.operations = fields.execution_gate().clone();
        store.state = Arc::new(Mutex::new(State::with_models(
            store.operations.clone(),
            fields.logical_model_names(),
        )));
        store.model_fields = fields.clone();
        store
    }

    fn memory_model_name(&self, role: crate::store::schema::EntityRole) -> AuthResult<&str> {
        let logical = crate::plugin_runtime::ModelFields::native_model_name(role)?;
        Ok(self.model_fields.storage_name(&role.into(), logical))
    }

    fn memory_storage_name<'a>(
        &'a self,
        model: &'a crate::plugin_runtime::ModelKey,
    ) -> AuthResult<&'a str> {
        Ok(self.model_fields.storage_name(model, model.logical_name()?))
    }

    fn snapshot_table<'a>(
        &self,
        state: &'a State,
        role: crate::store::schema::EntityRole,
    ) -> AuthResult<&'a table::TableRef<FieldMap>> {
        state.table(self.memory_model_name(role)?)
    }

    fn memory_create_id_input(
        &self,
        model: &crate::plugin_runtime::ModelKey,
        supplied: Option<Value>,
        policy: crate::id::AdapterIdInput,
    ) -> AuthResult<Option<Value>> {
        let generation = self.config.advanced.database.generate_id();
        let value = generation.adapter_create_id_input(model.logical_name()?, supplied, policy)?;
        if matches!(generation, crate::id::IdGeneration::Serial) {
            return self.operation(|op| Ok(self.next_serial_id(op.table_length(model)?)));
        }
        Ok(value)
    }

    fn memory_record_input(
        &self,
        model: &crate::plugin_runtime::ModelKey,
        name: &str,
        field: &crate::user_fields::UserFieldConfig,
        value: Value,
        create: bool,
    ) -> AuthResult<Value> {
        let value = self.memory_plugin_field_input(field, value)?;
        if create
            && name == "id"
            && matches!(
                self.config.advanced.database.generate_id(),
                crate::id::IdGeneration::Serial
            )
        {
            return self.operation(|op| Ok(Value::Number((op.table_length(model)? + 1) as f64)));
        }
        Ok(value)
    }

    /// Select Passkey storage before installing the adapter in an authentication context.
    /// Native is the default. Select Legacy to preserve opaque credentials and private update timestamps.
    pub fn with_passkey_storage(mut self, storage: crate::PasskeyStorage) -> Self {
        self.passkey_storage = storage;
        self
    }

    /// Register application lifecycle hooks in invocation order.
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>>) -> Self {
        self.hooks = hooks;
        self
    }

    async fn raw<T>(
        &self,
        model: &str,
        operation: &str,
        action: impl FnOnce(&MemoryOperation<'_>) -> AuthResult<T> + Send,
    ) -> AuthResult<T> {
        crate::observability::database::with_database_operation(
            &self.config,
            model,
            operation,
            async { self.operation(action) },
        )
        .await
    }

    fn operation<T>(
        &self,
        action: impl FnOnce(&MemoryOperation<'_>) -> AuthResult<T>,
    ) -> AuthResult<T> {
        MemoryOperation::run(self, action)
    }

    fn organization_fields(&self) -> AuthResult<crate::organization_fields::OrganizationFields> {
        self.organization_fields
            .read()
            .map(|fields| fields.clone())
            .map_err(|_| AuthError::internal("Ephemeral organization schema lock poisoned"))
    }

    fn verification_lock(&self, key: String) -> AuthResult<Arc<tokio::sync::Mutex<()>>> {
        let mut locks = self
            .verification_locks
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral verification lock registry poisoned"))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let _ = locks.insert(key, Arc::downgrade(&lock));
        Ok(lock)
    }

    async fn output_member(&self, value: FieldMap) -> AuthResult<Member> {
        self.output_record(better_auth_schema_registry::EntityRole::Member, value)
            .await
    }
    async fn output_invitation(&self, value: FieldMap) -> AuthResult<Invitation> {
        self.output_record(better_auth_schema_registry::EntityRole::Invitation, value)
            .await
    }
    async fn output_team(&self, value: FieldMap) -> AuthResult<crate::Team> {
        self.output_record(better_auth_schema_registry::EntityRole::Team, value)
            .await
    }
}

#[cfg(test)]
use crate::test_store::test_config;
