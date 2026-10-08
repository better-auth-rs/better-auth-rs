//! Process-local adapter used when an application does not configure a database.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};

use crate::{AuthRecordFields, FieldMap, FieldValue as Value, FromFieldMap, SchemaField};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
    ApiKey, CreateAccount, CreateDeviceCode, CreateInvitation, CreateMember, CreateOrganization,
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
mod history_tests;
mod hooks;
#[cfg(test)]
mod id_slot_tests;
mod invitation_accept;
mod joins;
mod jwks;
#[cfg(test)]
mod lifecycle_tests;
mod member_delete;
#[cfg(test)]
mod memory_json_tests;
mod organization;
#[cfg(test)]
mod organization_async_tests;
mod organization_joins;
#[cfg(test)]
mod organization_parent_tests;
mod passkeys;
#[cfg(test)]
mod plugin_display_json_tests;
mod plugin_records;
mod rate_limits;
mod rows;
mod runtime;
#[cfg(test)]
mod serial_primary_tests;
mod session_hooks;
mod sessions;
mod state;
mod team_capacity;
mod teams;
mod transactions;
mod two_factor;
#[cfg(test)]
mod user_serial_tests;
mod user_verification;
mod users;
mod verification_hooks;
mod verifications;
mod wallets;

use crate::store::database_hooks::DatabaseHooks;
use hooks::{PendingHook, PendingHookQueue};
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
    verification_locks: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
    device_code_consumptions: Option<Arc<Mutex<Vec<device_codes::DeviceCodeConsumption>>>>,
    session_config: crate::config::SessionConfig,
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
    fn generated_id(
        &self,
        model: &str,
        supplied: Option<String>,
        row_count: usize,
    ) -> AuthResult<Option<String>> {
        let policy = crate::id::AdapterIdInput {
            force_allow_id: supplied.is_some(),
            supports_native_uuid: false,
        };
        self.generated_id_with_policy(model, supplied, row_count, policy)
    }

    fn generated_id_with_policy(
        &self,
        model: &str,
        supplied: Option<String>,
        row_count: usize,
        policy: crate::id::AdapterIdInput,
    ) -> AuthResult<Option<String>> {
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) {
            return Ok(Some((row_count + 1).to_string()));
        }
        self.config
            .advanced
            .database
            .generate_id()
            .adapter_id_with_policy(model, supplied, policy)
    }

    fn next_serial_id(&self, row_count: usize) -> Option<Value> {
        matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        )
        .then(|| Value::Number((row_count + 1) as f64))
    }

    /// Construct an empty adapter. Restarting the process discards all records.
    pub fn new(config: Arc<AuthConfig>) -> Self {
        Self {
            model_fields: Default::default(),
            session_config: config.session.clone(),
            config,
            state: Arc::default(),
            verification_locks: Arc::default(),
            device_code_consumptions: None,
            organization_fields: Arc::default(),
            hooks: Vec::new(),
            pending_hooks: None,
        }
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
        action: impl FnOnce(&mut State) -> AuthResult<T> + Send,
    ) -> AuthResult<T> {
        crate::observability::database::with_database_operation(
            &self.config,
            model,
            operation,
            async {
                let mut state = self.lock()?;
                action(&mut state)
            },
        )
        .await
    }

    fn lock(&self) -> AuthResult<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral state lock poisoned"))
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

    async fn output_organization(&self, value: Organization) -> AuthResult<Organization> {
        Ok(self.output_organizations(vec![value]).await?.remove(0))
    }
    async fn output_organizations(
        &self,
        values: Vec<Organization>,
    ) -> AuthResult<Vec<Organization>> {
        self.output_records(
            better_auth_schema_registry::EntityRole::Organization,
            values,
        )
        .await
    }

    async fn output_member(&self, value: Member) -> AuthResult<Member> {
        self.output_record(better_auth_schema_registry::EntityRole::Member, value)
            .await
    }
    async fn output_invitation(&self, value: Invitation) -> AuthResult<Invitation> {
        self.output_record(better_auth_schema_registry::EntityRole::Invitation, value)
            .await
    }
    async fn output_team(&self, value: crate::Team) -> AuthResult<crate::Team> {
        self.output_record(better_auth_schema_registry::EntityRole::Team, value)
            .await
    }
    async fn output_organization_role(
        &self,
        value: crate::OrganizationRole,
    ) -> AuthResult<crate::OrganizationRole> {
        self.output_record(
            better_auth_schema_registry::EntityRole::OrganizationRole,
            value,
        )
        .await
    }
}

#[cfg(test)]
use crate::test_store::test_config;
