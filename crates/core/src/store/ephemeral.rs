//! Process-local adapter used when an application does not configure a database.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde_json::{Map, Value};

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

mod accounts;
mod api_keys;
mod device_codes;
mod fields;
mod hooks;
mod jwks;
#[cfg(test)]
mod lifecycle_tests;
mod organization;
mod passkeys;
mod rate_limits;
mod rows;
mod runtime;
mod session_hooks;
mod sessions;
mod state;
mod teams;
mod transactions;
mod two_factor;
mod user_verification;
mod users;
mod verification_hooks;
mod verifications;
mod wallets;

use crate::store::database_hooks::DatabaseHooks;
use hooks::PendingHook;
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
pub struct EphemeralStore {
    config: Arc<AuthConfig>,
    state: Arc<Mutex<State>>,
    verification_locks: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
    session_config: crate::config::SessionConfig,
    organization_fields: RwLock<crate::organization_fields::OrganizationFields>,
    hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>>,
    pending_hooks: Option<Arc<Mutex<Vec<PendingHook>>>>,
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
        if matches!(
            self.config.advanced.database.generate_id,
            crate::id::IdGeneration::Serial
        ) {
            return Ok(Some((row_count + 1).to_string()));
        }
        self.config
            .advanced
            .database
            .generate_id
            .adapter_id(model, supplied, false)
    }

    /// Construct an empty adapter. Restarting the process discards all records.
    pub fn new(config: Arc<AuthConfig>) -> Self {
        Self {
            session_config: config.session.clone(),
            config,
            state: Arc::default(),
            verification_locks: Arc::default(),
            organization_fields: RwLock::default(),
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

    fn output_organization(&self, value: Organization) -> AuthResult<Organization> {
        let metadata = value.metadata.clone();
        let mut output: Organization =
            self.output_record(better_auth_schema_registry::EntityRole::Organization, value)?;
        if !self
            .organization_fields()?
            .organization
            .additional_fields
            .contains_key("metadata")
        {
            output.metadata = metadata;
        }
        Ok(output)
    }
    fn output_member(&self, value: Member) -> AuthResult<Member> {
        self.output_record(better_auth_schema_registry::EntityRole::Member, value)
    }
    fn output_invitation(&self, value: Invitation) -> AuthResult<Invitation> {
        self.output_record(better_auth_schema_registry::EntityRole::Invitation, value)
    }
    fn output_team(&self, value: crate::Team) -> AuthResult<crate::Team> {
        self.output_record(better_auth_schema_registry::EntityRole::Team, value)
    }
    fn output_organization_role(
        &self,
        value: crate::OrganizationRole,
    ) -> AuthResult<crate::OrganizationRole> {
        self.output_record(
            better_auth_schema_registry::EntityRole::OrganizationRole,
            value,
        )
    }
}

#[cfg(test)]
use crate::test_store::test_config;
