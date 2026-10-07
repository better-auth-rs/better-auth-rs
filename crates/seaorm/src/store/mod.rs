//! SeaORM-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_key_numbers;
mod api_keys;
mod bundled_schema;
mod device_code_consume;
mod device_code_fields;
mod device_code_transactions;
mod device_codes;
pub mod entities;
mod field_output;
#[cfg(test)]
mod history_tests;
mod id_filter;
mod identity_schema;
mod instrumentation;
mod invitations;
mod joins;
mod jwks;
mod members;
mod migrator;
mod model_names;
mod organization_extensions;
mod organization_joins;
mod organization_models;
mod organization_roles;
mod organizations;
mod pagination;
mod passkeys;
mod plugin_models;
mod rate_limits;
pub(crate) mod record_bindings;
mod record_write;
mod runtime;
mod schema_preflight;
mod session_delete;
mod sessions;
mod team_capacity;
mod team_invitation;
mod teams;
mod transaction_hooks;
mod two_factor;
mod two_factor_security;
mod updates;
mod user_delete;
mod user_values;
mod user_verification;
mod users;
mod value_filter;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::{AuthMigrator, run_migrations};
    }
}

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use sea_orm::{DatabaseConnection, DbErr, SqlErr, TransactionTrait};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult, DatabaseError};
use crate::hooks::{SeaOrmHookContext, SeaOrmHooks, current_request_hook_context};
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel};

pub struct SeaOrmStore<
    S: AuthSchema,
    O: crate::SeaOrmOrganizationSchema = crate::OrganizationModels,
    P: crate::SeaOrmPluginSchema = crate::PluginModels,
> {
    config: Arc<AuthConfig>,
    model_fields: better_auth_core::plugin_runtime::ModelFields,
    db: DatabaseConnection,
    schema_revision: Arc<std::sync::atomic::AtomicU64>,
    hooks: Vec<Arc<dyn SeaOrmHooks<S>>>,
    organization_fields:
        Arc<std::sync::RwLock<better_auth_core::organization_fields::OrganizationFields>>,
    _schema: PhantomData<(S, O, P)>,
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> Clone
    for SeaOrmStore<S, O, P>
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            model_fields: self.model_fields.clone(),
            db: self.db.clone(),
            schema_revision: self.schema_revision.clone(),
            hooks: self.hooks.clone(),
            organization_fields: self.organization_fields.clone(),
            _schema: PhantomData,
        }
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    /// Construct a store with bundled organization models.
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        Self {
            config: config.into(),
            model_fields: Default::default(),
            db,
            schema_revision: Default::default(),
            hooks: Vec::new(),
            organization_fields: Default::default(),
            _schema: PhantomData,
        }
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    /// Invalidate checks after application-owned schema changes, including partially failed migrations.
    /// Clones of this store share invalidation; separately constructed stores do not.
    /// Direct SQL does not trigger invalidation automatically.
    pub fn invalidate_schema_check(&self) {
        let _previous = self
            .schema_revision
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Bind application-owned organization models while retaining core auth models and hooks.
    pub fn with_organization_schema<T: crate::SeaOrmOrganizationSchema>(
        self,
    ) -> SeaOrmStore<S, T, P> {
        SeaOrmStore {
            config: self.config,
            model_fields: self.model_fields,
            db: self.db,
            schema_revision: self.schema_revision,
            hooks: self.hooks,
            organization_fields: self.organization_fields,
            _schema: PhantomData,
        }
    }

    /// Bind application-owned plugin models while retaining core and organization models.
    pub fn with_plugin_schema<T: crate::SeaOrmPluginSchema>(self) -> SeaOrmStore<S, O, T> {
        SeaOrmStore {
            config: self.config,
            model_fields: self.model_fields,
            db: self.db,
            schema_revision: self.schema_revision,
            hooks: self.hooks,
            organization_fields: self.organization_fields,
            _schema: PhantomData,
        }
    }

    pub(crate) fn organization_fields(
        &self,
    ) -> AuthResult<better_auth_core::organization_fields::OrganizationFields> {
        self.organization_fields
            .read()
            .map(|fields| fields.clone())
            .map_err(|error| AuthError::internal(error.to_string()))
    }

    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn SeaOrmHooks<S>>>) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn hook<H: SeaOrmHooks<S> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    pub fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    fn parse_id<T>(&self, value: &str, parse: impl FnOnce(&str) -> AuthResult<T>) -> AuthResult<T> {
        parse(
            &self
                .config
                .advanced
                .database
                .generate_id()
                .coerce_id(value)?,
        )
    }

    fn generated_id(&self, model: &str, supplied: Option<String>) -> AuthResult<Option<String>> {
        let policy = better_auth_core::id::AdapterIdInput {
            force_allow_id: supplied.is_some(),
            supports_native_uuid: self.db.get_database_backend() == sea_orm::DbBackend::Postgres,
        };
        self.generated_id_with_policy(model, supplied, policy)
    }

    fn generated_id_with_policy(
        &self,
        model: &str,
        supplied: Option<String>,
        policy: better_auth_core::id::AdapterIdInput,
    ) -> AuthResult<Option<String>> {
        self.config
            .advanced
            .database
            .generate_id()
            .adapter_id_with_policy(model, supplied, policy)
    }

    fn create_fields(
        &self,
        model: &str,
        supplied: Option<String>,
        mut fields: better_auth_core::FieldMap,
    ) -> AuthResult<better_auth_core::FieldMap> {
        if let Some(id) = self.generated_id(model, supplied)? {
            let _ = fields.insert("id".into(), better_auth_core::FieldValue::String(id));
        }
        Ok(fields)
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn SeaOrmHooks<S>>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<HookTransaction<'a, S>>,
    ) -> SeaOrmHookContext<'a, S> {
        SeaOrmHookContext {
            config: self.config.as_ref(),
            db: &self.db,
            tx: tx.map(|(raw, _)| raw),
            transaction: tx.map(|(_, store)| store),
            request: current_request_hook_context(),
        }
    }

    pub async fn test_connection(&self) -> Result<(), DbErr> {
        self.db.ping().await
    }
}

type HookTransaction<'a, S> = (&'a crate::TransactionConnection, &'a dyn AuthTransaction<S>);

struct SeaOrmTransaction<
    S: AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> {
    store: SeaOrmStore<S, O, P>,
    tx: crate::TransactionConnection,
    effects: std::sync::Weak<Mutex<Vec<transaction_hooks::PendingEffect>>>,
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmTransaction<S, O, P>
{
    async fn begin(
        parent: &SeaOrmStore<S, O, P>,
        effects: &Arc<Mutex<Vec<transaction_hooks::PendingEffect>>>,
    ) -> AuthResult<Self> {
        let tx = crate::TransactionConnection::new(parent.db.begin().await.map_err(map_db_err)?);
        let mut store = parent.clone();
        store.model_fields = parent.model_fields.fresh_runtime();
        Ok(Self {
            store,
            tx,
            effects: Arc::downgrade(effects),
        })
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> AuthTransaction<S>
    for SeaOrmTransaction<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: crate::schema::SeaOrmVerificationModel,
{
    async fn get_member_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<better_auth_core::Member>> {
        self.store
            .get_member_value_with_connection(&self.tx, organization_id, user_id)
            .await
    }
    async fn get_organization_by_id_value(
        &self,
        id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<better_auth_core::Organization>> {
        self.store
            .get_organization_by_id_value_with_connection(&self.tx, id)
            .await
    }
    async fn get_team_value(
        &self,
        id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<better_auth_core::Team>> {
        self.store
            .get_team_value_with_connection(&self.tx, id)
            .await
    }
    async fn count_organization_members_value(
        &self,
        id: &better_auth_core::FieldValue,
    ) -> AuthResult<i64> {
        self.store
            .count_organization_members_with_connection(&self.tx, id)
            .await
    }
    async fn create_member(
        &self,
        input: better_auth_core::CreateMember,
    ) -> AuthResult<better_auth_core::Member> {
        self.store
            .create_member_with_connection(&self.tx, input)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &better_auth_core::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<better_auth_core::TeamMember>> {
        self.store
            .add_team_member_with_connection(&self.tx, team_id, user_id, maximum)
            .await
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        self.store.delete_member_with_connection(&self.tx, id).await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.store
            .delete_member_for_user_with_connection(&self.tx, id, organization_id, user_id)
            .await
    }
    fn clone_handle(&self) -> Arc<dyn AuthTransaction<S>> {
        Arc::new(Self {
            store: self.store.clone(),
            tx: self.tx.clone(),
            effects: self.effects.clone(),
        })
    }

    async fn create_user_optional(
        &self,
        input: better_auth_core::CreateUser,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let record = self
            .store
            .create_user_with_connection(&self.tx, Some((&self.tx, self)), input)
            .await?;
        if let Some(record) = &record {
            self.queue(transaction_hooks::Effect::UserCreated(record.clone()))?;
        }
        Ok(record)
    }
    async fn create_session_optional(
        &self,
        input: better_auth_core::CreateSession,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        let record = self
            .store
            .create_session_with_connection(&self.tx, Some((&self.tx, self)), input)
            .await?;
        if let Some(record) = &record {
            self.queue(transaction_hooks::Effect::SessionCreated(record.clone()))?;
        }
        Ok(record)
    }
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut better_auth_core::CreateSession,
    ) -> AuthResult<bool> {
        self.store
            .before_runtime_session_optional_in_tx(input, Some((&self.tx, self)))
            .await
    }
    fn queue_after_commit(
        &self,
        effect: better_auth_core::store::TypedTransactionFuture<'static, ()>,
    ) -> AuthResult<()> {
        if let Some(queue) = self.effects.upgrade() {
            queue
                .lock()
                .map_err(|_| AuthError::internal("Transaction hook queue lock poisoned"))?
                .push(transaction_hooks::PendingEffect::External { effect });
        }
        Ok(())
    }

    async fn before_create_runtime_verification(
        &self,
        input: &mut better_auth_core::CreateVerification,
    ) -> AuthResult<()> {
        self.store
            .before_runtime_verification_in_tx(input, Some((&self.tx, self)))
            .await
    }
    async fn create_verification(
        &self,
        input: better_auth_core::CreateVerification,
    ) -> AuthResult<better_auth_core::wire::VerificationView> {
        self.create_transaction_verification(input, None).await
    }
    async fn create_verification_with_writer(
        &self,
        input: better_auth_core::CreateVerification,
        writer: Option<better_auth_core::store::VerificationCreateWriter>,
    ) -> AuthResult<better_auth_core::wire::VerificationView> {
        self.create_transaction_verification(input, writer).await
    }

    async fn update_verification(
        &self,
        identifier: &str,
        update: better_auth_core::store::database_hooks::VerificationUpdate,
    ) -> AuthResult<Option<better_auth_core::wire::VerificationView>> {
        self.store
            .update_verification_with_connection(
                &self.tx,
                Some((&self.tx, self)),
                identifier,
                update,
            )
            .await
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<better_auth_core::wire::VerificationView>> {
        self.store
            .find_verification_with_connection(&self.tx, identifier)
            .await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.delete_expired_transaction_verifications().await
    }
    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<better_auth_core::wire::VerificationView>> {
        let consumed = self
            .store
            .consume_verification_with_transaction(self, identifier, None)
            .await?;
        if let Some(record) = &consumed {
            self.queue(transaction_hooks::Effect::Deleted(Box::new(record.clone())))?;
        }
        Ok(consumed)
    }
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        use crate::schema::SeaOrmVerificationModel;
        use sea_orm::ColumnTrait;
        self.store
            .delete_single_verification(
                &self.tx,
                Some((&self.tx, self)),
                S::Verification::identifier_column().eq(identifier),
            )
            .await
    }
    async fn get_user_by_id(
        &self,
        id: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        self.store
            .model_fields
            .begin_id_query(better_auth_core::store::schema::EntityRole::User)?;
        let id = self.store.parse_id(id, S::User::parse_id)?;
        match <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(id))
            .one(&self.tx)
            .await
            .map_err(map_db_err)?
            .as_ref()
        {
            Some(row) => self.store.output_user(row, &self.tx).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_user_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        self.store
            .model_fields
            .begin_id_query(better_auth_core::store::schema::EntityRole::User)?;
        match <S::User as SeaOrmUserModel>::Entity::find()
            .filter(
                <S::User as SeaOrmUserModel>::email_column()
                    .eq(crate::utils::email::normalize_user_email(email)),
            )
            .one(&self.tx)
            .await
            .map_err(map_db_err)?
            .as_ref()
        {
            Some(row) => self.store.output_user(row, &self.tx).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_user_by_username(
        &self,
        username: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.store.find_user_by_username(&self.tx, username).await
    }
    async fn update_user(
        &self,
        id: &str,
        update: better_auth_core::UpdateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        let record = self
            .store
            .update_user_with_connection(&self.tx, Some((&self.tx, self)), id, update)
            .await?;
        self.queue(transaction_hooks::Effect::UserUpdated(Some(record.clone())))?;
        Ok(record)
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: better_auth_core::UpdateUser,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        let record = self
            .store
            .update_user_outcome_with_connection(&self.tx, Some((&self.tx, self)), id, update)
            .await?
            .continue_value()
            .flatten();
        if let Some(user) = &record {
            self.queue(transaction_hooks::Effect::UserUpdated(Some(user.clone())))?;
        }
        Ok(record)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_optional(id, true).await.map(|_| ())
    }

    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let record = self
            .store
            .delete_user_with_connection(
                &self.tx,
                Some((&self.tx, self)),
                id,
                delete_database_sessions,
            )
            .await?;
        if let Some(record) = &record {
            self.queue(transaction_hooks::Effect::UserDeleted(record.clone()))?;
        }
        Ok(record)
    }
    fn passkey_storage(&self) -> better_auth_core::PasskeyStorage {
        <P::Passkey as crate::SeaOrmPluginModel>::passkey_storage()
    }
    async fn create_passkey(
        &self,
        input: better_auth_core::CreatePasskey,
    ) -> AuthResult<better_auth_core::Passkey> {
        self.store
            .create_passkey_with_connection(&self.tx, input)
            .await
    }
    async fn before_create_runtime_session(
        &self,
        session: &mut better_auth_core::CreateSession,
    ) -> AuthResult<()> {
        self.store
            .before_runtime_session_in_tx(session, Some((&self.tx, self)))
            .await
    }
    async fn create_user(
        &self,
        create_user: better_auth_core::CreateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        let record = self
            .store
            .create_user_in_tx((&self.tx, self), create_user)
            .await?;
        self.queue(transaction_hooks::Effect::UserCreated(record.clone()))?;
        Ok(record)
    }

    async fn create_account(
        &self,
        create_account: better_auth_core::CreateAccount,
    ) -> AuthResult<better_auth_core::wire::AccountView> {
        let record = self
            .store
            .create_account_in_tx((&self.tx, self), create_account)
            .await?;
        self.queue(transaction_hooks::Effect::AccountCreated(Box::new(
            record.clone(),
        )))?;
        Ok(record)
    }

    async fn create_session(
        &self,
        create_session: better_auth_core::CreateSession,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        let record = self
            .store
            .create_session_in_tx((&self.tx, self), create_session)
            .await?;
        self.queue(transaction_hooks::Effect::SessionCreated(record.clone()))?;
        Ok(record)
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> TransactionStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: crate::schema::SeaOrmVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let effects = Arc::new(Mutex::new(Vec::new()));
        let tx_store = SeaOrmTransaction::begin(self, &effects).await?;

        match work(&tx_store).await {
            Ok(value) => {
                tx_store.tx.commit().await.map_err(map_db_err)?;
                self.finish_queued_transaction_effects(&effects).await?;
                Ok(value)
            }
            Err(err) => {
                tx_store.tx.rollback().await.map_err(map_db_err)?;
                Err(err)
            }
        }
    }
}

pub(crate) fn map_db_err(err: DbErr) -> AuthError {
    if let DbErr::Custom(message) = err {
        return AuthError::Database(DatabaseError::Query(message));
    }
    match err.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::UniqueConstraint(message))
        }
        Some(SqlErr::ForeignKeyConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::Constraint(message))
        }
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

pub(crate) fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

#[cfg(test)]
mod organization_extension_tests;
