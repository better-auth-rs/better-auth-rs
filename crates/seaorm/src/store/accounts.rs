use super::instrumentation::database_operation;
use crate::store::query_compile::Execute;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ConnectionTrait, EntityName, EntityTrait, QueryFilter, QuerySelect};
use std::sync::Arc;

use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{AccountOwner, AccountStore, ResolvedJoin};
use better_auth_core::user_fields::AdapterRecord;
use better_auth_core::wire::AccountView;
use better_auth_core::{FieldValue, UserView};

use crate::error::{AuthError, AuthResult};
use crate::hooks::DatabaseUpdateResult;
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmUserModel};
use crate::types::{CreateAccount, UpdateAccount};

use super::value_filter::{self, QueryPredicate};
use super::{SeaOrmStore, cancelled_by_hook, plugin_rows::SqlRow};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Account: SeaOrmAccountModel,
{
    pub(super) async fn update_accounts_with_connection(
        &self,
        db: &impl ConnectionTrait,
        transaction: Option<super::HookTransaction<'_, S>>,
        selectors: &better_auth_core::FieldMap,
        update: UpdateAccount,
    ) -> AuthResult<Option<u64>> {
        let hook_context = self.hook_context(transaction);
        let mut prepared =
            better_auth_core::store::database_hooks::PreparedRecordWrite::new(update.fields()?);
        for hook in self.hooks() {
            let outcome =
                better_auth_core::observability::database::with_database_update_many_hook(
                    hook_context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::BeforeUpdateAccount,
                    hook.before_update_account(prepared.original_fields_mut(), &hook_context),
                )
                .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        better_auth_core::store::database_hooks::await_adapter_lookup().await;
        let backend = db.get_database_backend();
        let fields = self.field_policy().account();
        let selectors = selectors
            .iter()
            .map(|(name, value)| {
                self.bind_query_field(EntityRole::Account, &fields, name, value, backend)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let policy = self.config().advanced.database.generate_id();
        let input = super::record_write::prepare_fields(
            &fields,
            prepared.into_fields(),
            None,
            (&self.model_fields, EntityRole::Account),
            policy,
            backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    S::Account::field_column,
                    S::Account::native_json_field,
                    backend,
                )
            },
        )
        .await?;
        let write = super::record_write::RecordWrite::<<S::Account as SeaOrmAccountModel>::Entity>::from_fields(input, S::Account::field_column)?;
        let count = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "updateMany",
            async {
                let selectors = selectors
                    .into_iter()
                    .map(|selector| {
                        let (column, value) = selector.resolve(EntityRole::Account, &fields)?;
                        Ok(QueryPredicate::equals(
                            S::Account::field_column(&column)?,
                            value,
                        ))
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                let query = write.update_where(backend, selectors)?.query;
                query
                    .exec_native(db)
                    .await
                    .map(|result| result.rows_affected.min(9_007_199_254_740_991))
            },
        )
        .await?;
        self.after_creation(
            transaction,
            super::transaction_hooks::Effect::AccountUpdated(DatabaseUpdateResult::Many(count)),
            hook_context.request,
        )
        .await?;
        Ok(Some(count))
    }

    async fn account_records(
        &self,
        provider: &FieldValue,
        provider_account_id: &FieldValue,
    ) -> AuthResult<Vec<SqlRow>> {
        let condition =
            self.account_selectors([("providerId", provider), ("accountId", provider_account_id)])?;
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                super::plugin_rows::all(
                    self.connection(),
                    super::plugin_rows::select_all::<<S::Account as SeaOrmAccountModel>::Entity>()
                        .filter(condition)
                        .limit(2),
                )
                .await
            },
        )
        .await
    }

    pub(super) fn account_selector(
        &self,
        name: &str,
        original: &FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let backend = self.connection().get_database_backend();
        let (column, value) = self.query_field_binding(
            EntityRole::Account,
            &self.field_policy().account(),
            name,
            original,
            backend,
        )?;
        super::value_filter::equals(S::Account::field_column(&column)?, &value, backend)
    }

    fn account_selectors<const N: usize>(
        &self,
        selectors: [(&str, &FieldValue); N],
    ) -> AuthResult<sea_orm::Condition> {
        let backend = self.connection().get_database_backend();
        let fields = self.field_policy().account();
        let bound = selectors
            .into_iter()
            .map(|(name, value)| {
                self.bind_query_field(EntityRole::Account, &fields, name, value, backend)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let predicates = bound
            .into_iter()
            .map(|bound| {
                let (column, value) = bound.resolve(EntityRole::Account, &fields)?;
                Ok(QueryPredicate::equals(
                    S::Account::field_column(&column)?,
                    value,
                ))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        value_filter::all(predicates, backend)
    }

    async fn user_account_records(&self, user_id: &FieldValue) -> AuthResult<Vec<SqlRow>> {
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                super::plugin_rows::all(
                    self.connection(),
                    super::plugin_rows::select_all::<<S::Account as SeaOrmAccountModel>::Entity>()
                        .filter(self.account_selector("userId", user_id)?)
                        .limit(super::pagination::default_limit(
                            self.config(),
                            self.connection().get_database_backend(),
                        )?),
                )
                .await
            },
        )
        .await
    }

    pub(super) async fn output_accounts(
        &self,
        rows: &[SqlRow],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<better_auth_core::wire::AccountView>> {
        let fields = self.field_policy().account();
        let records = rows
            .iter()
            .map(|row| {
                row.record::<<S::Account as SeaOrmAccountModel>::Entity>(
                    &fields,
                    db.get_database_backend(),
                    S::Account::id_column(),
                    S::Account::field_column,
                )
                .map(|record| record.with_id_output(&self.model_fields, EntityRole::Account))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        super::plugin_rows::project_records(&fields, records, db.get_database_backend(), |fields| {
            Ok(AccountView::from_adapter_fields(fields))
        })
        .await
    }

    pub(super) async fn output_account(
        &self,
        account: &SqlRow,
        db: &impl ConnectionTrait,
    ) -> AuthResult<AccountView> {
        Ok(self
            .output_accounts(std::slice::from_ref(account), db)
            .await?
            .remove(0))
    }

    pub(super) async fn output_native_account(&self, account: &SqlRow) -> AuthResult<AccountView> {
        let fields = self.field_policy().account().adapter_fields(&[]);
        let backend = self.connection().get_database_backend();
        let record = account
            .native_record(&fields, backend, S::Account::field_column)?
            .with_id_output(&self.model_fields, EntityRole::Account);
        // Projection preserves the one selected child.
        Ok(
            super::plugin_rows::project_records(&fields, vec![record], backend, |fields| {
                Ok(AccountView::from_adapter_fields(fields))
            })
            .await?
            .remove(0),
        )
    }

    pub(super) async fn selected_join_accounts(
        &self,
        relation: &ResolvedJoin,
        value: FieldValue,
    ) -> AuthResult<Vec<SqlRow>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let fields = self.field_policy().account();
        let backend = self.connection().get_database_backend();
        let (physical_to, value) =
            self.query_field_binding(EntityRole::Account, &fields, &relation.to, &value, backend)?;
        let column = S::Account::field_column(&physical_to)?;
        let query = super::plugin_rows::select_all::<<S::Account as SeaOrmAccountModel>::Entity>()
            .filter(super::value_filter::equals(column, &value, backend)?);
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            if relation.many { "findMany" } else { "findOne" },
            async {
                if relation.many {
                    super::plugin_rows::all(
                        self.connection(),
                        query.limit(super::pagination::default_limit(self.config(), backend)?),
                    )
                    .await
                } else {
                    super::plugin_rows::one(self.connection(), query)
                        .await
                        .map(|account| account.into_iter().collect())
                }
            },
        )
        .await
    }

    async fn native_account_owners(
        &self,
        records: Vec<AdapterRecord>,
        users: Vec<Vec<SqlRow>>,
        many: bool,
    ) -> AuthResult<Vec<AccountOwner>>
    where
        S::User: SeaOrmUserModel,
    {
        let backend = self.connection().get_database_backend();
        let fields = self.field_policy().account();
        let user_fields = self.field_policy().user().adapter_fields(&[]);
        let entity = <S::User as SeaOrmUserModel>::Entity::default();
        let physical = self
            .model_fields
            .storage_model_name(EntityRole::User, entity.table_name());
        let records = records
            .into_iter()
            .zip(&users)
            .map(|(record, users)| {
                Ok(record.with_storage_property(
                    physical,
                    super::joins::raw_relation_value(
                        users,
                        &user_fields,
                        many,
                        S::User::field_column,
                    )?,
                ))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let continuation = Arc::new((users, fields.clone()));
        let store = self.clone();
        fields
            .project_adapter_records_owned_batches_then(
                records,
                backend == sea_orm::DbBackend::Postgres,
                backend != sea_orm::DbBackend::Sqlite,
                move |ready| {
                    let continuation = continuation.clone();
                    let store = store.clone();
                    async move {
                        let (users, fields) = continuation.as_ref();
                        let pages = ready
                            .iter()
                            .map(|(index, _)| {
                                users.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                    AuthError::internal(
                                        "Account projection lost its joined User page",
                                    )
                                })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        let projected = store.output_native_user_pages(pages).await?;
                        ready
                            .into_iter()
                            .zip(projected)
                            .map(|((index, output), users)| {
                                let users = users
                                    .into_iter()
                                    .map(UserView::try_from)
                                    .collect::<AuthResult<Vec<_>>>()?;
                                Ok((
                                    index,
                                    AccountOwner {
                                        account: AccountView::from_adapter_fields(
                                            super::plugin_rows::ordered_output(fields, output),
                                        ),
                                        user: super::joins::relation_value(many, users),
                                    },
                                ))
                            })
                            .collect()
                    }
                },
            )
            .await
    }

    pub(super) async fn create_account_with_connection<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut create_account: CreateAccount,
    ) -> AuthResult<Option<AccountView>>
    where
        C: ConnectionTrait,
    {
        create_account = create_account.with_timestamps(Utc::now().into());
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeCreateAccount,
                hook.before_create_account(&mut create_account, &hook_context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(None);
            }
        }
        let fields = self.field_policy().account();
        let policy = self.config().advanced.database.generate_id();
        let backend = db.get_database_backend();
        let input = super::record_write::prepare_fields(
            &fields,
            create_account.fields()?,
            Some("account"),
            (&self.model_fields, EntityRole::Account),
            policy,
            backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    S::Account::field_column,
                    S::Account::native_json_field,
                    backend,
                )
            },
        )
        .await?;
        let active = super::record_write::RecordWrite::from_initialized_fields(
            &fields,
            input,
            S::Account::field_column,
            S::Account::extra_insert_columns(),
            |fields| S::Account::new_active(None, fields),
        )?;
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "create",
            async {
                active
                    .insert_raw(
                        db,
                        super::create_readback::CreateReadback {
                            schema: &fields,
                            policy: self.config().advanced.database.generate_id(),
                            scope: self.readback_scope(tx),
                            column: S::Account::field_column,
                        },
                    )
                    .await
                    .map(|row| row.map(SqlRow::from))
            },
        )
        .await?;
        let account = match account {
            Some(account) => Some(self.output_account(&account, db).await?),
            None => None,
        };
        self.after_creation(
            tx,
            super::transaction_hooks::Effect::AccountCreated(account.clone().map(Box::new)),
            hook_context.request.clone(),
        )
        .await?;
        Ok(account)
    }

    pub(crate) async fn create_account_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_account: CreateAccount,
    ) -> AuthResult<AccountView> {
        self.create_account_with_connection(tx.0, Some(tx), create_account)
            .await?
            .ok_or_else(|| AuthError::internal("Account creation returned no record"))
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> AccountStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Account: SeaOrmAccountModel,
    S::User: SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
        self.create_account_optional(create_account)
            .await?
            .ok_or_else(|| AuthError::internal("Account creation returned no record"))
    }

    async fn create_account_optional(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<Option<AccountView>> {
        self.create_account_with_connection(self.connection(), None, create_account)
            .await
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        self.get_account_value(&provider.into(), &provider_account_id.into())
            .await
    }

    async fn get_account_value(
        &self,
        provider: &FieldValue,
        provider_account_id: &FieldValue,
    ) -> AuthResult<Option<AccountView>> {
        let records = self.account_records(provider, provider_account_id).await?;
        let accounts = self.output_accounts(&records, self.connection()).await?;
        if accounts.len() > 1 {
            return Err(crate::error::AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                provider.stringify()?.unwrap_or_else(|| "undefined".into())
            )));
        }
        Ok(accounts.into_iter().next())
    }

    async fn get_account_owner(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<better_auth_core::store::AccountOwner>> {
        self.get_account_owner_value(&provider.into(), &account_id.into())
            .await
    }

    async fn get_account_owner_value(
        &self,
        provider: &FieldValue,
        account_id: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::store::AccountOwner>> {
        let relation = AccountOwner::resolve_schema(
            self.config(),
            &self.model_fields,
            super::model_names::table_matches::<S, O, P>,
        )?;
        let (records, native_users) = if self.config().advanced.database.joins == Some(true) {
            self.model_fields.canonicalize_id(EntityRole::User)?;
            let query = super::joins::joined_query::<
                <S::Account as SeaOrmAccountModel>::Entity,
                <S::User as SeaOrmUserModel>::Entity,
            >(
                self.connection().get_database_backend(),
                (
                    super::plugin_rows::select_all::<<S::Account as SeaOrmAccountModel>::Entity>()
                        .filter(self.account_selectors([
                            ("providerId", provider),
                            ("accountId", account_id),
                        ])?)
                        .limit(2),
                    S::Account::id_column(),
                ),
                (
                    S::Account::field_column(&relation.from)?,
                    S::User::field_column(&relation.to)?,
                ),
                &self.field_policy().user().adapter_fields(&[]),
                S::User::field_column,
            )?;
            let rows = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
                self.config(),
                "findMany",
                super::joins::joined_raw_rows(self.connection(), &query),
            )
            .await?;
            let (records, users): (Vec<_>, Vec<_>) =
                super::joins::grouped_raw_rows(rows, S::Account::id_column())?
                    .into_iter()
                    .map(|(account, users)| {
                        let users = super::joins::selected_raw_children(
                            users.into_iter(),
                            S::User::id_column(),
                            relation.many,
                            self.config().advanced.database.find_many_limit(),
                        )?;
                        Ok((account, users))
                    })
                    .collect::<AuthResult<Vec<_>>>()?
                    .into_iter()
                    .unzip();
            (records, Some(users))
        } else {
            (self.account_records(provider, account_id).await?, None)
        };
        let fields = self.field_policy().account();
        let extracted = records
            .iter()
            .map(|record| {
                record
                    .record::<<S::Account as SeaOrmAccountModel>::Entity>(
                        &fields,
                        self.connection().get_database_backend(),
                        S::Account::id_column(),
                        S::Account::field_column,
                    )
                    .map(|record| record.with_id_output(&self.model_fields, EntityRole::Account))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let backend = self.connection().get_database_backend();
        let owners = if let Some(users) = native_users {
            self.native_account_owners(extracted, users, relation.many)
                .await?
        } else {
            let continuation = Arc::new((relation, fields.clone()));
            let store = self.clone();
            fields
                .project_adapter_records_owned_then(
                    extracted,
                    backend == sea_orm::DbBackend::Postgres,
                    backend != sea_orm::DbBackend::Sqlite,
                    move |_, output| {
                        let continuation = continuation.clone();
                        let store = store.clone();
                        async move {
                            let (relation, fields) = continuation.as_ref();
                            let source = relation.fallback_from(
                                (EntityRole::Account, "account", fields),
                                &store.model_fields,
                            )?;
                            let value = output.get(&source).cloned().unwrap_or_default();
                            let users = store
                                .selected_join_users(
                                    relation,
                                    value,
                                    store.config().advanced.database.find_many_limit(),
                                )
                                .await?;
                            let mut projected = Vec::with_capacity(users.len());
                            for user in users {
                                let user = store.output_user(&user, store.connection()).await?;
                                projected.push(user);
                            }
                            Ok(AccountOwner {
                                account: AccountView::from_adapter_fields(
                                    super::plugin_rows::ordered_output(fields, output),
                                ),
                                user: super::joins::relation_value(relation.many, projected),
                            })
                        }
                    },
                )
                .await?
        };
        if owners.len() > 1 {
            return Err(crate::error::AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                provider.stringify()?.unwrap_or_else(|| "undefined".into())
            )));
        }
        Ok(owners.into_iter().next())
    }

    async fn get_credential_account(&self, user_id: &str) -> AuthResult<Option<AccountView>> {
        self.get_credential_account_value(&user_id.into()).await
    }

    async fn get_credential_account_value(
        &self,
        user_id: &FieldValue,
    ) -> AuthResult<Option<AccountView>> {
        let condition = self.account_selectors([
            ("userId", user_id),
            ("providerId", &"credential".into()),
            ("accountId", user_id),
        ])?;
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                super::plugin_rows::one(
                    self.connection(),
                    super::plugin_rows::select_all::<<S::Account as SeaOrmAccountModel>::Entity>()
                        .filter(condition),
                )
                .await
            },
        )
        .await?;
        match account {
            Some(account) => self
                .output_account(&account, self.connection())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        self.get_user_accounts_value(&user_id.into()).await
    }

    async fn get_user_accounts_value(&self, user_id: &FieldValue) -> AuthResult<Vec<AccountView>> {
        let rows = self.user_account_records(user_id).await?;
        self.output_accounts(&rows, self.connection()).await
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        self.update_account_optional(id, update)
            .await?
            .ok_or_else(|| cancelled_by_hook("account update"))
    }

    async fn update_account_optional(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        self.update_account_by_id_value(&id.into(), update).await
    }

    async fn update_account_by_id_value(
        &self,
        id: &FieldValue,
        update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let hook_context = self.hook_context(None);
        let mut prepared =
            better_auth_core::store::database_hooks::PreparedRecordWrite::new(update.fields()?);
        for hook in self.hooks() {
            let outcome = better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateAccount,
                hook.before_update_account(prepared.original_fields_mut(), &hook_context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        better_auth_core::store::database_hooks::await_adapter_lookup().await;
        let fields = self.field_policy().account();
        let backend = self.connection().get_database_backend();
        let account_id = self.bind_query_field(EntityRole::Account, &fields, "id", id, backend)?;
        let policy = self.config().advanced.database.generate_id();
        let input = super::record_write::prepare_fields(
            &fields,
            prepared.into_fields(),
            None,
            (&self.model_fields, EntityRole::Account),
            policy,
            backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    S::Account::field_column,
                    S::Account::native_json_field,
                    backend,
                )
            },
        )
        .await?;
        let active = super::record_write::RecordWrite::<<S::Account as SeaOrmAccountModel>::Entity>::from_fields(input, S::Account::field_column)?;
        let account = match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "update",
            async {
                let (column, value) = account_id.resolve(EntityRole::Account, &fields)?;
                let account_id = QueryPredicate::equals(S::Account::field_column(&column)?, value);
                let (query, account_id) = active.update_where_returning(backend, [account_id])?;
                super::updates::execute_update_returning_raw::<
                    <S::Account as SeaOrmAccountModel>::Entity,
                    _,
                >(self.connection(), query, account_id)
                .await
                .map(|row| row.map(SqlRow::from))
            },
        )
        .await?
        .as_ref()
        {
            Some(record) => self
                .output_account(record, self.connection())
                .await
                .map(Some),
            None => Ok(None),
        }?;
        for hook in self.hooks() {
            better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::AfterUpdateAccount,
                hook.after_update_account(
                    DatabaseUpdateResult::One(account.as_ref()),
                    &hook_context,
                ),
            )
            .await?;
        }
        Ok(account)
    }

    async fn update_accounts(
        &self,
        selectors: &better_auth_core::FieldMap,
        update: UpdateAccount,
    ) -> AuthResult<Option<u64>> {
        self.update_accounts_with_connection(self.connection(), None, selectors, update)
            .await
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.delete_account_value(&id.into()).await
    }

    async fn delete_user_accounts_value(&self, user_id: &FieldValue) -> AuthResult<()> {
        self.delete_user_accounts_with_connection(self.connection(), None, user_id)
            .await
            .map(|_| ())
    }

    async fn delete_account_value(&self, id: &FieldValue) -> AuthResult<()> {
        // The upstream single-delete snapshot catch also covers adapter output failures.
        let snapshot: AuthResult<Option<AccountView>> = async {
            match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    super::plugin_rows::all(
                            self.connection(),
                            super::plugin_rows::select_all::<
                                <S::Account as SeaOrmAccountModel>::Entity,
                            >()
                            .filter(self.account_selector("id", id)?)
                            .limit(1),
                        )
                        .await
                },
            )
            .await?
            .first()
            {
                Some(record) => self
                    .output_account(record, self.connection())
                    .await
                    .map(Some),
                None => Ok(None),
            }
        }
        .await;
        let Ok(Some(account_model)) = snapshot else {
            return Ok(());
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeDeleteAccount,
                hook.before_delete_account(&account_model, &hook_context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(());
            }
        }
        let _ = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "delete",
            async {
                <S::Account as SeaOrmAccountModel>::Entity::delete_many()
                    .filter(self.account_selector("id", id)?)
                    .exec_native(self.connection())
                    .await
            },
        )
        .await?;
        for hook in self.hooks() {
            better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::AfterDeleteAccount,
                hook.after_delete_account(&account_model, &hook_context),
            )
            .await?;
        }
        Ok(())
    }
}
