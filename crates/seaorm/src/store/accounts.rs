use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};

use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{AccountOwner, AccountStore, ResolvedJoin};
use better_auth_core::user_fields::AdapterRecord;
use better_auth_core::wire::AccountView;
use better_auth_core::{FieldValue, UserView};

use crate::error::{AuthError, AuthResult};
use crate::hooks::DatabaseUpdateResult;
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmUserModel};
use crate::types::{CreateAccount, UpdateAccount};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err, plugin_rows::SqlRow};

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
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let selectors = selectors
            .iter()
            .map(|(name, value)| self.account_selector(name, value))
            .collect::<AuthResult<Vec<_>>>()?;
        let backend = db.get_database_backend();
        let fields = self.config().account.field_schema();
        let input = fields
            .record_storage_fields_with_binding(
                prepared.into_fields(),
                false,
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::Account::field_column,
                        S::Account::native_json_field,
                        backend,
                    )
                },
            )
            .await?;
        let write = super::record_write::RecordWrite::<<S::Account as SeaOrmAccountModel>::Entity>::from_fields(input, S::Account::field_column)?;
        let mut query = write.update(backend)?;
        for selector in selectors {
            query = query.filter(selector);
        }
        let count = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "updateMany",
            async {
                query
                    .exec(db)
                    .await
                    .map(|result| result.rows_affected.min(9_007_199_254_740_991))
                    .map_err(map_db_err)
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
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Vec<SqlRow>> {
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let provider = self.account_selector("providerId", &provider.into())?;
        let account_id = self.account_selector("accountId", &provider_account_id.into())?;
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                super::plugin_rows::all(
                    self.connection(),
                    <S::Account as SeaOrmAccountModel>::Entity::find()
                        .filter(provider)
                        .filter(account_id)
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
        let fields = self.config().account.field_schema();
        let field = if name == "id" {
            Default::default()
        } else {
            fields.fields().get(name).cloned().unwrap_or_default()
        };
        let backend = self.connection().get_database_backend();
        let value = if name == "id" || field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(original.clone())?
        } else {
            original.clone()
        };
        let value = better_auth_core::user_query::bind_filter(&field, &value)?;
        let value = super::value_filter::adapter_query_value(value, original, &field, backend)?;
        let name =
            better_auth_core::store::schema::resolve_field_name(field.field_name.as_deref(), name);
        super::value_filter::equals(S::Account::field_column(name)?, &value, backend)
    }

    async fn user_account_records(&self, user_id: &FieldValue) -> AuthResult<Vec<SqlRow>> {
        self.model_fields.begin_id_query(EntityRole::Account)?;
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                super::plugin_rows::all(
                    self.connection(),
                    <S::Account as SeaOrmAccountModel>::Entity::find()
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
        if !rows.is_empty() {
            self.model_fields.canonicalize_id(EntityRole::Account)?;
        }
        let fields = self.config().account.field_schema();
        let records = rows
            .iter()
            .map(|row| {
                row.record::<<S::Account as SeaOrmAccountModel>::Entity>(
                    &fields,
                    db.get_database_backend(),
                    S::Account::id_column(),
                    S::Account::field_column,
                )
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(fields
            .project_adapter_records(
                records,
                db.get_database_backend() == sea_orm::DbBackend::Postgres,
                db.get_database_backend() != sea_orm::DbBackend::Sqlite,
            )
            .await?
            .into_iter()
            .map(|output| super::plugin_rows::ordered_output(&fields, output))
            .map(better_auth_core::wire::AccountView::from_adapter_fields)
            .collect())
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
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let fields = self.config().account.field_schema();
        let backend = self.connection().get_database_backend();
        let record = account.native_record::<<S::Account as SeaOrmAccountModel>::Entity>(
            &fields,
            backend,
            S::Account::id_column(),
            S::Account::field_column,
        )?;
        // Projection preserves the one selected child.
        Ok(AccountView::from_adapter_fields(
            super::plugin_rows::ordered_output(
                &fields,
                fields
                    .project_adapter_records(
                        vec![record],
                        backend == sea_orm::DbBackend::Postgres,
                        backend != sea_orm::DbBackend::Sqlite,
                    )
                    .await?
                    .remove(0),
            ),
        ))
    }

    pub(super) async fn selected_join_accounts(
        &self,
        relation: &ResolvedJoin,
        value: FieldValue,
    ) -> AuthResult<Vec<SqlRow>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let fields = self.config().account.field_schema();
        let (logical_to, physical_to) = relation.fallback_target(
            (EntityRole::Account, "account", &fields),
            &self.model_fields,
        )?;
        let field = fields
            .fields()
            .get(&logical_to)
            .cloned()
            .unwrap_or_default();
        let backend = self.connection().get_database_backend();
        let original = value.clone();
        let value = if logical_to == "id" || field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(value)?
        } else {
            value
        };
        let value = better_auth_core::user_query::bind_filter(&field, &value)?;
        let value = super::value_filter::adapter_query_value(value, &original, &field, backend)?;
        let column = S::Account::field_column(&physical_to)?;
        let query = <S::Account as SeaOrmAccountModel>::Entity::find()
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
        users: &[Vec<SqlRow>],
        many: bool,
    ) -> AuthResult<Vec<AccountOwner>>
    where
        S::User: SeaOrmUserModel,
    {
        let backend = self.connection().get_database_backend();
        let fields = self.config().account.field_schema();
        fields
            .project_adapter_records_batches_then(
                records,
                backend == sea_orm::DbBackend::Postgres,
                backend != sea_orm::DbBackend::Sqlite,
                |ready| {
                    let fields = &fields;
                    async move {
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
                        let projected = self.output_native_user_pages(pages).await?;
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
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let fields = self.config().account.field_schema();
        let input = fields
            .record_storage_fields_with_binding(
                create_account.fields()?,
                true,
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::Account::field_column,
                        S::Account::native_json_field,
                        db.get_database_backend(),
                    )
                },
            )
            .await?;
        let id = self.generated_id(
            "account",
            input
                .get("id")
                .and_then(better_auth_core::FieldValue::as_str)
                .map(str::to_owned),
        )?;
        let id = id.as_deref().map(S::Account::parse_id).transpose()?;
        let mut active = super::record_write::RecordWrite::<
            <S::Account as SeaOrmAccountModel>::Entity,
        >::from_initialized_fields(
            input,
            S::Account::field_column,
            S::Account::extra_insert_columns(),
            |input| S::Account::new_active(id.clone(), input),
        )?;
        if let Some(id) = id {
            active.set(S::Account::id_column(), id.into());
        } else {
            active.not_set(S::Account::id_column());
        }
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
        let records = self.account_records(provider, provider_account_id).await?;
        let accounts = self.output_accounts(&records, self.connection()).await?;
        if accounts.len() > 1 {
            return Err(crate::error::AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                serde_json::to_string(provider)?
            )));
        }
        Ok(accounts.into_iter().next())
    }

    async fn get_account_owner(
        &self,
        provider: &str,
        account_id: &str,
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
                <S::Account as SeaOrmAccountModel>::Entity::find()
                    .filter(S::Account::provider_id_column().eq(provider))
                    .filter(S::Account::account_id_column().eq(account_id))
                    .limit(2),
                (
                    S::Account::field_column(&relation.from)?,
                    S::User::field_column(&relation.to)?,
                ),
                S::User::id_column(),
            );
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
        let fields = self.config().account.field_schema();
        let extracted = records
            .iter()
            .map(|record| {
                record.record::<<S::Account as SeaOrmAccountModel>::Entity>(
                    &fields,
                    self.connection().get_database_backend(),
                    S::Account::id_column(),
                    S::Account::field_column,
                )
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let backend = self.connection().get_database_backend();
        let owners = if let Some(users) = native_users {
            self.native_account_owners(extracted, &users, relation.many)
                .await?
        } else {
            fields
                .project_adapter_records_then(
                    extracted,
                    backend == sea_orm::DbBackend::Postgres,
                    backend != sea_orm::DbBackend::Sqlite,
                    |_, output| {
                        let relation = &relation;
                        let fields = &fields;
                        async move {
                            let source = relation.fallback_from(
                                (EntityRole::Account, "account", fields),
                                &self.model_fields,
                            )?;
                            let value = output.get(&source).cloned().unwrap_or_default();
                            let users = self
                                .selected_join_users(
                                    relation,
                                    value,
                                    self.config().advanced.database.find_many_limit(),
                                )
                                .await?;
                            let mut projected = Vec::with_capacity(users.len());
                            for user in users {
                                let user = self.output_user(&user, self.connection()).await?;
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
                serde_json::to_string(provider)?
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
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let owner = self.account_selector("userId", user_id)?;
        let provider = self.account_selector("providerId", &"credential".into())?;
        let account_id = self.account_selector("accountId", user_id)?;
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                super::plugin_rows::one(
                    self.connection(),
                    <S::Account as SeaOrmAccountModel>::Entity::find()
                        .filter(owner)
                        .filter(provider)
                        .filter(account_id),
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
        let fields = self.config().account.field_schema();
        let backend = self.connection().get_database_backend();
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let account_id = self.account_selector("id", id)?;
        let input = fields
            .record_storage_fields_with_binding(
                prepared.into_fields(),
                false,
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
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
                super::updates::execute_update_returning_raw::<
                    <S::Account as SeaOrmAccountModel>::Entity,
                    _,
                >(
                    self.connection(),
                    active.update_returning(backend)?.filter(account_id.clone()),
                    account_id,
                )
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
            self.model_fields.begin_id_query(EntityRole::Account)?;
            match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    super::plugin_rows::all(
                        self.connection(),
                        <S::Account as SeaOrmAccountModel>::Entity::find()
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
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let _ = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "delete",
            async {
                <S::Account as SeaOrmAccountModel>::Entity::delete_many()
                    .filter(self.account_selector("id", id)?)
                    .exec(self.connection())
                    .await
                    .map_err(map_db_err)
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
