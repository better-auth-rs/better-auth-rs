use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, sea_query::ExprTrait,
};

use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{AccountOwner, AccountStore, ResolvedJoin};
use better_auth_core::user_fields::AdapterRecord;
use better_auth_core::wire::AccountView;
use better_auth_core::{FieldValue, UserView};

use crate::error::{AuthError, AuthResult};
use crate::hooks::DatabaseHookUpdate;
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmUserModel};
use crate::types::{CreateAccount, UpdateAccount};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Account: SeaOrmAccountModel,
{
    async fn account_records(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Vec<S::Account>> {
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::Account as SeaOrmAccountModel>::Entity::find()
                    .filter(<S::Account as SeaOrmAccountModel>::provider_id_column().eq(provider))
                    .filter(
                        <S::Account as SeaOrmAccountModel>::account_id_column()
                            .eq(provider_account_id),
                    )
                    .limit(2)
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await
    }

    pub(super) async fn user_account_records(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let user_id = self.parse_id(user_id, <S::Account as SeaOrmAccountModel>::parse_user_id)?;
        database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::Account as SeaOrmAccountModel>::Entity::find()
                    .filter(<S::Account as SeaOrmAccountModel>::user_id_column().eq(user_id))
                    .limit(super::pagination::default_limit(
                        self.config(),
                        self.connection().get_database_backend(),
                    )?)
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await
    }

    pub(super) async fn output_accounts(
        &self,
        rows: &[S::Account],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<better_auth_core::wire::AccountView>> {
        if !rows.is_empty() {
            self.model_fields.canonicalize_id(EntityRole::Account)?;
        }
        let fields = self.config().account.field_schema();
        let records = rows
            .iter()
            .map(|row| row.record_fields(&fields))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(fields
            .project_adapter_records(
                records,
                db.get_database_backend() == sea_orm::DbBackend::Postgres,
                db.get_database_backend() != sea_orm::DbBackend::Sqlite,
            )
            .await?
            .into_iter()
            .map(better_auth_core::wire::AccountView::from_adapter_fields)
            .collect())
    }

    pub(super) async fn output_account(
        &self,
        account: &S::Account,
        db: &impl ConnectionTrait,
    ) -> AuthResult<AccountView> {
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        account
            .record(
                &self.config().account.field_schema(),
                db.get_database_backend() == sea_orm::DbBackend::Postgres,
                db.get_database_backend() != sea_orm::DbBackend::Sqlite,
            )
            .await
    }

    pub(super) async fn output_native_account(
        &self,
        account: &S::Account,
    ) -> AuthResult<AccountView> {
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let fields = self.config().account.field_schema();
        let backend = self.connection().get_database_backend();
        let storage = super::joins::native_child_fields(&fields, |name, field| {
            let value = super::field_output::column_value::<
                <S::Account as SeaOrmAccountModel>::Entity,
            >(account, S::Account::field_column(name)?);
            super::field_output::raw_field_output(value, field, backend)?.ok_or_else(|| {
                AuthError::internal(format!(
                    "Raw SQL output omitted selected Account field: {name}"
                ))
            })
        })?;
        let mut record = account.record_fields(&fields)?;
        record.map_storage_fields(
            &fields,
            super::field_output::capabilities(backend),
            |name, _| Ok(Some(storage.get(name).cloned().unwrap_or_default())),
        )?;
        // Projection preserves the one selected child.
        Ok(AccountView::from_adapter_fields(
            fields
                .project_adapter_records(
                    vec![record],
                    backend == sea_orm::DbBackend::Postgres,
                    backend != sea_orm::DbBackend::Sqlite,
                )
                .await?
                .remove(0),
        ))
    }

    pub(super) async fn selected_join_accounts(
        &self,
        relation: &ResolvedJoin,
        value: FieldValue,
    ) -> AuthResult<Vec<S::Account>> {
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
                    query
                        .limit(super::pagination::default_limit(self.config(), backend)?)
                        .all(self.connection())
                        .await
                        .map_err(map_db_err)
                } else {
                    query
                        .one(self.connection())
                        .await
                        .map(|account| account.into_iter().collect())
                        .map_err(map_db_err)
                }
            },
        )
        .await
    }

    async fn native_account_owners(
        &self,
        records: Vec<AdapterRecord>,
        users: &[Vec<S::User>],
        many: bool,
    ) -> AuthResult<Vec<AccountOwner>>
    where
        S::User: SeaOrmUserModel,
    {
        let backend = self.connection().get_database_backend();
        self.config()
            .account
            .field_schema()
            .project_adapter_records_batches_then(
                records,
                backend == sea_orm::DbBackend::Postgres,
                backend != sea_orm::DbBackend::Sqlite,
                |ready| async move {
                    let pages = ready
                        .iter()
                        .map(|(index, _)| {
                            users.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                AuthError::internal("Account projection lost its joined User page")
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
                                    account: AccountView::from_adapter_fields(output),
                                    user: super::joins::relation_value(many, users),
                                },
                            ))
                        })
                        .collect()
                },
            )
            .await
    }

    async fn create_account_with_connection<C>(
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
        let mut active = super::record_write::RecordWrite::from_active(S::Account::new_active(
            id.clone(),
            &input,
        )?);
        active.not_set(S::Account::id_column());
        active.apply_fields(input, S::Account::field_column)?;
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
                    .insert(
                        db,
                        super::create_readback::CreateReadback {
                            schema: &fields,
                            policy: self.config().advanced.database.generate_id(),
                            scope: self.readback_scope(tx),
                            column: S::Account::field_column,
                        },
                    )
                    .await
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
                super::joins::joined_rows::<
                    <S::Account as SeaOrmAccountModel>::Entity,
                    <S::User as SeaOrmUserModel>::Entity,
                >(self.connection(), &query),
            )
            .await?;
            let (records, users): (Vec<_>, Vec<_>) = super::joins::grouped_rows::<
                <S::Account as SeaOrmAccountModel>::Entity,
                <S::User as SeaOrmUserModel>::Entity,
            >(rows, S::Account::id_column())
            .into_iter()
            .map(|(account, users)| {
                let users = super::joins::selected_children::<<S::User as SeaOrmUserModel>::Entity>(
                    users.into_iter(),
                    S::User::id_column(),
                    relation.many,
                    self.config().advanced.database.find_many_limit(),
                );
                (account, users)
            })
            .unzip();
            (records, Some(users))
        } else {
            (self.account_records(provider, account_id).await?, None)
        };
        let fields = self.config().account.field_schema();
        let extracted = records
            .iter()
            .map(|record| record.record_fields(&fields))
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
                                let mut user = self.output_user(&user, self.connection()).await?;
                                self.set_join_user_visibility(&mut user);
                                projected.push(user);
                            }
                            Ok(AccountOwner {
                                account: AccountView::from_adapter_fields(output),
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
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let stored_user_id =
            self.parse_id(user_id, <S::Account as SeaOrmAccountModel>::parse_user_id)?;
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::Account as SeaOrmAccountModel>::Entity::find()
                    .filter(<S::Account as SeaOrmAccountModel>::user_id_column().eq(stored_user_id))
                    .filter(
                        <S::Account as SeaOrmAccountModel>::provider_id_column().eq("credential"),
                    )
                    .filter(<S::Account as SeaOrmAccountModel>::account_id_column().eq(user_id))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
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
        mut update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let account_id = self.parse_id(id, <S::Account as SeaOrmAccountModel>::parse_id)?;
        let hook_context = self.hook_context(None);
        let original = update.clone();
        for hook in self.hooks() {
            match better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateAccount,
                hook.before_update_account(id, &original, &hook_context),
            )
            .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let fields = self.config().account.field_schema();
        let backend = self.connection().get_database_backend();
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let input = fields
            .record_storage_fields_with_binding(update.fields()?, false, |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    self.config().advanced.database.generate_id(),
                    S::Account::field_column,
                    S::Account::native_json_field,
                    backend,
                )
            })
            .await?;
        let active = super::record_write::RecordWrite::<<S::Account as SeaOrmAccountModel>::Entity>::from_fields(input, S::Account::field_column)?;
        let reselect = match active.expression(S::Account::id_column(), backend)? {
            Some(value) => S::Account::id_column()
                .into_expr()
                .eq(S::Account::id_column().save_as(value)),
            None => S::Account::id_column().eq(account_id.clone()),
        };
        let account = match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "update",
            async {
                super::updates::update_record_returning_one::<
                    <S::Account as SeaOrmAccountModel>::Entity,
                    _,
                >(
                    self.connection(),
                    active,
                    S::Account::id_column().eq(account_id),
                    reselect,
                )
                .await
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
                hook.after_update_account(account.as_ref(), &hook_context),
            )
            .await?;
        }
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let account_id = self.parse_id(id, <S::Account as SeaOrmAccountModel>::parse_id)?;
        // The upstream single-delete snapshot catch also covers adapter output failures.
        let snapshot: AuthResult<Option<AccountView>> = async {
            match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
                self.config(),
                "findOne",
                async {
                    <S::Account as SeaOrmAccountModel>::Entity::find()
                        .filter(S::Account::id_column().eq(account_id.clone()))
                        .one(self.connection())
                        .await
                        .map_err(map_db_err)
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
                    .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
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
