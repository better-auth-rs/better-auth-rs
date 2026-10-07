use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect, sea_query::ExprTrait,
};

use better_auth_core::store::AccountStore;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::wire::AccountView;

use crate::error::{AuthError, AuthResult};
use crate::hooks::DatabaseHookUpdate;
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmUserModel};
use crate::types::{CreateAccount, UpdateAccount};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

fn stored_owner_id(
    value: Option<&sea_orm::Value>,
) -> AuthResult<better_auth_core::SchemaValue<String>> {
    value
        .cloned()
        .map(crate::__private_field_value)
        .transpose()?
        .map(|value| {
            if value.is_null() {
                Ok(better_auth_core::SchemaValue::from_field(value))
            } else {
                better_auth_core::SchemaValue::<String>::from_field(value)
                    .display_string()
                    .map(better_auth_core::SchemaValue::from)
            }
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

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

    async fn native_account_owners(
        &self,
        records: Vec<better_auth_core::user_fields::AdapterRecord>,
        users: &[Option<S::User>],
        owner_ids: &[Option<sea_orm::Value>],
    ) -> AuthResult<Vec<better_auth_core::store::AccountOwner>>
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
                    let indices: Vec<_> = ready.iter().map(|(index, _)| *index).collect();
                    let projected = self.output_joined_users(users, &indices).await?;
                    ready
                        .into_iter()
                        .zip(projected)
                        .map(|((index, output), user)| {
                            let owner_id = owner_ids.get(index).ok_or_else(|| {
                                AuthError::internal(
                                    "Account projection lost its stored owner index",
                                )
                            })?;
                            better_auth_core::store::AccountOwner::new(
                                AccountView::from_adapter_fields(output),
                                user,
                                &stored_owner_id(owner_id.as_ref())?,
                            )
                            .map(|owner| (index, owner))
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
        active.apply_fields(input, S::Account::field_column)?;
        if let Some(id) = id {
            active.set(S::Account::id_column(), id.into());
        } else {
            active.not_set(S::Account::id_column());
        }
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "create",
            async { active.insert(db).await },
        )
        .await?;
        let account = self.output_account(&account, db).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                better_auth_core::observability::database::with_database_hook(
                    hook_context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterCreateAccount,
                    hook.after_create_account(&account, &hook_context),
                )
                .await?;
            }
        }
        Ok(Some(account))
    }

    pub(crate) async fn create_account_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_account: CreateAccount,
    ) -> AuthResult<AccountView> {
        self.create_account_with_connection(tx.0, Some(tx), create_account)
            .await?
            .ok_or_else(|| cancelled_by_hook("account creation"))
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
            .ok_or_else(|| cancelled_by_hook("account creation"))
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
        better_auth_core::store::AccountOwner::validate_schema(
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
                (S::Account::user_id_column(), S::User::id_column()),
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
            let (records, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
            (records, Some(users))
        } else {
            (self.account_records(provider, account_id).await?, None)
        };
        let fields = self.config().account.field_schema();
        let mut owner_ids = Vec::with_capacity(records.len());
        let extracted = records
            .into_iter()
            .map(|record| {
                let extracted = record.record_fields(&fields)?;
                owner_ids.push(
                    record
                        .into_active_model()
                        .get(S::Account::user_id_column())
                        .into_value(),
                );
                Ok(extracted)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let backend = self.connection().get_database_backend();
        let owners = if let Some(users) = native_users {
            self.native_account_owners(extracted, &users, &owner_ids)
                .await?
        } else {
            fields
                .project_adapter_records_then(
                    extracted,
                    backend == sea_orm::DbBackend::Postgres,
                    backend != sea_orm::DbBackend::Sqlite,
                    |index, output| {
                        let owner_ids = &owner_ids;
                        async move {
                            let owner_id = owner_ids.get(index).ok_or_else(|| {
                                crate::error::AuthError::internal(
                                    "Account projection lost its stored owner index",
                                )
                            })?;
                            let account = AccountView::from_adapter_fields(output);
                            let stored_owner_id = stored_owner_id(owner_id.as_ref())?;
                            let Some(owner_id) = owner_id else {
                                return better_auth_core::store::AccountOwner::new(
                                    account,
                                    None,
                                    &stored_owner_id,
                                );
                            };
                            self.model_fields.canonicalize_id(EntityRole::User)?;
                            let owner =
                                database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
                                    self.config(),
                                    "findOne",
                                    async {
                                        <S::User as SeaOrmUserModel>::Entity::find()
                                            .filter(S::User::id_column().eq(owner_id.clone()))
                                            .one(self.connection())
                                            .await
                                            .map_err(map_db_err)
                                    },
                                )
                                .await?;
                            let user = match owner.as_ref() {
                                Some(row) => {
                                    self.output_user(row, self.connection()).await.map(Some)
                                }
                                None => Ok(None),
                            }?;
                            better_auth_core::store::AccountOwner::new(
                                account,
                                user,
                                &stored_owner_id,
                            )
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
