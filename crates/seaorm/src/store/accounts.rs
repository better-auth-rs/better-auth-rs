use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect,
};

use better_auth_core::store::AccountStore;
use better_auth_core::wire::AccountView;

use crate::error::AuthResult;
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

    pub(super) async fn output_accounts(
        &self,
        rows: &[S::Account],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<better_auth_core::wire::AccountView>> {
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
        account
            .record(
                &self.config().account.field_schema(),
                db.get_database_backend() == sea_orm::DbBackend::Postgres,
                db.get_database_backend() != sea_orm::DbBackend::Sqlite,
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
        create_account = create_account.with_timestamps(Utc::now());
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
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        )?;
        let parsed = id.as_deref().map(S::Account::parse_id).transpose()?;
        let mut active = S::Account::new_active(parsed, input)?;
        if id.is_none() {
            active.not_set(S::Account::id_column());
        }
        crate::reference_id::apply_bindings(
            &mut active,
            &fields,
            db.get_database_backend(),
            S::Account::field_column,
        )?;
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "create",
            async { active.insert(db).await.map_err(map_db_err) },
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
        let records = self.account_records(provider, account_id).await?;
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
        let owners = fields
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
                        let stored_owner_id = owner_id
                            .as_ref()
                            .map(sea_orm::sea_query::sea_value_to_json_value)
                            .map(|value| {
                                if value.is_null() {
                                    Ok(better_auth_core::SchemaValue::from_json(Some(value)))
                                } else {
                                    better_auth_core::SchemaValue::<String>::from_json(Some(value))
                                        .display_string()
                                        .map(better_auth_core::SchemaValue::from)
                                }
                            })
                            .transpose()?
                            .unwrap_or_default();
                        let Some(owner_id) = owner_id else {
                            return better_auth_core::store::AccountOwner::new(
                                account,
                                None,
                                &stored_owner_id,
                            );
                        };
                        let owner = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
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
                            Some(row) => self.output_user(row, self.connection()).await.map(Some),
                            None => Ok(None),
                        }?;
                        better_auth_core::store::AccountOwner::new(account, user, &stored_owner_id)
                    }
                },
            )
            .await?;
        if owners.len() > 1 {
            return Err(crate::error::AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                serde_json::to_string(provider)?
            )));
        }
        Ok(owners.into_iter().next())
    }

    async fn get_credential_account(&self, user_id: &str) -> AuthResult<Option<AccountView>> {
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
        let user_id = self.parse_id(user_id, <S::Account as SeaOrmAccountModel>::parse_user_id)?;
        match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
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
        {
            Ok(rows) => self.output_accounts(&rows, self.connection()).await,
            Err(error) => Err(error),
        }
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
        let mut active = <S::Account as SeaOrmAccountModel>::ActiveModel::default();
        S::Account::apply_fields(&mut active, input)?;
        crate::reference_id::apply_bindings(
            &mut active,
            &fields,
            backend,
            S::Account::field_column,
        )?;
        let reselect = match active.get(S::Account::id_column()) {
            sea_orm::ActiveValue::Set(value) => S::Account::id_column().eq(value),
            _ => S::Account::id_column().eq(account_id.clone()),
        };
        let account = match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "update",
            async {
                super::updates::update_returning_one::<
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
