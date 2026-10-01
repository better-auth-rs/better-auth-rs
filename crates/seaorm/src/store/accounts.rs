use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect,
};

use better_auth_core::store::AccountStore;
use better_auth_core::wire::AccountView;

use crate::error::AuthResult;
use crate::hooks::DatabaseHookUpdate;
use crate::schema::{AuthSchema, SeaOrmAccountModel};
use crate::types::{CreateAccount, UpdateAccount};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Account: SeaOrmAccountModel,
{
    pub(super) fn output_account(
        &self,
        account: &S::Account,
        db: &impl ConnectionTrait,
    ) -> AuthResult<AccountView> {
        account.record(
            &self.config().account.field_schema(),
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            db.get_database_backend() != sea_orm::DbBackend::Sqlite,
        )
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
        let input = fields.record_storage_fields_for_adapter(
            create_account.fields()?,
            true,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            S::Account::native_json_field,
        )?;
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
        let account = self.output_account(&account, db)?;
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
        let records = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
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
        .await?;
        // Upstream starts every row projection before observing an output error.
        let accounts = records
            .iter()
            .map(|record| self.output_account(record, self.connection()))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<AuthResult<Vec<_>>>()?;
        if accounts.len() > 1 {
            return Err(crate::error::AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                serde_json::to_string(provider)?
            )));
        }
        Ok(accounts.into_iter().next())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        let user_id = <S::Account as SeaOrmAccountModel>::parse_user_id(user_id)?;
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
        .await?
        .iter()
        .map(|record| self.output_account(record, self.connection()))
        .collect()
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
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
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
        let input = fields.record_storage_fields_for_adapter(
            update.fields()?,
            false,
            backend == sea_orm::DbBackend::Postgres,
            S::Account::native_json_field,
        )?;
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
        let account = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
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
        .map(|record| self.output_account(record, self.connection()))
        .transpose()?;
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
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
        // The upstream single-delete snapshot catch also covers adapter output failures.
        let snapshot: AuthResult<Option<AccountView>> = async {
            database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
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
            .map(|record| self.output_account(record, self.connection()))
            .transpose()
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
