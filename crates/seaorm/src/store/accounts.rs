use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder,
};

use better_auth_core::store::AccountStore;

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
    async fn create_account_with_connection<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut create_account: CreateAccount,
    ) -> AuthResult<Option<S::Account>>
    where
        C: ConnectionTrait,
    {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_account(&mut create_account, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
        }
        let now = Utc::now();
        let account = S::Account::new_active(None, create_account, now)
            .insert(db)
            .await
            .map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_account(&account, &hook_context).await?;
            }
        }
        Ok(Some(account))
    }

    pub(crate) async fn create_account_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_account: CreateAccount,
    ) -> AuthResult<S::Account> {
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
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        self.create_account_optional(create_account)
            .await?
            .ok_or_else(|| cancelled_by_hook("account creation"))
    }

    async fn create_account_optional(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<Option<S::Account>> {
        self.create_account_with_connection(self.connection(), None, create_account)
            .await
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::provider_id_column().eq(provider))
            .filter(<S::Account as SeaOrmAccountModel>::account_id_column().eq(provider_account_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        let user_id = <S::Account as SeaOrmAccountModel>::parse_user_id(user_id)?;
        <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::user_id_column().eq(user_id))
            .order_by_desc(<S::Account as SeaOrmAccountModel>::created_at_column())
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account> {
        self.update_account_optional(id, update)
            .await?
            .ok_or_else(|| cancelled_by_hook("account update"))
    }

    async fn update_account_optional(
        &self,
        id: &str,
        mut update: UpdateAccount,
    ) -> AuthResult<Option<S::Account>> {
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
        let hook_context = self.hook_context(None);
        let original = update.clone();
        for hook in self.hooks() {
            match hook
                .before_update_account(id, &original, &hook_context)
                .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let Some(model) = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            for hook in self.hooks() {
                hook.after_update_account(None, &hook_context).await?;
            }
            return Ok(None);
        };

        let mut active = model.into_active_model();
        S::Account::apply_update(&mut active, update, Utc::now());

        let account = active.update(self.connection()).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_account(Some(&account), &hook_context)
                .await?;
        }
        Ok(Some(account))
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
        let Some(account_model) = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id.clone()))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_account(&account_model, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account deletion"));
            }
        }
        let _ = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_account(&account_model, &hook_context)
                .await?;
        }
        Ok(())
    }
}
