use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder,
};

use better_auth_core::store::AccountStore;

use crate::error::AuthResult;
use crate::schema::{AuthSchema, SeaOrmAccountModel};
use crate::types::{CreateAccount, UpdateAccount};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Account: SeaOrmAccountModel,
{
    async fn create_account_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_account: CreateAccount,
    ) -> AuthResult<S::Account>
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
                return Err(cancelled_by_hook("account creation"));
            }
        }
        let now = Utc::now();
        let account = S::Account::new_active(None, create_account, now)
            .insert(db)
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    pub(crate) async fn create_account_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_account: CreateAccount,
    ) -> AuthResult<S::Account> {
        self.create_account_with_connection(tx, Some(tx), create_account)
            .await
    }
}

#[async_trait]
impl<S> AccountStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Account: SeaOrmAccountModel,
{
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
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

    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<S::Account> {
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_account(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account update"));
            }
        }
        let Some(model) = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active_model();
        S::Account::apply_update(&mut active, update, Utc::now());

        let account = active.update(self.connection()).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_account(&account, &hook_context).await?;
        }
        Ok(account)
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
