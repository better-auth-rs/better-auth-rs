use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::types::{Account, CreateAccount, UpdateAccount};

use super::entities::account::{ActiveModel, Column, Entity};
use super::{AuthStore, cancelled_by_hook, map_db_err};

impl AuthStore {
    async fn create_account_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_account: CreateAccount,
    ) -> AuthResult<Account>
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
        let account = ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            account_id: Set(create_account.account_id),
            provider_id: Set(create_account.provider_id),
            user_id: Set(create_account.user_id),
            access_token: Set(create_account.access_token),
            refresh_token: Set(create_account.refresh_token),
            id_token: Set(create_account.id_token),
            access_token_expires_at: Set(create_account.access_token_expires_at),
            refresh_token_expires_at: Set(create_account.refresh_token_expires_at),
            scope: Set(create_account.scope),
            password: Set(create_account.password),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await
        .map(Account::from)
        .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    pub async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
        self.create_account_with_connection(self.connection(), None, create_account)
            .await
    }

    /// Create an account inside an existing transaction.
    #[doc(hidden)]
    pub async fn create_account_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_account: CreateAccount,
    ) -> AuthResult<Account> {
        self.create_account_with_connection(tx, Some(tx), create_account)
            .await
    }

    pub async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Account>> {
        Entity::find()
            .filter(Column::ProviderId.eq(provider))
            .filter(Column::AccountId.eq(provider_account_id))
            .one(self.connection())
            .await
            .map(|model| model.map(Account::from))
            .map_err(map_db_err)
    }

    pub async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Account::from).collect())
            .map_err(map_db_err)
    }

    pub async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<Account> {
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
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active_model();
        if let Some(access_token) = update.access_token {
            active.access_token = Set(Some(access_token));
        }
        if let Some(refresh_token) = update.refresh_token {
            active.refresh_token = Set(Some(refresh_token));
        }
        if let Some(id_token) = update.id_token {
            active.id_token = Set(Some(id_token));
        }
        if let Some(expires_at) = update.access_token_expires_at {
            active.access_token_expires_at = Set(Some(expires_at));
        }
        if let Some(expires_at) = update.refresh_token_expires_at {
            active.refresh_token_expires_at = Set(Some(expires_at));
        }
        if let Some(scope) = update.scope {
            active.scope = Set(Some(scope));
        }
        if let Some(password) = update.password {
            active.password = Set(Some(password));
        }
        active.updated_at = Set(Utc::now());

        let account = active
            .update(self.connection())
            .await
            .map(Account::from)
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    pub async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let Some(account) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(Account::from)
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_account(&account, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account deletion"));
            }
        }
        let _ = Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_account(&account, &hook_context).await?;
        }
        Ok(())
    }
}
