use async_trait::async_trait;
use better_auth_core::store::AccountStore;
use better_auth_core::types::{CreateAccount, UpdateAccount};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::hooks::HookConnection;
use crate::models::{Account, AccountChanges};
use crate::schema::accounts;
use crate::sql_types::{NullableUtcTimestampValue, UtcTimestampValue};

use super::{DieselAuthSchema, DieselStore, cancelled_by_hook, new_id};

impl DieselStore {
    pub(crate) async fn insert_account<'a>(
        &'a self,
        connection: &'a HookConnection<'a>,
        mut create_account: CreateAccount,
    ) -> AuthResult<Account> {
        let hook_context = self.hook_context(connection);
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
        let row = Account {
            id: new_id(),
            account_id: create_account.account_id,
            provider_id: create_account.provider_id,
            user_id: create_account.user_id,
            access_token: create_account.access_token,
            refresh_token: create_account.refresh_token,
            id_token: create_account.id_token,
            access_token_expires_at: create_account.access_token_expires_at,
            refresh_token_expires_at: create_account.refresh_token_expires_at,
            scope: create_account.scope,
            password: create_account.password,
            created_at: now,
            updated_at: now,
        };

        let account = run_query!(lock connection, |c| {
            diesel::insert_into(accounts::table)
                .values(row)
                .returning(Account::as_returning())
                .get_result(c)
                .await
        })?;

        for hook in self.hooks() {
            hook.after_create_account(&account, &hook_context).await?;
        }
        Ok(account)
    }
}

fn account_changes(update: UpdateAccount, now: chrono::DateTime<Utc>) -> AccountChanges {
    AccountChanges {
        access_token: update.access_token,
        refresh_token: update.refresh_token,
        id_token: update.id_token,
        access_token_expires_at: update
            .access_token_expires_at
            .map(|value| NullableUtcTimestampValue(Some(value))),
        refresh_token_expires_at: update
            .refresh_token_expires_at
            .map(|value| NullableUtcTimestampValue(Some(value))),
        scope: update.scope,
        password: update.password,
        updated_at: Some(UtcTimestampValue(now)),
    }
}

#[async_trait]
impl AccountStore<DieselAuthSchema> for DieselStore {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
        self.insert_account(&HookConnection::pooled(&self.pool), create_account)
            .await
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Account>> {
        run_query!(self, |c| {
            accounts::table
                .filter(accounts::provider_id.eq(provider))
                .filter(accounts::account_id.eq(provider_account_id))
                .select(Account::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
        run_query!(self, |c| {
            accounts::table
                .filter(accounts::user_id.eq(user_id))
                .order(accounts::created_at.desc())
                .select(Account::as_select())
                .load(c)
                .await
        })
    }

    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<Account> {
        let connection = HookConnection::pooled(&self.pool);
        let hook_context = self.hook_context(&connection);
        for hook in self.hooks() {
            if hook
                .before_update_account(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account update"));
            }
        }

        let changes = account_changes(update, Utc::now());
        let account = run_query!(lock connection, |c| {
            diesel::update(accounts::table.find(id))
                .set(changes)
                .returning(Account::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .ok_or_else(|| AuthError::not_found("Account not found"))?;

        for hook in self.hooks() {
            hook.after_update_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let connection = HookConnection::pooled(&self.pool);
        let Some(account) = run_query!(lock connection, |c| {
            accounts::table
                .find(id)
                .select(Account::as_select())
                .first(c)
                .await
                .optional()
        })?
        else {
            return Err(AuthError::not_found("Account not found"));
        };
        let hook_context = self.hook_context(&connection);
        for hook in self.hooks() {
            if hook
                .before_delete_account(&account, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account deletion"));
            }
        }

        let _ = run_query!(lock connection, |c| {
            diesel::delete(accounts::table.find(id)).execute(c).await
        })?;

        for hook in self.hooks() {
            hook.after_delete_account(&account, &hook_context).await?;
        }
        Ok(())
    }
}
