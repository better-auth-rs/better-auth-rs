use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate};

#[async_trait]
impl AccountStore<StatelessSchema> for EphemeralStore {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
        self.create_account_optional(create_account)
            .await?
            .ok_or_else(|| AuthError::forbidden("account creation cancelled by database hook"))
    }

    async fn create_account_optional(
        &self,
        mut create_account: CreateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if hook
                .before_create_account(&mut create_account, &context)
                .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(None);
            }
        }
        let now = Utc::now();
        let account = AccountView {
            visible_fields: Some(
                [
                    ("accessToken", create_account.access_token.is_some()),
                    ("refreshToken", create_account.refresh_token.is_some()),
                    ("idToken", create_account.id_token.is_some()),
                    (
                        "accessTokenExpiresAt",
                        create_account.access_token_expires_at.is_some(),
                    ),
                    (
                        "refreshTokenExpiresAt",
                        create_account.refresh_token_expires_at.is_some(),
                    ),
                    ("scope", create_account.scope.is_some()),
                    ("password", create_account.password.is_some()),
                ]
                .into_iter()
                .filter(|(_, present)| *present)
                .map(|(name, _)| name.to_owned())
                .collect(),
            ),
            id: uuid::Uuid::new_v4().to_string(),
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
        let _ = self
            .lock()?
            .accounts
            .insert(account.id.clone(), account.clone());
        self.after(CommittedWrite::AccountCreated(account.clone()))
            .await?;
        Ok(Some(account))
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        Ok(self
            .lock()?
            .accounts
            .values()
            .find(|account| {
                account.provider_id == provider && account.account_id == provider_account_id
            })
            .cloned())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        Ok(self
            .lock()?
            .accounts
            .values()
            .filter(|account| account.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        self.update_account_optional(id, update)
            .await?
            .ok_or_else(|| AuthError::forbidden("account update cancelled by database hook"))
    }

    async fn update_account_optional(
        &self,
        id: &str,
        mut update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let original = update.clone();
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match hook.before_update_account(&original, &context).await? {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let account = (|| -> AuthResult<Option<AccountView>> {
            let mut state = self.lock()?;
            let Some(account) = state.accounts.get_mut(id) else {
                return Ok(None);
            };
            if let Some(access_token) = update.access_token {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("accessToken".into());
                }
                account.access_token = Some(access_token);
            }
            if let Some(refresh_token) = update.refresh_token {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("refreshToken".into());
                }
                account.refresh_token = Some(refresh_token);
            }
            if let Some(id_token) = update.id_token {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("idToken".into());
                }
                account.id_token = Some(id_token);
            }
            if let Some(access_token_expires_at) = update.access_token_expires_at {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("accessTokenExpiresAt".into());
                }
                account.access_token_expires_at = Some(access_token_expires_at);
            }
            if let Some(refresh_token_expires_at) = update.refresh_token_expires_at {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("refreshTokenExpiresAt".into());
                }
                account.refresh_token_expires_at = Some(refresh_token_expires_at);
            }
            if let Some(scope) = update.scope {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("scope".into());
                }
                account.scope = Some(scope);
            }
            if let Some(password) = update.password {
                if let Some(fields) = &mut account.visible_fields {
                    let _ = fields.insert("password".into());
                }
                account.password = Some(password);
            }
            account.updated_at = Utc::now();
            Ok(Some(account.clone()))
        })()?;
        self.after(CommittedWrite::AccountUpdated(account.clone()))
            .await?;
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let account = self.lock()?.accounts.get(id).cloned();
        let Some(account) = account else {
            return Ok(());
        };
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if hook.before_delete_account(&account, &context).await? == DatabaseHookControl::Cancel
            {
                return Ok(());
            }
        }
        let _ = self.lock()?.accounts.shift_remove(id);
        self.after(CommittedWrite::AccountDeleted(account)).await?;
        Ok(())
    }
}

impl EphemeralStore {
    pub(super) async fn delete_user_accounts_with_hooks(&self, user_id: &str) -> AuthResult<()> {
        // Upstream catches only the deletion snapshot read; hook and write failures still propagate.
        let accounts = self.get_user_accounts(user_id).await.unwrap_or_default();
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for account in &accounts {
            for hook in &self.hooks {
                if hook.before_delete_account(account, &context).await?
                    == DatabaseHookControl::Cancel
                {
                    return Ok(());
                }
            }
        }
        self.lock()?
            .accounts
            .retain(|_, row| row.user_id != user_id);
        for account in accounts {
            self.after(CommittedWrite::AccountDeleted(account)).await?;
        }
        Ok(())
    }
}
