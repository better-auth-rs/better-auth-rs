use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate};

impl EphemeralStore {
    async fn account_records(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Vec<serde_json::Map<String, Value>>> {
        let fields = self.config.account.field_schema();
        let provider =
            self.memory_field_query(&fields, "providerId", Value::String(provider.to_owned()))?;
        let account_id =
            self.memory_field_query(&fields, "accountId", Value::String(account_id.to_owned()))?;
        self.raw("account", "findMany", |state| {
            Ok(state
                .accounts
                .snapshot()?
                .iter()
                .filter(|record| {
                    record.get(fields.record_storage_key("providerId")) == Some(&provider)
                        && record.get(fields.record_storage_key("accountId")) == Some(&account_id)
                })
                .take(2)
                .cloned()
                .collect::<Vec<_>>())
        })
        .await
    }

    pub(super) async fn user_account_records(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<Map<String, Value>>> {
        let fields = self.config.account.field_schema();
        let user_id =
            self.memory_field_query(&fields, "userId", Value::String(user_id.to_owned()))?;
        let records: Vec<_> = self
            .raw("account", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .accounts
                        .snapshot()?
                        .iter()
                        .filter(|record| {
                            record.get(fields.record_storage_key("userId")) == Some(&user_id)
                        })
                        .cloned()
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        Ok(records)
    }

    pub(super) async fn output_accounts(
        &self,
        records: &[Map<String, Value>],
    ) -> AuthResult<Vec<AccountView>> {
        Ok(self
            .config
            .account
            .field_schema()
            .project_records(records, true, true)
            .await?
            .into_iter()
            .map(AccountView::from_adapter_fields)
            .collect())
    }

    pub(super) async fn output_account(
        &self,
        record: &Map<String, Value>,
    ) -> AuthResult<AccountView> {
        Ok(AccountView::from_adapter_fields(
            self.config
                .account
                .field_schema()
                .project_record(record, true, true)
                .await?,
        ))
    }
}

#[async_trait]
impl AccountStore<StatelessSchema> for EphemeralStore {
    async fn create_account(&self, input: CreateAccount) -> AuthResult<AccountView> {
        self.create_account_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("account creation cancelled by database hook"))
    }

    async fn create_account_optional(
        &self,
        input: CreateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let mut input = input.with_timestamps(Utc::now());
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateAccount,
                hook.before_create_account(&mut input, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(None);
            }
        }
        let mut fields = self
            .config
            .account
            .field_schema()
            .record_storage_fields_with_binding(input.fields()?, true, |_, field, value| {
                self.memory_record_input(field, value)
            })
            .await?;
        let supplied = fields
            .remove("id")
            .and_then(|id| id.as_str().map(str::to_owned));
        let id = self.generated_id("account", supplied, self.lock()?.accounts.len())?;
        if let Some(id) = id {
            let _ = fields.insert("id".into(), Value::String(id));
        }
        self.raw("account", "create", |state| {
            state.accounts.push(fields.clone());
            Ok(())
        })
        .await?;
        // The input is durable before output transformation; output errors suppress only later after hooks.
        let account = self.output_account(&fields).await?;
        self.after(CommittedWrite::AccountCreated(account.clone()))
            .await?;
        Ok(Some(account))
    }

    async fn get_account(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        let records = self.account_records(provider, account_id).await?;
        let accounts = self.output_accounts(&records).await?;
        if accounts.len() > 1 {
            return Err(AuthError::internal(format!(
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
    ) -> AuthResult<Option<crate::store::AccountOwner>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_account_owner(provider, account_id).await;
        }
        let fields = self.config.account.field_schema();
        let records = self.account_records(provider, account_id).await?;
        let owner_ids: Vec<_> = records
            .iter()
            .map(|record| record.get(fields.record_storage_key("userId")).cloned())
            .collect();
        let owners = fields
            .project_records_batches_then(&records, true, true, |ready| {
                let owner_ids = &owner_ids;
                async move {
                    let mut pending = Vec::new();
                    let mut users = Vec::new();
                    for (index, output) in ready {
                        let owner_id = owner_ids.get(index).ok_or_else(|| {
                            AuthError::internal("Account projection lost its stored owner index")
                        })?;
                        let stored_owner_id = self.stored_account_owner_id(owner_id.clone())?;
                        let user = match owner_id {
                            Some(id) if !id.is_null() => self.user_ref_by_id_value(id).await?,
                            _ => None,
                        };
                        let has_user = user.is_some();
                        users.extend(user);
                        pending.push((index, output, stored_owner_id, has_user));
                    }
                    let mut users = self.output_user_refs(users).await?.into_iter();
                    pending
                        .into_iter()
                        .map(|(index, output, stored_owner_id, has_user)| {
                            crate::store::AccountOwner::new(
                                AccountView::from_adapter_fields(output),
                                if has_user { users.next() } else { None },
                                &stored_owner_id,
                            )
                            .map(|owner| (index, owner))
                        })
                        .collect()
                }
            })
            .await?;
        if owners.len() > 1 {
            return Err(AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                serde_json::to_string(provider)?
            )));
        }
        Ok(owners.into_iter().next())
    }

    async fn get_credential_account(&self, user_id: &str) -> AuthResult<Option<AccountView>> {
        let fields = self.config.account.field_schema();
        let account_id =
            self.memory_field_query(&fields, "accountId", Value::String(user_id.to_owned()))?;
        let user_id =
            self.memory_field_query(&fields, "userId", Value::String(user_id.to_owned()))?;
        let provider = self.memory_field_query(
            &fields,
            "providerId",
            Value::String("credential".to_owned()),
        )?;
        let record = self
            .raw("account", "findOne", |state| {
                Ok(state.accounts.snapshot()?.into_iter().find(|record| {
                    record.get(fields.record_storage_key("userId")) == Some(&user_id)
                        && record.get(fields.record_storage_key("providerId")) == Some(&provider)
                        && record.get(fields.record_storage_key("accountId")) == Some(&account_id)
                }))
            })
            .await?;
        match record {
            Some(record) => self.output_account(&record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        self.output_accounts(&self.user_account_records(user_id).await?)
            .await
    }

    async fn update_account(&self, id: &str, input: UpdateAccount) -> AuthResult<AccountView> {
        self.update_account_optional(id, input)
            .await?
            .ok_or_else(|| AuthError::forbidden("account update cancelled by database hook"))
    }

    async fn update_account_optional(
        &self,
        id: &str,
        mut update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let original = update.clone();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateAccount,
                hook.before_update_account(&original, &context),
            )
            .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let patch = self
            .config
            .account
            .field_schema()
            .record_storage_fields_with_binding(update.fields()?, false, |_, field, value| {
                self.memory_record_input(field, value)
            })
            .await?;
        let record = self
            .raw("account", "update", |state| {
                Ok({
                    if let Some(mut fields) = state
                        .accounts
                        .find_mut(|row| row.get("id").and_then(Value::as_str) == Some(id))?
                    {
                        fields.extend(patch);
                        Some(fields.clone())
                    } else {
                        None
                    }
                })
            })
            .await?;
        let account = futures_util::future::OptionFuture::from(
            record.as_ref().map(|record| self.output_account(record)),
        )
        .await
        .transpose()?;
        self.after(CommittedWrite::AccountUpdated(account.clone()))
            .await?;
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let record = self
            .raw("account", "findOne", |state| {
                Ok(state
                    .accounts
                    .snapshot()?
                    .iter()
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
                    .cloned())
            })
            .await?;
        // Upstream single-delete catches the read and output projection before hooks and writes.
        let Some(account) = (match record {
            Some(record) => self.output_account(&record).await.ok(),
            None => None,
        }) else {
            return Ok(());
        };
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeDeleteAccount,
                hook.before_delete_account(&account, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(());
            }
        }
        self.raw("account", "delete", |state| {
            let _ = state
                .accounts
                .remove_first(|row| row.get("id").and_then(Value::as_str) == Some(id))?;
            Ok(())
        })
        .await?;
        self.after(CommittedWrite::AccountDeleted(account)).await
    }
}

impl EphemeralStore {
    pub(super) async fn delete_user_accounts_with_hooks(&self, user_id: &str) -> AuthResult<()> {
        // Upstream catches only the batch snapshot; the matching database deletion still runs.
        let accounts = self.get_user_accounts(user_id).await.unwrap_or_default();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for account in &accounts {
            for hook in &self.hooks {
                if crate::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    crate::observability::database::DatabaseHook::BeforeDeleteAccount,
                    hook.before_delete_account(account, &context),
                )
                .await?
                    == DatabaseHookControl::Cancel
                {
                    return Ok(());
                }
            }
        }
        let schema = self.config.account.field_schema();
        let user_id =
            self.memory_field_query(&schema, "userId", Value::String(user_id.to_owned()))?;
        self.raw("account", "deleteMany", |state| {
            state.accounts.retain(|record| {
                record.get(schema.record_storage_key("userId")) != Some(&user_id)
            })?;
            Ok(())
        })
        .await?;
        for account in accounts {
            self.after(CommittedWrite::AccountDeleted(account)).await?;
        }
        Ok(())
    }
}
