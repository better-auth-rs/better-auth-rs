use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate, DatabaseUpdateResult};
use crate::store::schema::EntityRole;

impl EphemeralStore {
    fn account_field_selector(
        &self,
        fields: &crate::user_fields::UserConfig,
        name: &str,
        value: Value,
    ) -> AuthResult<(String, Value)> {
        if name == "id" {
            return Ok(("id".into(), self.memory_primary_id_query(&value)?));
        }
        let value = self.memory_field_query(fields, name, value)?;
        let value = match fields.fields().get(name) {
            Some(field) => crate::user_query::bind_filter(field, &value)?,
            None => value,
        };
        Ok((fields.record_storage_key(name).to_owned(), value))
    }

    fn account_matches_selectors(record: &FieldMap, selectors: &[(String, Value)]) -> bool {
        selectors.iter().all(|(field, expected)| {
            crate::query::field_matches_equality(
                record.get(field).unwrap_or(&Value::Undefined),
                expected,
            )
        })
    }

    pub(super) async fn account_records(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Vec<FieldMap>> {
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let fields = self.config.account.field_schema();
        let selectors = [
            self.account_field_selector(&fields, "providerId", provider.into())?,
            self.account_field_selector(&fields, "accountId", account_id.into())?,
        ];
        self.raw("account", "findMany", |state| {
            Ok(state
                .accounts
                .snapshot()?
                .iter()
                .filter(|record| Self::account_matches_selectors(record, &selectors))
                .take(2)
                .cloned()
                .collect::<Vec<_>>())
        })
        .await
    }

    async fn user_account_records(&self, user_id: &Value) -> AuthResult<Vec<FieldMap>> {
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let fields = self.config.account.field_schema();
        let selectors = [self.account_field_selector(&fields, "userId", user_id.clone())?];
        let records: Vec<_> = self
            .raw("account", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .accounts
                        .snapshot()?
                        .iter()
                        .filter(|record| Self::account_matches_selectors(record, &selectors))
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
        records: &[FieldMap],
    ) -> AuthResult<Vec<AccountView>> {
        if !records.is_empty() {
            self.model_fields.canonicalize_id(EntityRole::Account)?;
        }
        Ok(self
            .config
            .account
            .field_schema()
            .project_memory_records(records)
            .await?
            .into_iter()
            .map(AccountView::from_adapter_fields)
            .collect())
    }

    pub(super) async fn output_account(&self, record: &FieldMap) -> AuthResult<AccountView> {
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        Ok(AccountView::from_adapter_fields(
            self.config
                .account
                .field_schema()
                .project_memory_records(std::slice::from_ref(record))
                .await?
                .remove(0),
        ))
    }
}

#[async_trait]
impl AccountStore<StatelessSchema> for EphemeralStore {
    async fn create_account(&self, input: CreateAccount) -> AuthResult<AccountView> {
        self.create_account_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("account creation returned no record"))
    }

    async fn create_account_optional(
        &self,
        input: CreateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let mut input = input.with_timestamps(Utc::now().into());
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
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let mut fields = self
            .config
            .account
            .field_schema()
            .record_storage_fields_with_binding(input.fields()?, true, |_, field, value| {
                self.memory_plugin_field_input(field, value)
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
            if let Some(id) = self.next_serial_id(state.accounts.len()) {
                let _ = fields.insert("id".into(), id);
            }
            state.accounts.push(fields.clone());
            Ok(())
        })
        .await?;
        // The input is durable before output transformation; output errors suppress only later after hooks.
        let account = self.output_account(&fields).await?;
        self.after(CommittedWrite::AccountCreated(Some(account.clone())))
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
        let relation = crate::store::AccountOwner::resolve_schema(
            &self.config,
            &self.model_fields,
            |_, _| false,
        )?;
        self.account_owner_relation(provider, account_id, &relation)
            .await
    }

    async fn get_credential_account(&self, user_id: &str) -> AuthResult<Option<AccountView>> {
        self.get_credential_account_value(&user_id.into()).await
    }

    async fn get_credential_account_value(
        &self,
        user_id: &Value,
    ) -> AuthResult<Option<AccountView>> {
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let fields = self.config.account.field_schema();
        let selectors = [
            self.account_field_selector(&fields, "userId", user_id.clone())?,
            self.account_field_selector(&fields, "providerId", "credential".into())?,
            self.account_field_selector(&fields, "accountId", user_id.clone())?,
        ];
        let record = self
            .raw("account", "findOne", |state| {
                Ok(state
                    .accounts
                    .snapshot()?
                    .into_iter()
                    .find(|record| Self::account_matches_selectors(record, &selectors)))
            })
            .await?;
        match record {
            Some(record) => self.output_account(&record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        self.get_user_accounts_value(&user_id.into()).await
    }

    async fn get_user_accounts_value(&self, user_id: &Value) -> AuthResult<Vec<AccountView>> {
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
        update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        self.update_account_by_id_value(&id.into(), update).await
    }

    async fn update_account_by_id_value(
        &self,
        id: &Value,
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
        self.model_fields.canonicalize_id(EntityRole::Account)?;
        let id = self.memory_primary_id_query(id)?;
        let patch = self
            .config
            .account
            .field_schema()
            .record_storage_fields_with_binding(update.fields()?, false, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        let record = self
            .raw("account", "update", |state| {
                Ok({
                    if let Some(mut fields) = state.accounts.find_mut(|row| {
                        crate::query::field_matches_equality(
                            row.get("id").unwrap_or(&Value::Undefined),
                            &id,
                        )
                    })? {
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
        self.after(CommittedWrite::AccountUpdated(DatabaseUpdateResult::One(
            account.clone(),
        )))
        .await?;
        Ok(account)
    }

    async fn update_accounts(
        &self,
        selectors: &FieldMap,
        mut update: UpdateAccount,
    ) -> AuthResult<Option<u64>> {
        let original = update.clone();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match crate::observability::database::with_database_update_many_hook(
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
        crate::store::database_hooks::await_adapter_lookup().await;
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let fields = self.config.account.field_schema();
        let selectors = selectors
            .iter()
            .map(|(name, value)| self.account_field_selector(&fields, name, value.clone()))
            .collect::<AuthResult<Vec<_>>>()?;
        let patch = fields
            .record_storage_fields_with_binding(update.fields()?, false, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        let count = self
            .raw("account", "updateMany", |state| {
                let mut count = 0;
                state.accounts.update_each(|row| {
                    if Self::account_matches_selectors(row, &selectors) {
                        row.extend(patch.clone());
                        count += 1;
                    }
                    Ok(())
                })?;
                Ok(count)
            })
            .await?;
        self.after(CommittedWrite::AccountUpdated(DatabaseUpdateResult::Many(
            count,
        )))
        .await?;
        Ok(Some(count))
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.delete_account_value(&id.into()).await
    }

    async fn delete_user_accounts_value(&self, user_id: &Value) -> AuthResult<()> {
        self.delete_user_accounts_with_hooks(user_id).await
    }

    async fn delete_account_value(&self, id: &Value) -> AuthResult<()> {
        // Upstream single-delete catches the read and output projection before hooks and writes.
        let snapshot: AuthResult<Option<AccountView>> = async {
            self.model_fields.begin_id_query(EntityRole::Account)?;
            let id = self.memory_primary_id_query(id)?;
            let record = self
                .raw("account", "findMany", |state| {
                    Ok(state.accounts.snapshot()?.into_iter().find(|row| {
                        row.get("id")
                            .unwrap_or(&Value::Undefined)
                            .strict_equals(&id)
                    }))
                })
                .await?;
            match record {
                Some(record) => self.output_account(&record).await.map(Some),
                None => Ok(None),
            }
        }
        .await;
        let Ok(Some(account)) = snapshot else {
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
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let id = self.memory_primary_id_query(id)?;
        self.raw("account", "delete", |state| {
            let _ = state.accounts.remove_first(|row| {
                row.get("id")
                    .unwrap_or(&Value::Undefined)
                    .strict_equals(&id)
            })?;
            Ok(())
        })
        .await?;
        self.after(CommittedWrite::AccountDeleted(account)).await
    }
}

impl EphemeralStore {
    pub(super) async fn delete_user_accounts_with_hooks(&self, user_id: &Value) -> AuthResult<()> {
        // Upstream catches only the batch snapshot; the matching database deletion still runs.
        let accounts = self
            .get_user_accounts_value(user_id)
            .await
            .unwrap_or_default();
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
        self.model_fields.begin_id_query(EntityRole::Account)?;
        let schema = self.config.account.field_schema();
        let selectors = [self.account_field_selector(&schema, "userId", user_id.clone())?];
        self.raw("account", "deleteMany", |state| {
            state
                .accounts
                .retain(|record| !Self::account_matches_selectors(record, &selectors))?;
            Ok(())
        })
        .await?;
        for account in accounts {
            self.after(CommittedWrite::AccountDeleted(account)).await?;
        }
        Ok(())
    }
}
