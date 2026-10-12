use super::hooks::CommittedWrite;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseUpdateResult};
use crate::store::schema::EntityRole;

impl EphemeralStore {
    async fn account_storage_fields(&self, input: FieldMap, create: bool) -> AuthResult<FieldMap> {
        let force_allow_id = create && input.contains_key("id");
        super::raw_records::MemoryRecordModel::new(
            self,
            EntityRole::Account,
            self.field_policy().account(),
        )
        .prepare(input.into(), create, force_allow_id)
        .await
    }

    pub(super) fn account_matches_selectors(
        record: &RowRef<FieldMap>,
        selectors: &[(String, Value)],
    ) -> AuthResult<bool> {
        crate::memory_query::matches_all(selectors.iter(), |(field, expected)| {
            Ok(crate::query::field_matches_equality(
                &record.field(field)?.unwrap_or_default(),
                expected,
            ))
        })
    }

    pub(super) fn account_identity_selectors(
        &self,
        provider: &Value,
        account_id: &Value,
    ) -> AuthResult<[(String, Value); 2]> {
        let fields = self.field_policy().account();
        Ok([
            self.memory_query_field(EntityRole::Account, &fields, "providerId", provider.clone())?,
            self.memory_query_field(
                EntityRole::Account,
                &fields,
                "accountId",
                account_id.clone(),
            )?,
        ])
    }

    pub(super) async fn account_records(
        &self,
        provider: &Value,
        account_id: &Value,
    ) -> AuthResult<Vec<RecordSource>> {
        let selectors = self.account_identity_selectors(provider, account_id)?;
        self.raw("account", "findMany", |op| {
            Ok(op
                .capture_table(EntityRole::Account)?
                .select_refs(|record| Self::account_matches_selectors(record, &selectors))?
                .into_iter()
                .take(2)
                .map(RecordSource::Live)
                .collect::<Vec<_>>())
        })
        .await
    }

    async fn user_account_records(&self, user_id: &Value) -> AuthResult<Vec<RecordSource>> {
        let fields = self.field_policy().account();
        let selectors =
            [self.memory_query_field(EntityRole::Account, &fields, "userId", user_id.clone())?];
        let records: Vec<_> = self
            .raw("account", "findMany", |op| {
                Ok(crate::query::paginate_memory(
                    op.capture_table(EntityRole::Account)?
                        .select_refs(|record| Self::account_matches_selectors(record, &selectors))?
                        .into_iter()
                        .map(RecordSource::Live)
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
        records: Vec<RecordSource>,
    ) -> AuthResult<Vec<AccountView>> {
        Ok(self
            .project_record_sources(EntityRole::Account, &self.field_policy().account(), records)
            .await?
            .into_iter()
            .map(AccountView::from_adapter_fields)
            .collect())
    }

    pub(super) async fn output_account(&self, record: RecordSource) -> AuthResult<AccountView> {
        Ok(self.output_accounts(vec![record]).await?.remove(0))
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
        let mut fields = self.account_storage_fields(input.fields()?, true).await?;
        let record = self
            .raw("account", "create", |op| {
                let table = op.create_table(EntityRole::Account)?;
                if let Some(id) = self.next_serial_id(table.len()?) {
                    let _ = fields.insert("id".into(), id);
                }
                table.push(fields)
            })
            .await?;
        // The input is durable before output transformation; output errors suppress only later after hooks.
        let account = self.output_account(RecordSource::Live(record)).await?;
        self.after(CommittedWrite::AccountCreated(Some(account.clone())))
            .await?;
        Ok(Some(account))
    }

    async fn get_account(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        self.get_account_value(&provider.into(), &account_id.into())
            .await
    }

    async fn get_account_value(
        &self,
        provider: &Value,
        account_id: &Value,
    ) -> AuthResult<Option<AccountView>> {
        let records = self.account_records(provider, account_id).await?;
        let accounts = self.output_accounts(records).await?;
        if accounts.len() > 1 {
            return Err(AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                provider.stringify()?.unwrap_or_else(|| "undefined".into())
            )));
        }
        Ok(accounts.into_iter().next())
    }

    async fn get_account_owner(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<crate::store::AccountOwner>> {
        self.get_account_owner_value(&provider.into(), &account_id.into())
            .await
    }

    async fn get_account_owner_value(
        &self,
        provider: &Value,
        account_id: &Value,
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
        let fields = self.field_policy().account();
        let selectors = [
            self.memory_query_field(EntityRole::Account, &fields, "userId", user_id.clone())?,
            self.memory_query_field(
                EntityRole::Account,
                &fields,
                "providerId",
                "credential".into(),
            )?,
            self.memory_query_field(EntityRole::Account, &fields, "accountId", user_id.clone())?,
        ];
        let record = self
            .raw("account", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Account)?
                    .select_refs(|record| Self::account_matches_selectors(record, &selectors))?
                    .into_iter()
                    .next())
            })
            .await?;
        match record {
            Some(record) => self
                .output_account(RecordSource::Live(record))
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        self.get_user_accounts_value(&user_id.into()).await
    }

    async fn get_user_accounts_value(&self, user_id: &Value) -> AuthResult<Vec<AccountView>> {
        self.output_accounts(self.user_account_records(user_id).await?)
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
        update: UpdateAccount,
    ) -> AuthResult<Option<AccountView>> {
        let mut prepared = crate::store::database_hooks::PreparedRecordWrite::new(update.fields()?);
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateAccount,
                hook.before_update_account(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        crate::store::database_hooks::await_adapter_lookup().await;
        let (column, id) = self.memory_query_field(
            EntityRole::Account,
            &self.field_policy().account(),
            "id",
            id.clone(),
        )?;
        let patch = self
            .account_storage_fields(prepared.into_fields(), false)
            .await?;
        let record = self
            .raw("account", "update", |op| {
                let records = op.capture_table(EntityRole::Account)?.select_refs(|row| {
                    Ok(crate::query::field_matches_equality(
                        &row.field(&column)?.unwrap_or_default(),
                        &id,
                    ))
                })?;
                for record in &records {
                    record.apply_patch(patch.clone())?;
                }
                Ok(records.into_iter().next())
            })
            .await?;
        let account = futures_util::future::OptionFuture::from(
            record.map(|record| self.output_account(RecordSource::Live(record))),
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
        update: UpdateAccount,
    ) -> AuthResult<Option<u64>> {
        let mut prepared = crate::store::database_hooks::PreparedRecordWrite::new(update.fields()?);
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_update_many_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateAccount,
                hook.before_update_account(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        crate::store::database_hooks::await_adapter_lookup().await;
        let fields = self.field_policy().account();
        let selectors = selectors
            .iter()
            .map(|(name, value)| {
                self.memory_query_field(EntityRole::Account, &fields, name, value.clone())
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let patch = self
            .account_storage_fields(prepared.into_fields(), false)
            .await?;
        let count = self
            .raw("account", "updateMany", |op| {
                let rows = op
                    .capture_table(EntityRole::Account)?
                    .select_refs(|row| Self::account_matches_selectors(row, &selectors))?;
                for row in &rows {
                    row.apply_patch(patch.clone())?;
                }
                Ok(rows.len() as u64)
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
            let (column, id) = self.memory_query_field(
                EntityRole::Account,
                &self.field_policy().account(),
                "id",
                id.clone(),
            )?;
            let record = self
                .raw("account", "findMany", |op| {
                    Ok(op
                        .capture_table(EntityRole::Account)?
                        .select_refs(|row| {
                            Ok(crate::query::field_matches_equality(
                                &row.field(&column)?.unwrap_or_default(),
                                &id,
                            ))
                        })?
                        .into_iter()
                        .next())
                })
                .await?;
            match record {
                Some(record) => self
                    .output_account(RecordSource::Live(record))
                    .await
                    .map(Some),
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
        crate::store::database_hooks::await_adapter_lookup().await;
        let (column, id) = self.memory_query_field(
            EntityRole::Account,
            &self.field_policy().account(),
            "id",
            id.clone(),
        )?;
        self.raw("account", "delete", |op| {
            let table = op.capture_table(EntityRole::Account)?;
            let selected = table.select_refs(|row| {
                Ok(crate::query::field_matches_equality(
                    &row.field(&column)?.unwrap_or_default(),
                    &id,
                ))
            })?;
            op.replace_table(EntityRole::Account, table.without_refs(&selected)?)
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
        let schema = self.field_policy().account();
        let selectors =
            [self.memory_query_field(EntityRole::Account, &schema, "userId", user_id.clone())?];
        self.raw("account", "deleteMany", |op| {
            let table = op.capture_table(EntityRole::Account)?;
            let selected =
                table.select_refs(|record| Self::account_matches_selectors(record, &selectors))?;
            op.replace_table(EntityRole::Account, table.without_refs(&selected)?)
        })
        .await?;
        for account in accounts {
            self.after(CommittedWrite::AccountDeleted(account)).await?;
        }
        Ok(())
    }
}
