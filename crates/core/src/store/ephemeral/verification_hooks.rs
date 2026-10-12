use super::hooks::CommittedWrite;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, PreparedRecordWrite, VerificationUpdate};
use crate::store::schema::EntityRole;

impl EphemeralStore {
    pub(super) async fn update_verification_with_hooks(
        &self,
        identifier: &str,
        update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        let mut prepared = PreparedRecordWrite::new(update.fields()?);
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateVerification,
                hook.before_update_verification(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        crate::store::database_hooks::await_adapter_lookup().await;
        let (identifier_column, bound_identifier) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "identifier",
            identifier.into(),
        )?;
        let patch = self
            .verification_storage_fields(prepared.into_fields(), false)
            .await?;
        let record = self
            .raw("verification", "update", |op| {
                let rows = op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        Ok(row
                            .field(&identifier_column)?
                            .unwrap_or_default()
                            .strict_equals(&bound_identifier))
                    })?;
                for row in &rows {
                    row.apply_patch(patch.clone())?;
                }
                Ok(rows.into_iter().next())
            })
            .await?;
        let record = futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
        )
        .await
        .transpose()?;
        self.after(CommittedWrite::VerificationUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    pub(super) async fn delete_verifications_with_hooks<P>(
        &self,
        bind: impl Fn() -> AuthResult<P> + Send + Sync,
        many: bool,
    ) -> AuthResult<usize>
    where
        P: Fn(&RowRef<FieldMap>) -> AuthResult<bool> + Send + Sync,
    {
        let predicate = bind()?;
        let rows: Vec<_> = self
            .raw("verification", "findMany", |op| {
                let matched = op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(&predicate)?;
                Ok(crate::query::paginate_memory(
                    matched,
                    Some(if many {
                        self.config.advanced.database.find_many_limit()
                    } else {
                        1.0
                    }),
                    None,
                ))
            })
            .await?;
        self.finish_verification_delete(rows, bind, many).await
    }

    pub(super) async fn finish_verification_delete<P>(
        &self,
        rows: Vec<RowRef<FieldMap>>,
        bind: impl FnOnce() -> AuthResult<P> + Send,
        many: bool,
    ) -> AuthResult<usize>
    where
        P: Fn(&RowRef<FieldMap>) -> AuthResult<bool> + Send + Sync,
    {
        // Single and batch delete both catch snapshot output errors; only batch still deletes on an empty snapshot.
        let rows = self
            .output_verifications(rows.into_iter().map(RecordSource::Live).collect())
            .await
            .unwrap_or_default();
        if !many && rows.is_empty() {
            return Ok(0);
        }
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for row in &rows {
            for hook in &self.hooks {
                if crate::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    crate::observability::database::DatabaseHook::BeforeDeleteVerification,
                    hook.before_delete_verification(row, &context),
                )
                .await?
                    == DatabaseHookControl::Cancel
                {
                    return Ok(0);
                }
            }
        }
        crate::store::database_hooks::await_adapter_lookup().await;
        let predicate = bind()?;
        let count = self
            .raw(
                "verification",
                if many { "deleteMany" } else { "delete" },
                |op| {
                    let table = op.capture_table(EntityRole::Verification)?;
                    let selected = table.select_refs(&predicate)?;
                    op.replace_table(EntityRole::Verification, table.without_refs(&selected)?)?;
                    Ok(selected.len())
                },
            )
            .await?;
        for row in rows {
            self.after(CommittedWrite::VerificationDeleted(row)).await?;
        }
        Ok(count)
    }

    async fn consume_verification_inner(
        &self,
        identifier: &str,
        value: Option<&str>,
    ) -> AuthResult<Option<VerificationView>> {
        let Some(record) = self.latest_verification_record(identifier).await? else {
            return Ok(None);
        };
        let snapshot = self.output_verification(RecordSource::Live(record)).await?;
        if value.is_some_and(|value| snapshot.value != value) {
            return Ok(None);
        }
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeDeleteVerification,
                hook.before_delete_verification(&snapshot, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(None);
            }
        }
        let (id_column, id) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "id",
            snapshot.id.field_value(),
        )?;
        let Some(consumed) = self
            .raw("verification", "consumeOne", |op| {
                let table = op.capture_table(EntityRole::Verification)?;
                let selected = table.select_refs(|row| {
                    Ok(row
                        .field(&id_column)?
                        .unwrap_or_default()
                        .strict_equals(&id))
                })?;
                let selected = selected.into_iter().next();
                if let Some(row) = &selected {
                    op.replace_table(
                        EntityRole::Verification,
                        table.without_refs(std::slice::from_ref(row))?,
                    )?;
                }
                Ok(selected)
            })
            .await?
        else {
            return Ok(None);
        };
        let consumed = self
            .output_verification(RecordSource::Live(consumed))
            .await?;
        let (identifier_column, bound_identifier) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "identifier",
            identifier.into(),
        )?;
        self.raw("verification", "deleteMany", |op| {
            let table = op.capture_table(EntityRole::Verification)?;
            let selected = table.select_refs(|row| {
                Ok(row
                    .field(&identifier_column)?
                    .unwrap_or_default()
                    .strict_equals(&bound_identifier))
            })?;
            op.replace_table(EntityRole::Verification, table.without_refs(&selected)?)
        })
        .await?;
        self.after(CommittedWrite::VerificationDeleted(consumed.clone()))
            .await?;
        Ok(Some(consumed))
    }

    pub(super) async fn consume_verification_with_hooks(
        &self,
        identifier: &str,
        value: Option<&str>,
    ) -> AuthResult<Option<VerificationView>> {
        let lock = self.verification_lock(format!("verification:{identifier}"))?;
        let _guard = lock.lock().await;
        if self.pending_hooks.is_some() {
            return self.consume_verification_inner(identifier, value).await;
        }
        let (base, isolated, queue) = self.begin_transaction()?;
        let result = isolated
            .consume_verification_inner(identifier, value)
            .await?;
        self.commit_transaction(base, isolated, queue).await?;
        Ok(result)
    }
}
