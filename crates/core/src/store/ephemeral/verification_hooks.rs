use super::hooks::CommittedWrite;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, PreparedRecordWrite, VerificationUpdate};

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
        let bound_identifier = self.verification_query("identifier", identifier)?;
        let patch = self
            .verification_storage_fields(prepared.into_fields(), false)
            .await?;
        let record = self
            .raw("verification", "update", |state| {
                let rows = state.verifications.select_refs(|row| {
                    self.verification_field(row, "identifier")
                        .unwrap_or(&Value::Undefined)
                        .strict_equals(&bound_identifier)
                })?;
                for row in &rows {
                    row.write(|record| {
                        record.extend(patch.clone());
                        Ok(())
                    })?;
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

    pub(super) async fn delete_verifications_with_hooks(
        &self,
        predicate: impl Fn(&FieldMap) -> AuthResult<bool> + Send + Sync,
        many: bool,
    ) -> AuthResult<usize> {
        let rows: Vec<_> = self
            .raw("verification", "findMany", |state| {
                let matched = state.verifications.try_select_refs(&predicate)?;
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
        self.finish_verification_delete(rows, predicate, many).await
    }

    pub(super) async fn finish_verification_delete(
        &self,
        rows: Vec<RowRef<FieldMap>>,
        predicate: impl Fn(&FieldMap) -> AuthResult<bool> + Send + Sync,
        many: bool,
    ) -> AuthResult<usize> {
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
        let count = self
            .raw(
                "verification",
                if many { "deleteMany" } else { "delete" },
                |state| {
                    Ok({
                        let count = state.verifications.len();
                        state
                            .verifications
                            .try_retain(|row| predicate(row).map(|matches| !matches))?;
                        count - state.verifications.len()
                    })
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
        // Preserve numeric Serial IDs and deterministic reservation IDs before output projection.
        let id = record.read(|row| Ok(row.get("id").cloned().unwrap_or_default()))?;
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
        self.model_fields
            .begin_id_query(crate::store::schema::EntityRole::Verification)?;
        let Some(consumed) = self
            .raw("verification", "consumeOne", |state| {
                state.verifications.remove_first(|row| {
                    row.get("id")
                        .unwrap_or(&Value::Undefined)
                        .strict_equals(&id)
                })
            })
            .await?
        else {
            return Ok(None);
        };
        let consumed = self
            .output_verification(RecordSource::Snapshot(Box::new(consumed)))
            .await?;
        let bound_identifier = self.verification_query("identifier", identifier)?;
        self.raw("verification", "deleteMany", |state| {
            state.verifications.retain(|row| {
                !self
                    .verification_field(row, "identifier")
                    .unwrap_or(&Value::Undefined)
                    .strict_equals(&bound_identifier)
            })?;
            Ok(())
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
