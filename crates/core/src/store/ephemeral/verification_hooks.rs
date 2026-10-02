use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate, VerificationUpdate};

impl EphemeralStore {
    pub(super) async fn update_verification_with_hooks(
        &self,
        identifier: &str,
        mut update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        let original = update.clone();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateVerification,
                hook.before_update_verification(&original, &context),
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
            .verification
            .field_schema()
            .record_storage_fields_with_binding(update.fields()?, false, |_, field, value| {
                self.memory_record_input(field, value)
            })
            .await?;
        let bound_identifier = self.verification_query("identifier", identifier)?;
        let record = self
            .raw("verification", "update", |state| {
                Ok({
                    let row = state.verifications.find_mut(|row| {
                        self.verification_field(row, "identifier") == Some(&bound_identifier)
                    })?;
                    if let Some(mut record) = row {
                        record.extend(patch);
                        Some(record.clone())
                    } else {
                        None
                    }
                })
            })
            .await?;
        let record = futures_util::future::OptionFuture::from(
            record
                .as_ref()
                .map(|record| self.output_verification(record)),
        )
        .await
        .transpose()?;
        self.after(CommittedWrite::VerificationUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    pub(super) async fn delete_verifications_with_hooks(
        &self,
        predicate: impl Fn(&Map<String, Value>) -> bool + Send + Sync,
        many: bool,
    ) -> AuthResult<usize> {
        let rows: Vec<_> = self
            .raw(
                "verification",
                if many { "findMany" } else { "findOne" },
                |state| {
                    Ok(crate::query::paginate_memory(
                        state
                            .verifications
                            .snapshot()?
                            .iter()
                            .filter(|row| predicate(row))
                            .cloned()
                            .collect(),
                        Some(if many {
                            self.config.advanced.database.find_many_limit()
                        } else {
                            1.0
                        }),
                        None,
                    ))
                },
            )
            .await?;
        // Single and batch delete both catch snapshot output errors; only batch still deletes on an empty snapshot.
        let rows = self.output_verifications(&rows).await.unwrap_or_default();
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
        let count = self
            .raw(
                "verification",
                if many { "deleteMany" } else { "delete" },
                |state| {
                    Ok({
                        let count = state.verifications.len();
                        state.verifications.retain(|row| !predicate(row))?;
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
        let Some(snapshot) = self.get_verification_including_expired(identifier).await? else {
            return Ok(None);
        };
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
        let id = snapshot.id.json()?;
        let Some(consumed) = self
            .raw("verification", "consumeOne", |state| {
                state
                    .verifications
                    .remove_first(|row| row.get("id") == id.as_ref())
            })
            .await?
        else {
            return Ok(None);
        };
        let consumed = self.output_verification(&consumed).await?;
        let bound_identifier = self.verification_query("identifier", identifier)?;
        self.raw("verification", "deleteMany", |state| {
            state.verifications.retain(|row| {
                self.verification_field(row, "identifier") != Some(&bound_identifier)
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
