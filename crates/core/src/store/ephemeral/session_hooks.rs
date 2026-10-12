use super::hooks::CommittedWrite;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, PreparedRecordWrite, SessionUpdate};
use crate::store::schema::EntityRole;

impl EphemeralStore {
    pub(super) async fn update_session_with_hooks(
        &self,
        token: &str,
        update: SessionUpdate,
    ) -> AuthResult<Option<SessionView>> {
        self.update_session_with_writer(token, update, None).await
    }

    pub(super) async fn update_session_with_writer(
        &self,
        token: &str,
        update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        self.update_session_with_writer_by_token_value(&token.into(), update, secondary)
            .await
    }

    pub(super) async fn update_session_with_writer_by_token_value(
        &self,
        token: &crate::FieldValue,
        update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        let mut prepared = PreparedRecordWrite::new(update.into_public_fields()?);
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateSession,
                hook.before_update_session(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        let update = prepared.into_fields();
        let (write_database, cached) = match secondary {
            Some(secondary) => {
                let result = (secondary.write)(update.clone()).await?;
                (secondary.write_database, result)
            }
            None => (true, None),
        };
        let session = if write_database {
            crate::store::database_hooks::await_adapter_lookup().await;
            self.write_session_update(token, update).await?
        } else {
            cached
        };
        self.after(CommittedWrite::SessionUpdated(session.clone()))
            .await?;
        Ok(session)
    }

    async fn write_session_update(
        &self,
        token: &crate::FieldValue,
        update: FieldMap,
    ) -> AuthResult<Option<SessionView>> {
        let (column, token) = self.memory_session_token_query(token.clone())?;
        let fields = self.bind_session_update_fields(update).await?;
        let session = self
            .raw("session", "update", |op| {
                let sources = op.capture_table(EntityRole::Session)?.select_refs(|row| {
                    Ok(crate::query::field_matches_equality(
                        &row.field(&column)?.unwrap_or_default(),
                        &token,
                    ))
                })?;
                for source in &sources {
                    source.apply_patch(fields.clone())?;
                }
                Ok(sources.into_iter().next().map(RecordSource::Live))
            })
            .await?;
        futures_util::future::OptionFuture::from(session.map(|row| self.output_session(row)))
            .await
            .transpose()
    }

    pub(super) async fn bind_session_update_fields(
        &self,
        mut input: FieldMap,
    ) -> AuthResult<FieldMap> {
        let schema = self.field_policy().session(&input).adapter_fields(&[]);
        let mut supplied_id = input.remove("id");
        let fields = self
            .model_fields
            .with_id_input(
                EntityRole::Session,
                crate::id::AdapterIdInput::default(),
                schema.update_adapter_storage_fields(
                    input,
                    || {
                        let Some(value) = supplied_id.take() else {
                            return Ok(None);
                        };
                        let Some(policy) =
                            self.model_fields.id_input_policy(EntityRole::Session)?
                        else {
                            return Ok(Some(value));
                        };
                        self.config
                            .advanced
                            .database
                            .generate_id()
                            .adapter_id_input(value, policy)
                    },
                    |_, field, value| self.memory_plugin_field_input(field, value),
                ),
            )
            .await?;
        Ok(fields)
    }

    pub(super) async fn delete_sessions_with_hooks(
        &self,
        bind: impl Fn() -> AuthResult<Vec<(String, Value, crate::WhereOperator)>> + Send + Sync,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let expiry = preserve.then(|| Value::from(Utc::now()));
        let bind_matches = || -> AuthResult<_> {
            let mut clauses = bind()?;
            let expiry = expiry
                .as_ref()
                .map(|value| self.memory_session_field_query("expiresAt", value.clone()))
                .transpose()?;
            if let Some((column, now)) = expiry {
                clauses.push((column, now, crate::WhereOperator::Gt));
            }
            Ok(move |row: &RowRef<FieldMap>| {
                crate::memory_query::matches_all(clauses.iter(), |(column, value, operator)| {
                    crate::memory_query::matches(
                        row.field(column)?.as_ref(),
                        value,
                        *operator,
                        crate::WhereMode::Sensitive,
                    )
                })
            })
        };
        // Upstream deleteManyWithHooks catches snapshot query and projection failures before the write.
        let sessions = async {
            let matches = bind_matches()?;
            let sessions = self
                .raw("session", "findMany", |op| {
                    Ok(crate::query::paginate_memory(
                        op.capture_table(EntityRole::Session)?
                            .select_refs(matches)?
                            .into_iter()
                            .map(RecordSource::Live)
                            .collect(),
                        Some(self.config.advanced.database.find_many_limit()),
                        None,
                    ))
                })
                .await?;
            self.output_sessions(sessions).await
        }
        .await
        .unwrap_or_default();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for session in &sessions {
            for hook in &self.hooks {
                if crate::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    crate::observability::database::DatabaseHook::BeforeDeleteSession,
                    hook.before_delete_session(session, &context),
                )
                .await?
                    == DatabaseHookControl::Cancel
                {
                    return Ok(None);
                }
            }
        }
        let matches = bind_matches()?;
        let count = if preserve {
            let expires_at = Utc::now();
            let fields = self
                .bind_session_update_fields([("expiresAt".into(), expires_at.into())].into())
                .await?;
            self.raw("session", "updateMany", |op| {
                let sessions = op
                    .capture_table(EntityRole::Session)?
                    .select_refs(matches)?;
                for source in &sessions {
                    source.apply_patch(fields.clone())?;
                }
                Ok(sessions.len())
            })
            .await?
        } else {
            self.raw("session", "deleteMany", |op| {
                let table = op.capture_table(EntityRole::Session)?;
                let selected = table.select_refs(matches)?;
                op.replace_table(EntityRole::Session, table.without_refs(&selected)?)?;
                Ok(selected.len())
            })
            .await?
        };
        for session in sessions {
            self.after(CommittedWrite::SessionDeleted(session)).await?;
        }
        Ok(Some(count))
    }
}
