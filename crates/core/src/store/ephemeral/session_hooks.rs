use super::hooks::CommittedWrite;
use super::rows::RecordSource;
use super::sessions::session_token_matches;
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
            .raw("session", "update", |state| {
                let sources = state
                    .sessions
                    .select_refs(|row| session_token_matches(row, &column, &token))?;
                for source in &sources {
                    source.write(|session| {
                        session.extend(fields.clone());
                        Ok(())
                    })?;
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
        let schema = crate::store::session_create_schema(&self.session_config, &input);
        self.model_fields
            .begin_id_input(EntityRole::Session, crate::id::AdapterIdInput::default())?;
        let mut supplied_id = input.remove("id");
        let fields = schema
            .update_adapter_storage_fields(
                input,
                || {
                    let Some(value) = supplied_id.take() else {
                        return Ok(None);
                    };
                    let Some(policy) = self.model_fields.id_input_policy(EntityRole::Session)?
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
            )
            .await?;
        Ok(fields)
    }

    pub(super) async fn delete_sessions_with_hooks<P>(
        &self,
        bind: impl Fn() -> AuthResult<P> + Send + Sync,
        preserve: bool,
    ) -> AuthResult<Option<usize>>
    where
        P: Fn(&FieldMap) -> AuthResult<bool> + Send + Sync,
    {
        let expiry = preserve.then(|| Value::from(Utc::now()));
        let bind_matches = || -> AuthResult<_> {
            let predicate = bind()?;
            let expiry = expiry
                .as_ref()
                .map(|value| self.memory_session_field_query("expiresAt", value.clone()))
                .transpose()?;
            Ok(move |row: &FieldMap| {
                Ok(predicate(row)?
                    && match &expiry {
                        Some((column, now)) => {
                            crate::query::field_compare(
                                row.get(column).unwrap_or(&Value::Undefined),
                                now,
                            )? == Some(std::cmp::Ordering::Greater)
                        }
                        None => true,
                    })
            })
        };
        // Upstream deleteManyWithHooks catches snapshot query and projection failures before the write.
        let sessions = async {
            let matches = bind_matches()?;
            let sessions = self
                .raw("session", "findMany", |state| {
                    Ok(crate::query::paginate_memory(
                        state
                            .sessions
                            .try_select_refs(matches)?
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
            self.raw("session", "updateMany", |state| {
                let sessions = state.sessions.try_select_refs(matches)?;
                for source in &sessions {
                    source.write(|session| {
                        session.extend(fields.clone());
                        Ok(())
                    })?;
                }
                Ok(sessions.len())
            })
            .await?
        } else {
            self.raw("session", "deleteMany", |state| {
                let before = state.sessions.len();
                state
                    .sessions
                    .try_retain(|row| matches(row).map(|matches| !matches))?;
                Ok(before - state.sessions.len())
            })
            .await?
        };
        for session in sessions {
            self.after(CommittedWrite::SessionDeleted(session)).await?;
        }
        Ok(Some(count))
    }
}
