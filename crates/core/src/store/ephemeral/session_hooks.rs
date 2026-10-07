use super::hooks::CommittedWrite;
use super::sessions::SessionSource;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate, SessionUpdate};
use crate::store::schema::EntityRole;

impl SessionUpdate {
    fn apply(
        self,
        session: &mut SessionView,
        id: Option<crate::SchemaValue<String>>,
        user_id: Option<crate::SchemaValue<String>>,
    ) {
        if let Some(fields) = &mut session.visible_fields {
            for (name, supplied) in [
                ("impersonatedBy", self.impersonated_by.is_some()),
                (
                    "activeOrganizationId",
                    self.active_organization_id.is_some(),
                ),
                ("activeTeamId", self.active_team_id.is_some()),
            ] {
                if supplied {
                    let _ = fields.insert(name.into());
                }
            }
        }
        macro_rules! fields {
            ($($field:ident),* $(,)?) => {$(if let Some(value) = self.$field { session.$field = value; })*};
        }
        if let Some(id) = id {
            session.id = id;
            let _ = session.additional_fields.remove("id");
        }
        if let Some(user_id) = user_id {
            session.user_id = user_id;
        }
        fields!(
            token,
            expires_at,
            created_at,
            ip_address,
            user_agent,
            impersonated_by,
            active_organization_id,
            active_team_id
        );
        session.updated_at = self.updated_at.unwrap_or_else(|| Utc::now().into());
        session.additional_fields.extend(self.additional_fields);
    }
}

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
        mut update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        let original = update.clone();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateSession,
                hook.before_update_session(&original, &context),
            )
            .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
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
        token: &str,
        mut update: SessionUpdate,
    ) -> AuthResult<Option<SessionView>> {
        let schema = self.session_config.adapter_schema();
        let configured_user_id = schema.fields().contains_key("userId");
        let mut user_id = if configured_user_id {
            if let Some(user_id) = update.user_id.take() {
                let _ = update
                    .additional_fields
                    .insert("userId".into(), user_id.into());
            }
            None
        } else {
            update
                .user_id
                .take()
                .map(|user_id| self.memory_reference_id_input(user_id.into()))
                .transpose()?
        };
        self.model_fields
            .begin_id_input(EntityRole::Session, crate::id::AdapterIdInput::default())?;
        let mut input = std::mem::take(&mut update.additional_fields);
        let typed_id = update.id.take().map(Value::from);
        let mut supplied_id = input.remove("id").or(typed_id);
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
        let id = fields
            .get("id")
            .cloned()
            .map(crate::SchemaValue::from_field);
        update.additional_fields = fields;
        if configured_user_id {
            user_id = update
                .additional_fields
                .get(schema.record_storage_key("userId"))
                .cloned()
                .map(crate::SchemaValue::from_field);
        }
        let _ = update.additional_fields.remove("id");
        let session = self
            .raw("session", "update", |state| {
                let Some(source) = state.sessions.first_ref(|row| row.token == token)? else {
                    return Ok(None);
                };
                source.write(|session| {
                    update.apply(session, id, user_id);
                    Ok(())
                })?;
                Ok(Some(SessionSource::Live(source)))
            })
            .await?;
        let session =
            futures_util::future::OptionFuture::from(session.map(|row| self.output_session(row)))
                .await
                .transpose()?;
        Ok(session)
    }

    pub(super) async fn delete_sessions_with_hooks(
        &self,
        predicate: impl Fn(&SessionView) -> bool + Send + Sync,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let now = Utc::now();
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let matches = |row: &SessionView| {
            predicate(row)
                && (!preserve || row.expires_at.milliseconds() > now.timestamp_millis() as f64)
        };
        let sessions: Vec<_> = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .select_refs(matches)?
                        .into_iter()
                        .map(SessionSource::Live)
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        // Upstream deleteManyWithHooks catches snapshot projection failures, then runs the write.
        let sessions = self.output_sessions(sessions).await.unwrap_or_default();
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
        let count = if preserve {
            let expires_at = Utc::now();
            let schema = self.session_config.adapter_schema();
            self.model_fields
                .begin_id_input(EntityRole::Session, crate::id::AdapterIdInput::default())?;
            let fields = schema
                .storage_fields_with_binding(Default::default(), false, |_, field, value| {
                    self.memory_plugin_field_input(field, value)
                })
                .await?;
            let user_id = if schema.fields().contains_key("userId") {
                fields
                    .get(schema.record_storage_key("userId"))
                    .cloned()
                    .map(crate::SchemaValue::from_field)
            } else {
                None
            };
            self.raw("session", "updateMany", |state| {
                let mut count = 0;
                state.sessions.update_each(|session| {
                    if matches(session) {
                        session.expires_at = expires_at.into();
                        session.updated_at = expires_at.into();
                        if let Some(user_id) = &user_id {
                            session.user_id = user_id.clone();
                        }
                        session.additional_fields.extend(fields.clone());
                        count += 1;
                    }
                    Ok(())
                })?;
                Ok(count)
            })
            .await?
        } else {
            self.model_fields.begin_id_query(EntityRole::Session)?;
            self.raw("session", "deleteMany", |state| {
                let before = state.sessions.len();
                state.sessions.retain(|row| !matches(row))?;
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
