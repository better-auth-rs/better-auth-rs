use super::hooks::CommittedWrite;
use super::sessions::SessionSource;
use super::sessions::session_token_matches;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate, SessionUpdate};
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
        token: &crate::FieldValue,
        update: SessionUpdate,
    ) -> AuthResult<Option<SessionView>> {
        let fields = self
            .bind_session_update_fields(update.into_public_fields()?)
            .await?;
        let (column, token) = self.memory_session_token_query(token.clone())?;
        let session = self
            .raw("session", "update", |state| {
                let Some(source) = state
                    .sessions
                    .first_ref(|row| session_token_matches(row, &column, &token))?
                else {
                    return Ok(None);
                };
                source.write(|session| {
                    self.apply_session_storage_fields(session, &fields);
                    Ok(())
                })?;
                Ok(Some(SessionSource::Live(source)))
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

    pub(super) fn apply_session_storage_fields(
        &self,
        session: &mut SessionView,
        fields: &FieldMap,
    ) {
        let schema = self.session_config.adapter_schema();
        macro_rules! apply {
            ($($field:ident => $name:literal),* $(,)?) => {$(
                if let Some(value) = fields.get(schema.record_storage_key($name)) {
                    session.$field = crate::SchemaValue::from_field(value.clone());
                    if let Some(present) = &mut session.visible_fields
                        && matches!($name, "impersonatedBy" | "activeTeamId" | "activeOrganizationId") {
                        let _ = present.insert($name.into());
                    }
                }
            )*};
        }
        apply!(id => "id", token => "token", user_id => "userId", expires_at => "expiresAt",
            created_at => "createdAt", updated_at => "updatedAt", ip_address => "ipAddress",
            user_agent => "userAgent", impersonated_by => "impersonatedBy",
            active_organization_id => "activeOrganizationId", active_team_id => "activeTeamId");
        session.additional_fields.extend(fields.clone());
        for name in [
            "id",
            "token",
            "userId",
            "expiresAt",
            "createdAt",
            "updatedAt",
            "ipAddress",
            "userAgent",
            "impersonatedBy",
            "activeOrganizationId",
            "activeTeamId",
        ] {
            if schema.record_storage_key(name) == name {
                let _ = session.additional_fields.remove(name);
            }
        }
    }

    pub(super) async fn delete_sessions_with_hooks(
        &self,
        predicate: impl Fn(&SessionView) -> AuthResult<bool> + Send + Sync,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let now = Utc::now();
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let matches =
            |row: &SessionView| Ok(predicate(row)? && (!preserve || row.expires_at.is_after(now)?));
        let sessions: Vec<_> = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .try_select_refs(matches)?
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
            let fields = self
                .bind_session_update_fields(
                    [
                        ("expiresAt".into(), expires_at.into()),
                        ("updatedAt".into(), expires_at.into()),
                    ]
                    .into(),
                )
                .await?;
            self.raw("session", "updateMany", |state| {
                let mut count = 0;
                state.sessions.update_each(|session| {
                    if matches(session)? {
                        self.apply_session_storage_fields(session, &fields);
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
