use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, SessionUpdate};
use crate::store::schema::EntityRole;
use crate::store::schema::resolve_field_name;
#[cfg(test)]
use crate::user_fields::{FieldTransforms, UserFieldTransform};

pub(super) enum SessionSource {
    Live(RowRef<SessionView>),
    Snapshot(Box<SessionView>),
}

impl SessionSource {
    fn read<T>(&self, read: impl FnOnce(&SessionView) -> AuthResult<T>) -> AuthResult<T> {
        match self {
            Self::Live(source) => source.read(read),
            Self::Snapshot(row) => read(row),
        }
    }
}

impl EphemeralStore {
    pub(super) async fn output_session(&self, session: SessionSource) -> AuthResult<SessionView> {
        // Projection preserves the one input row.
        Ok(self.output_sessions(vec![session]).await?.remove(0))
    }

    pub(super) async fn output_sessions(
        &self,
        sessions: Vec<SessionSource>,
    ) -> AuthResult<Vec<SessionView>> {
        self.output_sessions_batches_then(sessions, |ready| std::future::ready(Ok(ready)))
            .await
    }

    pub(super) async fn output_sessions_batches_then<R: Send, F>(
        &self,
        sessions: Vec<SessionSource>,
        complete: impl Fn(Vec<(usize, SessionView)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        if !sessions.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Session)?;
        }
        let schema = self.session_config.adapter_schema();
        let mut rows: Vec<_> = sessions
            .into_iter()
            .map(|source| {
                let mut session = source.read(|row| Ok(row.clone()))?;
                session.additional_fields.clear();
                Ok((session, source))
            })
            .collect::<AuthResult<_>>()?;
        crate::user_fields::project_source_fields_batches_then(
            &mut rows,
            schema.fields(),
            |(_, source), name, field| {
                source.read(|row| {
                    if name == "id" {
                        return Ok(row.id.field_value());
                    }
                    let storage = row.field_values()?;
                    Ok(storage
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .or_else(|| storage.get(name))
                        .cloned()
                        .unwrap_or_default())
                })
            },
            |(session, _), name, field, value| {
                Box::pin(async move {
                    if name == "id" {
                        session.id = Self::project_id(&crate::SchemaValue::from_field(value))?;
                        return Ok(());
                    }
                    let value = if resolve_field_name(field.field_name.as_deref(), name) == "id" {
                        let value = match field.output_transform() {
                            Some(transform) => transform.call(value).await?,
                            None => value,
                        };
                        Self::project_id(&crate::SchemaValue::from_field(value))?.into_field_value()
                    } else {
                        field.adapter_output(value, field.references_id()).await?
                    };
                    let _ = session.additional_fields.insert(name.to_owned(), value);
                    Ok(())
                })
            },
            |_, (session, _)| {
                let mut session = session.clone();
                if self.session_config.fields().contains_key("userId") {
                    session.user_id = crate::SchemaValue::from_field(
                        session
                            .additional_fields
                            .remove("userId")
                            .unwrap_or_default(),
                    );
                } else {
                    session.user_id = Self::project_id(&session.user_id)?;
                }
                Ok(session.into_projected_fields())
            },
            complete,
        )
        .await
    }
}

impl EphemeralStore {
    async fn write_session_create_fields(&self, mut fields: FieldMap) -> AuthResult<SessionView> {
        let schema = crate::store::session_create_schema(&self.session_config, &fields);
        let mut supplied_id = fields.remove("id");
        self.model_fields.begin_id_input(
            EntityRole::Session,
            crate::id::AdapterIdInput {
                force_allow_id: supplied_id.is_some(),
                supports_native_uuid: false,
            },
        )?;
        let mut additional_fields = schema
            .storage_fields_with_bound_id(
                fields,
                true,
                || {
                    let supplied = supplied_id.take();
                    let Some(policy) = self.model_fields.id_input_policy(EntityRole::Session)?
                    else {
                        return Ok(supplied.filter(|value| !value.is_undefined()));
                    };
                    let row_count = self.lock()?.sessions.len();
                    let value = self
                        .config
                        .advanced
                        .database
                        .generate_id()
                        .adapter_create_id_input("session", supplied, policy)?;
                    Ok(self.next_serial_id(row_count).or(value))
                },
                |name, field, value| {
                    let value = self.memory_plugin_field_input(field, value)?;
                    Ok(if name == "id" {
                        self.next_serial_id(self.lock()?.sessions.len())
                            .unwrap_or(value)
                    } else {
                        value
                    })
                },
            )
            .await?;
        let mut native = crate::store::session_create_native_fields(&schema, &additional_fields);
        let id = additional_fields.remove("id").unwrap_or_default();
        let _ = native.insert("id".into(), id);
        let mut session = crate::store::session_from_create_fields(native.clone())?;
        // Physical aliases must remain independent of the typed logical members used by store queries.
        for (name, canonical) in native {
            match additional_fields.get(&name) {
                Some(value) if value.strict_equals(&canonical) => {
                    let _ = additional_fields.remove(&name);
                }
                None if name != "id" => {
                    let _ = additional_fields.insert(name, crate::FieldValue::Undefined);
                }
                _ => {}
            }
        }
        session.additional_fields = additional_fields;
        let source = self
            .raw("session", "create", |state| {
                if let Some(id) = self.next_serial_id(state.sessions.len()) {
                    session.id = crate::SchemaValue::from_field(id);
                }
                Ok(SessionSource::Live(state.sessions.push_ref(session)))
            })
            .await?;
        self.output_session(source).await
    }
}

#[async_trait]
impl SessionStore<StatelessSchema> for EphemeralStore {
    async fn update_session_with_writer(
        &self,
        token: &str,
        update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        EphemeralStore::update_session_with_writer(self, token, update, secondary).await
    }

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        self.delete_sessions_with_hooks(|row| row.token == token, true)
            .await
            .map(|_| ())
    }

    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: crate::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        self.accept_invitation(
            invitation_id,
            user_id,
            session_token,
            teams_enabled,
            maximum,
        )
        .await
    }

    async fn before_create_runtime_session(
        &self,
        input: &mut crate::store::PreparedSessionCreate,
    ) -> AuthResult<()> {
        if self.before_create_runtime_session_optional(input).await? {
            Ok(())
        } else {
            Err(AuthError::forbidden(
                "session creation cancelled by database hook",
            ))
        }
    }
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut crate::store::PreparedSessionCreate,
    ) -> AuthResult<bool> {
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateSession,
                hook.before_create_session(input.fields_mut(), &context),
            )
            .await?;
            if !input.apply(outcome) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn after_create_runtime_session(
        &self,
        session: &SessionView,
        request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_with_request(CommittedWrite::SessionCreated(session.clone()), request)
            .await
    }

    async fn create_session(&self, input: CreateSession) -> AuthResult<SessionView> {
        self.create_session_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("session creation cancelled by database hook"))
    }
    async fn create_session_optional(
        &self,
        input: CreateSession,
    ) -> AuthResult<Option<SessionView>> {
        self.create_session_with_writer(input, None).await
    }

    async fn create_session_with_writer(
        &self,
        input: CreateSession,
        writer: Option<crate::store::SessionCreateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        let request = crate::hooks::current_request_hook_context();
        let write_database = writer.as_ref().is_none_or(|writer| writer.write_database);
        let mut prepared =
            crate::store::PreparedSessionCreate::new(input, &self.config, !write_database)?;
        if !self
            .before_create_runtime_session_optional(&mut prepared)
            .await?
        {
            return Ok(None);
        }
        let (original, fields) = prepared.into_parts();
        let session = if write_database {
            crate::store::database_hooks::await_adapter_lookup().await;
            self.write_session_create_fields(fields).await?
        } else {
            crate::store::session_from_create_fields(fields)?
        };
        let deferred = match writer {
            Some(writer) => {
                let write = (writer.write)(original, session.clone());
                if writer.deferred {
                    Some(write)
                } else {
                    write.await?;
                    None
                }
            }
            None => None,
        };
        self.after_create_runtime_session(&session, request).await?;
        if let Some(write) = deferred {
            if self.pending_hooks.is_some() {
                EphemeralTransaction {
                    store: self.clone(),
                }
                .queue_after_commit(write)?;
            } else {
                write.await?;
            }
        }
        Ok(Some(session))
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let session = self
            .raw("session", "findOne", |state| {
                Ok(state
                    .sessions
                    .first_ref(|row| row.token == token)?
                    .map(SessionSource::Live))
            })
            .await?;
        futures_util::future::OptionFuture::from(
            session.map(|session| self.output_session(session)),
        )
        .await
        .transpose()
    }

    async fn get_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<Option<(SessionView, Option<crate::session::SessionData>)>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_session_snapshot(token).await;
        }
        Ok(self
            .get_session(token)
            .await?
            .map(|session| (session, None)))
    }

    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<Vec<(SessionView, Option<crate::session::SessionData>)>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_session_snapshots(tokens, only_active).await;
        }
        let now = Utc::now();
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let sessions = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .select_refs(|session| {
                            tokens.contains(&session.token)
                                && (!only_active
                                    || session.expires_at.milliseconds()
                                        > now.timestamp_millis() as f64)
                        })?
                        .into_iter()
                        .map(SessionSource::Live)
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        let snapshots = self
            .output_sessions_batches_then(sessions, |ready| async move {
                let mut pending = Vec::new();
                let mut users = Vec::new();
                for (index, session) in ready {
                    let owner = session.user_id.field_value();
                    let user = if owner.is_null() || owner.is_undefined() {
                        None
                    } else {
                        self.user_ref_by_id_value(&owner).await?
                    };
                    let has_user = user.is_some();
                    users.extend(user);
                    pending.push((index, session, has_user));
                }
                let mut users = self.output_user_refs(users).await?.into_iter();
                Ok(pending
                    .into_iter()
                    .map(|(index, session, has_user)| {
                        let data = if has_user { users.next() } else { None }.map(|user| {
                            crate::session::SessionData {
                                session: session.clone(),
                                user,
                            }
                        });
                        (index, (session, data))
                    })
                    .collect())
            })
            .await?;
        // Complete started output callbacks before applying the joined batch's missing-user rule.
        if snapshots.iter().any(|(_, user)| user.is_none()) {
            return Ok(Vec::new());
        }
        Ok(snapshots)
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: FieldMap,
    ) -> AuthResult<Option<SessionView>> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
        )
        .await
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let user_id = self.memory_session_user_id_query(Value::from(user_id))?;
        let sessions: Vec<_> = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .select_refs(|session| {
                            session.user_id.field_value().strict_equals(&user_id)
                        })?
                        .into_iter()
                        .map(SessionSource::Live)
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.output_sessions(sessions).await
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<SessionView> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                expires_at: Some(expires_at.into()),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let session = self
            .raw("session", "findOne", |state| {
                Ok(state
                    .sessions
                    .first_ref(|row| row.token == token)?
                    .map(SessionSource::Live))
            })
            .await?;
        // A failed single-row snapshot prevents deletion, unlike a failed batch snapshot.
        let Some(session) = (match session {
            Some(row) => self.output_session(row).await.ok(),
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
                crate::observability::database::DatabaseHook::BeforeDeleteSession,
                hook.before_delete_session(&session, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(());
            }
        }
        self.model_fields.begin_id_query(EntityRole::Session)?;
        self.raw("session", "delete", |state| {
            let _ = state.sessions.remove_first(|row| row.token == token)?;
            Ok(())
        })
        .await?;
        self.after(CommittedWrite::SessionDeleted(session)).await?;
        Ok(())
    }

    async fn delete_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        self.delete_sessions_with_hooks(|row| tokens.contains(&row.token), false)
            .await
            .map(|_| ())
    }

    async fn end_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        self.delete_sessions_with_hooks(|row| tokens.contains(&row.token), true)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.delete_user_sessions_optional(user_id, false)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions_optional(
        &self,
        user_id: &str,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let user_id = self.memory_session_user_id_query(Value::from(user_id))?;
        self.delete_sessions_with_hooks(
            |row| row.user_id.field_value().strict_equals(&user_id),
            preserve,
        )
        .await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now = Utc::now();
        self.delete_sessions_with_hooks(
            |row| row.expires_at.milliseconds() <= now.timestamp_millis() as f64 || !row.active,
            false,
        )
        .await
        .map(Option::unwrap_or_default)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                active_organization_id: Some(organization_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                active_team_id: Some(team_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
}

#[cfg(test)]
mod live_output_tests;

#[tokio::test]
async fn invitation_fields_update_atomically_with_team_membership() {
    use crate::{
        CreateTeam,
        organization_fields::OrganizationFields,
        store::{TeamMemberLimits, TeamStore},
        user_fields::{UserConfig, UserFieldConfig},
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    let reject = Arc::new(AtomicBool::new(true));
    let rejection = reject.clone();
    let field = UserFieldConfig {
        required: Some(false),
        returned: Some(false),
        field_name: Some("stored_marker".into()),
        default_value: Some(Value::from("created")),
        on_update: Some(Arc::new(|| Ok(Value::from("updated")))),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                if rejection.load(Ordering::SeqCst) && value == Value::from("updated") {
                    return Err(AuthError::bad_request("transform failed"));
                }
                Ok(Value::from(format!("{}:in", value.as_str().unwrap())))
            })),
            output: Some(UserFieldTransform::new(|value| {
                Ok(Value::from(format!("{}:out", value.as_str().unwrap())))
            })),
        }),
        ..Default::default()
    };
    let schema = UserConfig {
        additional_fields: Some([("marker".into(), field)].into()),
    };
    let store = EphemeralStore::new(test_config());
    store
        .configure_organization_fields(OrganizationFields {
            member: schema.clone(),
            invitation: schema,
            ..Default::default()
        })
        .unwrap();
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await
        .unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut input = CreateInvitation::new(
        organization.id.typed().unwrap(),
        "member@example.com",
        "member",
        "owner",
        (Utc::now() + chrono::Duration::days(1)).into(),
    );
    input.team_id = Some(team.id.typed().unwrap().clone());
    let invitation = store.create_invitation(input).await.unwrap();
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: "member".into(),
            expires_at: (Utc::now() + chrono::Duration::days(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    assert!(
        store
            .accept_invitation_with_teams(
                invitation.id.typed().unwrap(),
                "member",
                Some(&session.token),
                true,
                TeamMemberLimits::Fixed(None)
            )
            .await
            .is_err()
    );
    assert!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .get_member(organization.id.typed().unwrap(), "member")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .is_pending()
    );
    reject.store(false, Ordering::SeqCst);
    let (member, accepted, _) = store
        .accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "member",
            Some(&session.token),
            true,
            TeamMemberLimits::Fixed(None),
        )
        .await
        .unwrap();
    assert_eq!(
        member.additional_fields.get("marker"),
        Some(&Value::from("created:in:out"))
    );
    assert_eq!(
        accepted.additional_fields.get("marker"),
        Some(&Value::from("updated:in:out"))
    );
    assert_eq!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .additional_fields,
        accepted.additional_fields
    );
    assert_eq!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
}
