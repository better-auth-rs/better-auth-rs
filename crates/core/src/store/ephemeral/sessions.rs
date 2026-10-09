use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, SessionUpdate};
use crate::store::schema::EntityRole;
use crate::store::schema::resolve_field_name;
#[cfg(test)]
use crate::user_fields::{FieldTransforms, UserFieldTransform};

pub(super) enum SessionSource {
    Live(RowRef<FieldMap>),
    Snapshot(Box<FieldMap>),
}

impl SessionSource {
    fn read<T>(&self, read: impl FnOnce(&FieldMap) -> AuthResult<T>) -> AuthResult<T> {
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
        let schema = crate::store::session_create_schema(&self.session_config, &FieldMap::new());
        let mut rows: Vec<_> = sessions
            .into_iter()
            .map(|source| {
                let stored = source.read(|row| Ok(row.clone()))?;
                let implicit: FieldMap = ["impersonatedBy", "activeOrganizationId", "activeTeamId"]
                    .into_iter()
                    .filter(|name| {
                        !schema.fields().contains_key(*name)
                            && !schema.fields().iter().any(|(logical, field)| {
                                resolve_field_name(field.field_name.as_deref(), logical) == *name
                            })
                    })
                    .filter_map(|name| stored.get(name).map(|value| (name.into(), value.clone())))
                    .collect();
                let session = SessionView {
                    active: true,
                    visible_fields: Some(Default::default()),
                    field_order: crate::store::session_create_schema(
                        &self.session_config,
                        &implicit,
                    )
                    .fields()
                    .keys()
                    .cloned()
                    .collect(),
                    additional_fields: implicit,
                    ..Default::default()
                };
                Ok((session, source))
            })
            .collect::<AuthResult<_>>()?;
        crate::user_fields::project_source_fields_batches_then(
            &mut rows,
            schema.fields(),
            |(_, source), name, field| {
                source.read(|row| {
                    if name == "id" {
                        return Ok(row.get("id").cloned().unwrap_or_default());
                    }
                    Ok(row
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned()
                        .unwrap_or_default())
                })
            },
            |(session, _), name, field, value| {
                Box::pin(async move {
                    if !session.field_order.iter().any(|field| field == name) {
                        session.field_order.push(name.into());
                    }
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
                        field
                            .adapter_output_from_raw(
                                value,
                                crate::user_fields::FieldOutputCapabilities::json_only(false),
                            )
                            .await?
                    };
                    let _ = session.additional_fields.insert(name.to_owned(), value);
                    Ok(())
                })
            },
            |_, (session, _)| Ok(session.clone().into_projected_fields()),
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
        let mut storage = schema
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
        let source = self
            .raw("session", "create", |state| {
                if let Some(id) = self.next_serial_id(state.sessions.len()) {
                    let _ = storage.insert("id".into(), id);
                }
                Ok(SessionSource::Live(state.sessions.push_ref(storage)))
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

    async fn update_session_with_writer_by_token_value(
        &self,
        token: &crate::FieldValue,
        update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        EphemeralStore::update_session_with_writer_by_token_value(self, token, update, secondary)
            .await
    }

    async fn update_session_fields_by_token_value(
        &self,
        token: &crate::FieldValue,
        fields: FieldMap,
    ) -> AuthResult<Option<SessionView>> {
        self.update_session_with_writer_by_token_value(
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
            None,
        )
        .await
    }

    async fn accept_invitation_with_teams_by_token_value(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: crate::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        self.accept_invitation_with_teams_values(
            &invitation_id.into(),
            &user_id.into(),
            session_token,
            teams_enabled,
            maximum,
        )
        .await
    }

    async fn accept_invitation_with_teams_values(
        &self,
        invitation_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
        session_token: Option<&crate::FieldValue>,
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

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        self.end_session_by_token_value(&token.into()).await
    }

    async fn end_session_by_token_value(&self, token: &crate::FieldValue) -> AuthResult<()> {
        let (column, token) = self.memory_session_token_query(token.clone())?;
        self.delete_sessions_with_hooks(|row| Ok(session_token_matches(row, &column, &token)), true)
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
        let token = session_token.map(crate::FieldValue::from);
        self.accept_invitation_with_teams_values(
            &invitation_id.into(),
            &user_id.into(),
            token.as_ref(),
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
        session: Option<&SessionView>,
        request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_with_request(CommittedWrite::SessionCreated(session.cloned()), request)
            .await
    }

    async fn create_session(&self, input: CreateSession) -> AuthResult<SessionView> {
        self.create_session_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("session creation returned no record"))
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
        let secondary_fields = (!write_database).then(|| fields.clone());
        let session = if write_database {
            crate::store::database_hooks::await_adapter_lookup().await;
            self.write_session_create_fields(fields).await?
        } else {
            crate::store::session_from_create_fields(fields)?
        };
        let deferred = match writer {
            Some(writer) => {
                let write = (writer.write)(
                    original,
                    secondary_fields.unwrap_or_else(|| session.clone().into()),
                );
                if writer.deferred {
                    Some(write)
                } else {
                    write.await?;
                    None
                }
            }
            None => None,
        };
        self.after_create_runtime_session(Some(&session), request)
            .await?;
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
        self.get_session_by_token_value(&token.into()).await
    }

    async fn get_session_by_token_value(
        &self,
        token: &crate::FieldValue,
    ) -> AuthResult<Option<SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let (column, token) = self.memory_session_token_query(token.clone())?;
        let session = self
            .raw("session", "findOne", |state| {
                Ok(state
                    .sessions
                    .first_ref(|row| session_token_matches(row, &column, &token))?
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
    ) -> AuthResult<
        Option<(
            SessionView,
            Option<crate::session::SessionData<crate::store::JoinValue<UserView>>>,
        )>,
    > {
        self.get_session_snapshot_value(&token.into()).await
    }

    async fn get_session_snapshot_value(
        &self,
        token: &crate::FieldValue,
    ) -> AuthResult<
        Option<(
            SessionView,
            Option<crate::session::SessionData<crate::store::JoinValue<UserView>>>,
        )>,
    > {
        let relation = crate::session::SessionData::resolve_schema(
            &self.config,
            &self.model_fields,
            |_, _| false,
        )?;
        Ok(self
            .session_user_relations(token.clone(), false, true, &relation)
            .await?
            .into_iter()
            .next())
    }

    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<
        Vec<(
            SessionView,
            Option<crate::session::SessionData<crate::store::JoinValue<UserView>>>,
        )>,
    > {
        let relation = crate::session::SessionData::resolve_schema(
            &self.config,
            &self.model_fields,
            |_, _| false,
        )?;
        let tokens = tokens
            .iter()
            .map(|token| token.as_str().into())
            .collect::<Vec<_>>();
        self.session_user_relations(tokens.into(), only_active, false, &relation)
            .await
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
        self.get_user_sessions_value(&user_id.into()).await
    }

    async fn get_user_sessions_value(&self, user_id: &Value) -> AuthResult<Vec<SessionView>> {
        Ok(self
            .get_user_session_snapshots_value(user_id, false)
            .await?
            .into_iter()
            .map(|(session, _)| session)
            .collect())
    }

    async fn get_user_session_snapshots_value(
        &self,
        user_id: &Value,
        only_active: bool,
    ) -> AuthResult<Vec<(SessionView, Option<SessionView>)>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let user_id = self.memory_session_user_id_query(user_id.clone())?;
        let schema = crate::store::session_create_schema(&self.session_config, &FieldMap::new());
        let now = if only_active {
            let now = self.memory_field_query(&schema, "expiresAt", Utc::now().into())?;
            Some(crate::user_query::bind_filter(
                &schema.fields()["expiresAt"],
                &now,
            )?)
        } else {
            None
        };
        let sessions: Vec<_> = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .try_select_refs(|session| {
                            let fields = session;
                            Ok(crate::query::field_matches_equality(
                                fields
                                    .get(schema.record_storage_key("userId"))
                                    .unwrap_or(&Value::Undefined),
                                &user_id,
                            ) && match &now {
                                Some(now) => {
                                    crate::query::field_compare(
                                        fields
                                            .get(schema.record_storage_key("expiresAt"))
                                            .unwrap_or(&Value::Undefined),
                                        now,
                                    )? == Some(std::cmp::Ordering::Greater)
                                }
                                None => true,
                            })
                        })?
                        .into_iter()
                        .map(SessionSource::Live)
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        Ok(self
            .output_sessions(sessions)
            .await?
            .into_iter()
            .map(|session| (session, None))
            .collect())
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
        self.delete_session_by_token_value(&token.into()).await
    }

    async fn delete_session_by_token_value(&self, token: &crate::FieldValue) -> AuthResult<()> {
        let snapshot = async {
            self.model_fields.begin_id_query(EntityRole::Session)?;
            let (column, converted) = self.memory_session_token_query(token.clone())?;
            let session = self
                .raw("session", "findOne", |state| {
                    Ok(state
                        .sessions
                        .first_ref(|row| session_token_matches(row, &column, &converted))?
                        .map(SessionSource::Live))
                })
                .await?;
            match session {
                Some(row) => self.output_session(row).await.map(Some),
                None => Ok(None),
            }
        }
        .await;
        // Upstream catches query and projection failures before single-row delete hooks.
        let Some(session) = snapshot.ok().flatten() else {
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
        crate::store::database_hooks::await_adapter_lookup().await;
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let (column, converted) = self.memory_session_token_query(token.clone())?;
        self.raw("session", "delete", |state| {
            state
                .sessions
                .retain(|row| !session_token_matches(row, &column, &converted))?;
            Ok(())
        })
        .await?;
        self.after(CommittedWrite::SessionDeleted(session)).await?;
        Ok(())
    }

    async fn delete_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let tokens = tokens
            .iter()
            .map(|token| token.as_str().into())
            .collect::<Vec<_>>();
        let (column, tokens) = self.memory_session_token_query(tokens.into())?;
        self.delete_sessions_with_hooks(|row| session_tokens_match(row, &column, &tokens), false)
            .await
            .map(|_| ())
    }

    async fn end_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let tokens = tokens
            .iter()
            .map(|token| token.as_str().into())
            .collect::<Vec<_>>();
        let (column, tokens) = self.memory_session_token_query(tokens.into())?;
        self.delete_sessions_with_hooks(|row| session_tokens_match(row, &column, &tokens), true)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.delete_user_sessions_by_user_value(&user_id.into())
            .await
    }

    async fn delete_user_sessions_by_user_value(&self, user_id: &Value) -> AuthResult<()> {
        self.delete_user_sessions_optional_value(user_id, false)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions_optional(
        &self,
        user_id: &str,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.delete_user_sessions_optional_value(&user_id.into(), preserve)
            .await
    }

    async fn delete_user_sessions_optional_value(
        &self,
        user_id: &Value,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let (column, user_id) = self.memory_session_field_query("userId", user_id.clone())?;
        self.delete_sessions_with_hooks(
            |row| {
                Ok(crate::query::field_matches_equality(
                    row.get(&column).unwrap_or(&Value::Undefined),
                    &user_id,
                ))
            },
            preserve,
        )
        .await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let (column, now) = self.memory_session_field_query("expiresAt", Utc::now().into())?;
        self.delete_sessions_with_hooks(
            |row| {
                Ok(matches!(
                    crate::query::field_compare(
                        row.get(&column).unwrap_or(&Value::Undefined),
                        &now
                    )?,
                    Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                ))
            },
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
#[cfg(test)]
mod native_owner_tests;
#[cfg(test)]
mod physical_tests;

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
            inherited_fields: Default::default(),
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
                Some(session.token.typed().unwrap()),
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
            Some(session.token.typed().unwrap()),
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

pub(super) fn session_token_matches(
    fields: &FieldMap,
    column: &str,
    token: &crate::FieldValue,
) -> bool {
    crate::query::field_matches_equality(
        fields.get(column).unwrap_or(&crate::FieldValue::Undefined),
        token,
    )
}

pub(super) fn session_tokens_match(
    fields: &FieldMap,
    column: &str,
    tokens: &crate::FieldValue,
) -> AuthResult<bool> {
    let tokens = tokens
        .as_array()
        .ok_or_else(|| AuthError::internal("Value must be an array"))?;
    let actual = fields.get(column).unwrap_or(&crate::FieldValue::Undefined);
    Ok(tokens.iter().any(|token| actual.same_value_zero(token)))
}
