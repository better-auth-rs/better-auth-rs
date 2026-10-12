use super::hooks::CommittedWrite;
use super::rows::RecordSource;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, SessionUpdate};
use crate::store::schema::EntityRole;
use crate::store::schema::resolve_field_name;
#[cfg(test)]
use crate::user_fields::{FieldTransforms, UserFieldTransform};

impl EphemeralStore {
    pub(super) async fn output_session(&self, session: RecordSource) -> AuthResult<SessionView> {
        // Projection preserves the one input row.
        Ok(self.output_sessions(vec![session]).await?.remove(0))
    }

    pub(super) async fn output_sessions(
        &self,
        sessions: Vec<RecordSource>,
    ) -> AuthResult<Vec<SessionView>> {
        self.output_sessions_batches_then(sessions, |ready| std::future::ready(Ok(ready)))
            .await
    }

    pub(super) async fn output_sessions_batches_then<R: Send + 'static, F>(
        &self,
        sessions: Vec<RecordSource>,
        complete: impl Fn(Vec<(usize, SessionView)>) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
    {
        let schema = crate::store::session_create_schema(&self.session_config, &FieldMap::new());
        let rows: Vec<_> = sessions
            .into_iter()
            .map(|source| {
                let stored = source.shallow_fields()?;
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
                Ok((session, source, false))
            })
            .collect::<AuthResult<_>>()?;
        let runtime = self.model_fields.clone();
        crate::user_fields::project_owned_source_fields_batches_then(
            rows,
            schema.fields().clone(),
            move |(_, source, started), name, field| {
                if !*started {
                    runtime.begin_id_output(EntityRole::Session)?;
                    *started = true;
                }
                let physical = if name == "id" {
                    "id"
                } else {
                    resolve_field_name(field.field_name.as_deref(), name)
                };
                Ok(source.field(physical)?.unwrap_or_default())
            },
            |(session, _, _), name, field, value| {
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
                            Some(transform) => transform.call_adapter(value).await?,
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
            |_, (session, _, _)| Ok(session.clone().into_projected_fields()),
            complete,
        )
        .await
    }
}

impl EphemeralStore {
    async fn write_session_create_fields(&self, fields: FieldMap) -> AuthResult<SessionView> {
        let schema = crate::store::session_create_schema(&self.session_config, &fields);
        let force_allow_id = fields.contains_key("id");
        let source = super::raw_records::MemoryRecordModel::new(self, EntityRole::Session, schema)
            .create_ref(fields.into(), FieldMap::new(), force_allow_id)
            .await?;
        self.output_session(RecordSource::Live(source)).await
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
        self.accept_invitation_with_session_effects_values(
            invitation_id,
            user_id,
            session_token,
            teams_enabled,
            maximum,
            Default::default(),
        )
        .await
    }

    async fn accept_invitation_with_session_effects_values(
        &self,
        invitation_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: crate::store::TeamMemberLimits<'_>,
        effects: crate::store::SessionWriteEffects<StatelessSchema>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        self.accept_invitation(
            invitation_id,
            user_id,
            session_token,
            teams_enabled,
            maximum,
            effects,
        )
        .await
    }

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        self.end_session_by_token_value(&token.into()).await
    }

    async fn end_session_by_token_value(&self, token: &crate::FieldValue) -> AuthResult<()> {
        self.delete_sessions_with_hooks(
            || {
                let (column, token) = self.memory_session_token_query(token.clone())?;
                Ok(vec![(column, token, crate::WhereOperator::Eq)])
            },
            true,
        )
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
        let (column, token) = self.memory_session_token_query(token.clone())?;
        let session = self
            .raw("session", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Session)?
                    .select_refs(|row| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(&column)?.unwrap_or_default(),
                            &token,
                        ))
                    })?
                    .into_iter()
                    .next()
                    .map(RecordSource::Live))
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
        Ok(self
            .session_user_relations(token.clone(), false, true)
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
        let tokens = tokens
            .iter()
            .map(|token| token.as_str().into())
            .collect::<Vec<_>>();
        self.session_user_relations(tokens.into(), only_active, false)
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
        let (user_column, user_id) = self.memory_session_field_query("userId", user_id.clone())?;
        let expiry = only_active
            .then(|| self.memory_session_field_query("expiresAt", Utc::now().into()))
            .transpose()?;
        let sessions: Vec<_> = self
            .raw("session", "findMany", |op| {
                Ok(crate::query::paginate_memory(
                    op.capture_table(EntityRole::Session)?
                        .select_refs(|session| {
                            let clauses =
                                std::iter::once((&user_column, &user_id, crate::WhereOperator::Eq))
                                    .chain(expiry.as_ref().map(|(column, value)| {
                                        (column, value, crate::WhereOperator::Gt)
                                    }));
                            crate::memory_query::matches_all(
                                clauses,
                                |(column, value, operator)| {
                                    crate::memory_query::matches(
                                        session.field(column)?.as_ref(),
                                        value,
                                        operator,
                                        crate::WhereMode::Sensitive,
                                    )
                                },
                            )
                        })?
                        .into_iter()
                        .map(RecordSource::Live)
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
            let (column, converted) = self.memory_session_token_query(token.clone())?;
            let session = self
                .raw("session", "findMany", |op| {
                    Ok(op
                        .capture_table(EntityRole::Session)?
                        .select_refs(|row| {
                            Ok(crate::query::field_matches_equality(
                                &row.field(&column)?.unwrap_or_default(),
                                &converted,
                            ))
                        })?
                        .into_iter()
                        .next()
                        .map(RecordSource::Live))
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
        let (column, converted) = self.memory_session_token_query(token.clone())?;
        self.raw("session", "delete", |op| {
            let table = op.capture_table(EntityRole::Session)?;
            let selected = table.select_refs(|row| {
                Ok(crate::query::field_matches_equality(
                    &row.field(&column)?.unwrap_or_default(),
                    &converted,
                ))
            })?;
            op.replace_table(EntityRole::Session, table.without_refs(&selected)?)
        })
        .await?;
        self.after(CommittedWrite::SessionDeleted(session)).await?;
        Ok(())
    }

    async fn delete_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let tokens: Value = tokens
            .iter()
            .map(|token| token.as_str().into())
            .collect::<Vec<_>>()
            .into();
        self.delete_sessions_with_hooks(
            || {
                let (column, tokens) = self.memory_session_token_query(tokens.clone())?;
                Ok(vec![(column, tokens, crate::WhereOperator::In)])
            },
            false,
        )
        .await
        .map(|_| ())
    }

    async fn end_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let tokens: Value = tokens
            .iter()
            .map(|token| token.as_str().into())
            .collect::<Vec<_>>()
            .into();
        self.delete_sessions_with_hooks(
            || {
                let (column, tokens) = self.memory_session_token_query(tokens.clone())?;
                Ok(vec![(column, tokens, crate::WhereOperator::In)])
            },
            true,
        )
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
        self.delete_sessions_with_hooks(
            || {
                let (column, user_id) =
                    self.memory_session_field_query("userId", user_id.clone())?;
                Ok(vec![(column, user_id, crate::WhereOperator::Eq)])
            },
            preserve,
        )
        .await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now = Value::from(Utc::now());
        self.delete_sessions_with_hooks(
            || {
                let (column, now) = self.memory_session_field_query("expiresAt", now.clone())?;
                Ok(vec![(column, now, crate::WhereOperator::Lte)])
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
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
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
        on_update: Some(crate::user_fields::UserFieldFactory::new(|| {
            Ok(Value::from("updated"))
        })),
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
