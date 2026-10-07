use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, SessionUpdate};
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
            self.session_config.fields(),
            |(_, source), name, field| {
                source.read(|row| {
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
                    let value = field.adapter_output(value, field.references_id()).await?;
                    let _ = session.additional_fields.insert(name.to_owned(), value);
                    Ok(())
                })
            },
            |_, (session, source)| {
                let mut session = session.clone();
                session.id = if self.session_config.fields().contains_key("id") {
                    Self::project_id(&session.id)?
                } else {
                    // The implicit ID slot follows application fields; earlier native fields keep their selected values.
                    source.read(|row| Self::project_id(&row.id))?
                };
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
                Ok(session)
            },
            complete,
        )
        .await
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

    async fn before_create_runtime_session(&self, input: &mut CreateSession) -> AuthResult<()> {
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
        input: &mut CreateSession,
    ) -> AuthResult<bool> {
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateSession,
                hook.before_create_session(input, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
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
        mut create_session: CreateSession,
    ) -> AuthResult<Option<SessionView>> {
        if !self
            .before_create_runtime_session_optional(&mut create_session)
            .await?
        {
            return Ok(None);
        }
        let now = crate::FieldDate::from(Utc::now());
        let token = crate::id::random_id(None);
        let schema = self.session_config.field_schema();
        let configured_user_id = schema.fields().contains_key("userId");
        let mut fields = self.session_config.default_fields();
        if configured_user_id {
            let _ = fields
                .entry("userId".into())
                .or_insert_with(|| create_session.user_id.field_value());
        }
        fields.extend(create_session.additional_fields);
        let mut plugin_fields = FieldMap::new();
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            if let Some(value) = fields.remove(name) {
                let _ = plugin_fields.insert(name.into(), value);
            }
        }
        let id = self
            .generated_id("session", None, self.lock()?.sessions.len())?
            .map(crate::SchemaValue::Typed)
            .unwrap_or_default();
        let mut user_id = if configured_user_id {
            create_session.user_id
        } else {
            self.memory_reference_id_input(create_session.user_id.into_field_value())?
        };
        let mut additional_fields = schema
            .storage_fields_with_binding(fields, true, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        if configured_user_id {
            user_id = crate::SchemaValue::from_field(
                additional_fields
                    .remove(schema.record_storage_key("userId"))
                    .unwrap_or_default(),
            );
        }
        let mut session = SessionView {
            visible_fields: Some(
                [
                    ("impersonatedBy", create_session.impersonated_by.is_some()),
                    (
                        "activeOrganizationId",
                        create_session.active_organization_id.is_some(),
                    ),
                ]
                .into_iter()
                .filter(|(_, present)| *present)
                .map(|(name, _)| name.to_owned())
                .collect(),
            ),
            id,
            expires_at: create_session.expires_at,
            token: token.clone(),
            created_at: now.clone(),
            updated_at: now,
            ip_address: create_session.ip_address.or_else(|| Some(String::new())),
            user_agent: create_session.user_agent.or_else(|| Some(String::new())),
            user_id,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active_team_id: None,
            active: true,
            additional_fields,
        };
        for (field, target) in [
            ("impersonatedBy", &mut session.impersonated_by),
            ("activeOrganizationId", &mut session.active_organization_id),
            ("activeTeamId", &mut session.active_team_id),
        ] {
            if let Some(value) = plugin_fields.remove(field) {
                *target = value.decode()?;
                if let Some(visible) = &mut session.visible_fields {
                    let _ = visible.insert(field.into());
                }
            }
        }
        let source = self
            .raw("session", "create", |state| {
                if let Some(id) = self.next_serial_id(state.sessions.len()) {
                    session.id = crate::SchemaValue::from_field(id);
                }
                Ok(SessionSource::Live(state.sessions.push_ref(session)))
            })
            .await?;
        let session = self.output_session(source).await?;
        self.after_create_runtime_session(&session, crate::hooks::current_request_hook_context())
            .await?;
        Ok(Some(session))
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
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
        on_update: Some(Arc::new(|| Value::from("updated"))),
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
