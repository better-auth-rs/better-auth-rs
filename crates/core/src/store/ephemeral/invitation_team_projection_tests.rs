#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report callback and storage regressions; fixture setup errors propagate through Result."
)]

use super::rows::RowRef;
use super::*;
use crate::id::IdGeneration;
use crate::organization_fields::OrganizationFields;
use crate::store::schema::EntityRole;
use crate::store::{TeamMemberLimitResolver, TeamMemberLimits};
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Events = Arc<Mutex<Vec<(&'static str, Value)>>>;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a stored invitation fixture row"))
}

fn events_snapshot(events: &Events) -> AuthResult<Vec<(&'static str, Value)>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Event lock poisoned"))
        .map(|events| events.clone())
}

fn event(events: &Events, name: &'static str, value: Value) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Event lock poisoned"))?
        .push((name, value));
    Ok(())
}

fn seed_team(
    store: &EphemeralStore,
    id: Value,
    name: &str,
    organization: Value,
    count: f64,
) -> AuthResult<RowRef<FieldMap>> {
    store.operation(|op| {
        op.capture_table(EntityRole::Team)?.push(
            [
                ("id".into(), id),
                ("name".into(), name.into()),
                ("organizationId".into(), organization),
                ("createdAt".into(), Utc::now().into()),
                ("memberCount".into(), Value::Number(count)),
            ]
            .into(),
        )
    })
}

fn membership(id: Value, team: Value, user: &str) -> FieldMap {
    [
        ("id".into(), id),
        ("teamId".into(), team),
        ("userId".into(), user.into()),
        ("membershipKey".into(), user.into()),
        ("createdAt".into(), Utc::now().into()),
    ]
    .into()
}

async fn invitation(
    store: &EphemeralStore,
    organization: &str,
    teams: &str,
) -> AuthResult<Invitation> {
    let mut input = CreateInvitation::new(
        organization,
        "recipient@example.com",
        "member",
        "9",
        (Utc::now() + chrono::Duration::days(1)).into(),
    );
    input.team_id = Some(teams.into());
    store.create_invitation(input).await
}

struct ProjectionLimits {
    calls: AtomicUsize,
    events: Events,
    fields: UserConfig,
}

#[async_trait]
impl TeamMemberLimitResolver for ProjectionLimits {
    fn team_output_fields(&self) -> Option<&UserConfig> {
        Some(&self.fields)
    }

    async fn maximum(&self, team_id: &str, _: &Value) -> AuthResult<Option<usize>> {
        event(&self.events, "maximum", team_id.into())?;
        Ok(Some(if self.calls.fetch_add(1, Ordering::SeqCst) == 2 {
            0
        } else {
            1
        }))
    }
}

#[tokio::test]
async fn acceptance_reads_live_teams_and_pending_seats_without_callback_replay() -> AuthResult<()> {
    for serial in [false, true] {
        for outcome in ["commit", "reject", "conflict"] {
            let mut config = (*test_config()).clone();
            if serial {
                config.advanced.database.generate_id = Some(IdGeneration::Serial);
            }
            let store = EphemeralStore::new(Arc::new(config));
            let (organization, user, first_selector, second_selector, duplicate) = if serial {
                ("1", "3", "01", "02", "1")
            } else {
                ("organization", "recipient", "first", "second", "first")
            };
            let owner = if serial {
                Value::Number(1.0)
            } else {
                organization.into()
            };
            let first = seed_team(
                &store,
                if serial {
                    Value::Number(1.0)
                } else {
                    "first".into()
                },
                "First",
                owner.clone(),
                0.0,
            )?;
            let second = seed_team(
                &store,
                if serial {
                    Value::Number(2.0)
                } else {
                    "second".into()
                },
                "Second",
                "other".into(),
                0.0,
            )?;
            let claimed = invitation(
                &store,
                organization,
                &format!("{first_selector},{second_selector},{duplicate}"),
            )
            .await?;
            let original_teams = store.storage_rows(EntityRole::Team)?;
            let events = Events::default();
            let mut fields = OrganizationFields::default();
            let _ = fields.team.fields_mut().insert(
                "name".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            let second = second.clone();
                            let owner = owner.clone();
                            let changed = AtomicBool::new(false);
                            move |value| {
                                event(&events, "team.name", value.clone())?;
                                if !changed.swap(true, Ordering::SeqCst) {
                                    second.apply_patch(
                                        [
                                            ("name".into(), "Second live".into()),
                                            ("organizationId".into(), owner.clone()),
                                        ]
                                        .into(),
                                    )?;
                                }
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let _ = fields.team.fields_mut().insert(
                "memberCount".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "team.count", value.clone())?;
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let _ = fields.member.fields_mut().insert(
                "role".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new({
                            let events = events.clone();
                            let first = first.clone();
                            move |value| {
                                event(&events, "member.input", value.clone())?;
                                if outcome == "reject" {
                                    return Err(AuthError::type_error("member-rejected"));
                                }
                                if outcome == "conflict" {
                                    first.set_field("memberCount".into(), Value::Number(9.0))?;
                                }
                                Ok(value)
                            }
                        })),
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "member.output", value.clone())?;
                                Ok(value)
                            }
                        })),
                    }),
                    ..Default::default()
                },
            );
            let _ = fields.invitation.fields_mut().insert(
                "status".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "invitation", value.clone())?;
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let limits = ProjectionLimits {
                calls: AtomicUsize::new(0),
                events: events.clone(),
                fields: fields.team.clone(),
            };
            store.configure_organization_fields(fields)?;
            let result = store
                .accept_invitation_with_teams(
                    claimed.id.typed()?,
                    user,
                    None,
                    true,
                    TeamMemberLimits::Resolver(&limits),
                )
                .await;
            match outcome {
                "commit" => {
                    let _ = result?;
                }
                "reject" => assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "member-rejected")
                ),
                _ => assert!(matches!(result, Err(AuthError::Conflict(_)))),
            }
            let mut expected = vec![
                ("invitation", "accepted".into()),
                ("team.name", "First".into()),
                ("team.count", Value::Number(0.0)),
                ("maximum", first_selector.into()),
                ("team.name", "First".into()),
                ("team.count", Value::Number(1.0)),
                ("team.name", "Second live".into()),
                ("team.count", Value::Number(0.0)),
                ("maximum", second_selector.into()),
                ("team.name", "Second live".into()),
                ("team.count", Value::Number(1.0)),
                ("team.name", "First".into()),
                ("team.count", Value::Number(1.0)),
                ("maximum", duplicate.into()),
                ("member.input", "member".into()),
            ];
            if outcome != "reject" {
                expected.push(("member.output", "member".into()));
            }
            if outcome != "commit" {
                expected.push(("invitation", "pending".into()));
            }
            assert_eq!(
                events_snapshot(&events)?,
                expected,
                "{outcome}, serial={serial}"
            );
            assert_eq!(limits.calls.load(Ordering::SeqCst), 3);
            let mut expected_teams = original_teams;
            let second = required(expected_teams.get_mut(1))?;
            let _ = second.insert("name".into(), "Second live".into());
            let _ = second.insert("organizationId".into(), owner);
            if outcome == "commit" {
                for row in &mut expected_teams {
                    let _ = row.insert("memberCount".into(), Value::Number(1.0));
                }
            } else if outcome == "conflict" {
                let _ = required(expected_teams.first_mut())?
                    .insert("memberCount".into(), Value::Number(9.0));
            }
            let state = store.operation(|op| op.capture_state())?;
            assert_eq!(state.fixture_table("team").snapshot()?, expected_teams);
            assert_eq!(
                state.fixture_table("member").len()?,
                usize::from(outcome == "commit")
            );
            assert_eq!(
                state.fixture_table("teamMember").len()?,
                if outcome == "commit" { 2 } else { 0 }
            );
            let rows = state.fixture_table("invitation").snapshot()?;
            assert_eq!(
                required(rows.first())?.get("status"),
                Some(&Value::from(if outcome == "commit" {
                    "accepted"
                } else {
                    "pending"
                }))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn pending_team_scope_patch_is_used_by_the_next_scoped_lookup() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let _ = seed_team(&store, "first".into(), "First", "organization".into(), -1.0)?;
    let claimed = invitation(&store, "organization", "first,first").await?;
    let original = store.storage_rows(EntityRole::Team)?;
    let events = Events::default();
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "organizationId".into(),
        UserFieldConfig {
            on_update: Some(crate::user_fields::UserFieldFactory::new(|| {
                Ok("other".into())
            })),
            ..Default::default()
        },
    );
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "count", value.clone())?;
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let limits = ProjectionLimits {
        calls: AtomicUsize::new(0),
        events: events.clone(),
        fields: fields.team.clone(),
    };
    store.configure_organization_fields(fields)?;
    let result = store
        .accept_invitation_with_teams(
            claimed.id.typed()?,
            "recipient",
            None,
            true,
            TeamMemberLimits::Resolver(&limits),
        )
        .await;
    let error = result.err().ok_or_else(|| {
        AuthError::internal("The changed team scope did not reject the next lookup")
    })?;
    assert_eq!(error.status_value()?, Value::from("BAD_REQUEST"));
    assert_eq!(
        error.body_value()?,
        Value::from(FieldMap::from([
            ("message".into(), "Team not found".into()),
            ("code".into(), "TEAM_NOT_FOUND".into()),
        ]))
    );
    assert_eq!(
        events_snapshot(&events)?,
        vec![
            ("count", Value::Number(-1.0)),
            ("maximum", "first".into()),
            ("count", Value::Number(0.0)),
            ("count", Value::Number(1.0))
        ]
    );
    let state = store.operation(|op| op.capture_state())?;
    assert_eq!(state.fixture_table("team").snapshot()?, original);
    assert_eq!(state.fixture_table("teamMember").len()?, 0);
    assert_eq!(state.fixture_table("member").len()?, 0);
    assert_eq!(
        required(state.fixture_table("invitation").snapshot()?.first())?.get("status"),
        Some(&Value::from("pending"))
    );
    Ok(())
}

struct ConcurrentMembershipLimits {
    store: EphemeralStore,
    calls: AtomicUsize,
    serial: bool,
    concurrent: FieldMap,
}

#[async_trait]
impl TeamMemberLimitResolver for ConcurrentMembershipLimits {
    async fn maximum(&self, _: &str, _: &Value) -> AuthResult<Option<usize>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.store.operation(|op| {
            let table = op.capture_table(EntityRole::TeamMember)?;
            if self.serial && call == 1 {
                let mut selected =
                    table.select_refs(|row| Ok(row.field("id")? == Some(Value::Number(1.0))))?;
                selected.truncate(1);
                let table = table.without_refs(&selected)?;
                table.push(self.concurrent.clone())?;
                op.replace_table(EntityRole::TeamMember, table)?;
            } else if !self.serial {
                if call == 0 {
                    table.push(self.concurrent.clone())?;
                } else {
                    let mut selected = table
                        .select_refs(|row| Ok(row.field("id")? == Some(Value::from("external"))))?;
                    selected.truncate(1);
                    op.replace_table(EntityRole::TeamMember, table.without_refs(&selected)?)?;
                }
            }
            Ok(())
        })?;
        Ok(Some(1))
    }
}

#[tokio::test]
async fn membership_refresh_preserves_external_deletion_and_serial_allocation() -> AuthResult<()> {
    for serial in [false, true] {
        let mut config = (*test_config()).clone();
        if serial {
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
        }
        let store = EphemeralStore::new(Arc::new(config));
        let (organization, teams, user) = if serial {
            ("1", "1,2", "3")
        } else {
            ("organization", "first,second", "recipient")
        };
        let owner = if serial {
            Value::Number(1.0)
        } else {
            organization.into()
        };
        let _ = seed_team(
            &store,
            if serial {
                Value::Number(1.0)
            } else {
                "first".into()
            },
            "First",
            owner.clone(),
            0.0,
        )?;
        let _ = seed_team(
            &store,
            if serial {
                Value::Number(2.0)
            } else {
                "second".into()
            },
            "Second",
            owner,
            0.0,
        )?;
        if serial {
            store.operation(|op| {
                op.capture_table(EntityRole::TeamMember)?.push(membership(
                    Value::Number(1.0),
                    Value::Number(9.0),
                    "previous",
                ))?;
                Ok(())
            })?;
        }
        let concurrent = membership(
            if serial {
                Value::Number(2.0)
            } else {
                "external".into()
            },
            if serial {
                Value::Number(9.0)
            } else {
                "outside".into()
            },
            "external",
        );
        let limits = ConcurrentMembershipLimits {
            store: store.clone(),
            calls: AtomicUsize::new(0),
            serial,
            concurrent: concurrent.clone(),
        };
        let claimed = invitation(&store, organization, teams).await?;
        let result = store
            .accept_invitation_with_teams(
                claimed.id.typed()?,
                user,
                None,
                true,
                TeamMemberLimits::Resolver(&limits),
            )
            .await;
        if serial {
            assert!(matches!(result, Err(AuthError::Conflict(_))));
        } else {
            let _ = result?;
        }
        assert_eq!(limits.calls.load(Ordering::SeqCst), 2);
        let state = store.operation(|op| op.capture_state())?;
        let memberships = state.fixture_table("teamMember").snapshot()?;
        if serial {
            assert_eq!(memberships, vec![concurrent]);
        } else {
            assert_eq!(memberships.len(), 2);
            assert!(
                memberships
                    .iter()
                    .all(|row| row.get("userId") == Some(&Value::from(user)))
            );
        }
        assert_eq!(state.fixture_table("member").len()?, usize::from(!serial));
        for team in state.fixture_table("team").snapshot()? {
            assert_eq!(
                team.get("memberCount"),
                Some(&Value::Number(if serial { 0.0 } else { 1.0 }))
            );
        }
        assert_eq!(
            required(state.fixture_table("invitation").snapshot()?.first())?.get("status"),
            Some(&Value::from(if serial { "pending" } else { "accepted" }))
        );
    }
    Ok(())
}

struct SessionAcceptanceHooks {
    writer: EphemeralStore,
    events: Events,
    mode: &'static str,
}

#[crate::database_hooks()]
impl crate::store::database_hooks::DatabaseHooks<StatelessSchema> for SessionAcceptanceHooks {
    async fn before_update_session(
        &self,
        fields: &mut FieldMap,
        context: &crate::store::database_hooks::DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<crate::store::database_hooks::DatabaseHookUpdate<FieldMap>> {
        use crate::store::database_hooks::DatabaseHookUpdate;
        let team = fields.contains_key("activeTeamId");
        let phase = if team { "team" } else { "organization" };
        event(&self.events, "before", phase.into())?;
        let transaction = required(context.transaction)?;
        let state = self.writer.operation(|op| op.capture_state())?;
        assert_eq!(state.fixture_table("member").len()?, 0);
        assert_eq!(state.fixture_table("user").len()?, 0);
        assert_eq!(
            required(state.fixture_table("team").snapshot()?.first())?.get("memberCount"),
            Some(&Value::Number(0.0))
        );
        assert_eq!(
            required(transaction.get_team_value(&"team".into()).await?)?
                .additional_fields
                .get("memberCount"),
            Some(&Value::Number(1.0))
        );
        assert_eq!(
            transaction
                .count_organization_members_value(&"organization".into())
                .await?,
            i64::from(!team)
        );
        if team {
            let _ = required(
                transaction
                    .create_user_fields_optional(
                        [
                            ("name".into(), "Created by Session hook".into()),
                            ("email".into(), "hook@example.com".into()),
                        ]
                        .into(),
                    )
                    .await?,
            )?;
        }
        if self.mode == "before" && !team {
            return Err(AuthError::type_error("before-session"));
        }
        if (self.mode == "cancel-team" && team) || (self.mode == "cancel-organization" && !team) {
            return Ok(DatabaseHookUpdate::Cancel);
        }
        Ok(DatabaseHookUpdate::Patch(
            [("ipAddress".into(), phase.into())].into(),
        ))
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        context: &crate::store::database_hooks::DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        assert_eq!(
            required(user)?.email.field_value(),
            "hook@example.com".into()
        );
        let state = self.writer.operation(|op| op.capture_state())?;
        assert_eq!(state.fixture_table("member").len()?, 1);
        assert_eq!(state.fixture_table("user").len()?, 1);
        event(&self.events, "after.user", "committed".into())
    }

    async fn after_update_session(
        &self,
        session: Option<&SessionView>,
        context: &crate::store::database_hooks::DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        let state = self.writer.operation(|op| op.capture_state())?;
        assert_eq!(state.fixture_table("member").len()?, 1);
        assert_eq!(state.fixture_table("teamMember").len()?, 1);
        assert_eq!(
            required(state.fixture_table("invitation").snapshot()?.first())?.get("status"),
            Some(&Value::from("accepted"))
        );
        event(
            &self.events,
            "after.session",
            required(session)?.ip_address.field_value(),
        )?;
        if self.mode == "after" {
            return Err(AuthError::type_error("after-session"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn acceptance_session_writes_share_transaction_hooks_projection_and_ownership()
-> AuthResult<()> {
    for mode in [
        "commit",
        "before",
        "output",
        "after",
        "external",
        "cancel-team",
        "cancel-organization",
    ] {
        let writer = EphemeralStore::new(test_config());
        let _ = seed_team(&writer, "team".into(), "Team", "organization".into(), 0.0)?;
        let claimed = invitation(&writer, "organization", "team").await?;
        let session = writer
            .create_session(CreateSession {
                inherited_fields: FieldMap::new(),
                additional_fields: [
                    ("token".into(), "accept-session".into()),
                    ("activeOrganizationId".into(), Value::Null),
                ]
                .into(),
                user_id: "recipient".into(),
                expires_at: (Utc::now() + chrono::Duration::days(1)).into(),
                ip_address: Some("initial".into()),
                user_agent: Some("initial-agent".into()),
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let original =
            writer.operation(|op| required(op.capture_table(EntityRole::Session)?.row_at(0)?))?;
        let original_fields = original.shallow_fields()?;
        let events = Events::default();
        let mut reader = writer
            .clone()
            .with_hooks(vec![Arc::new(SessionAcceptanceHooks {
                writer: writer.clone(),
                events: events.clone(),
                mode,
            })]);
        let _ = reader.session_config.fields_mut().insert(
            "ipAddress".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        let original = original.clone();
                        move |value| {
                            event(&events, "output.ip", value.clone())?;
                            if mode == "output" && value == Value::from("organization") {
                                return Err(AuthError::type_error("output-session"));
                            }
                            if mode == "external" && value == Value::from("team") {
                                original.set_field("userAgent".into(), "external-agent".into())?;
                            }
                            Ok(format!("{}:projected", required(value.as_str())?).into())
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let _ = reader.session_config.fields_mut().insert(
            "userAgent".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            event(&events, "output.agent", value.clone())?;
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let result = reader
            .accept_invitation_with_teams(
                claimed.id.typed()?,
                "recipient",
                Some(session.token.typed()?),
                true,
                TeamMemberLimits::Fixed(Some(1)),
            )
            .await;
        let committed = matches!(mode, "commit" | "after" | "cancel-organization");
        match mode {
            "commit" | "cancel-organization" => {
                let (_, accepted, cookie) = result?;
                assert_eq!(accepted.status, InvitationStatus::Accepted);
                let cookie = required(cookie)?;
                assert_eq!(
                    cookie.ip_address.field_value(),
                    Value::from("team:projected")
                );
                assert_eq!(
                    cookie.user_agent.field_value(),
                    Value::from("initial-agent")
                );
                assert_eq!(cookie.active_team_id.field_value(), Value::from("team"));
                assert_eq!(cookie.active_organization_id.field_value(), Value::Null);
            }
            "external" => assert!(matches!(result, Err(AuthError::Conflict(_)))),
            "cancel-team" => assert!(
                matches!(result, Err(AuthError::TypeError(message)) if message == "Cannot read properties of null (reading 'token')")
            ),
            _ => assert!(
                matches!(result, Err(AuthError::TypeError(message)) if message == format!("{mode}-session"))
            ),
        }
        let mut expected = vec![("before", "team".into())];
        if mode != "cancel-team" {
            expected.extend([
                ("output.ip", "team".into()),
                ("output.agent", "initial-agent".into()),
                ("before", "organization".into()),
            ]);
            if mode != "before" && mode != "cancel-organization" {
                expected.push(("output.ip", "organization".into()));
                if mode != "output" {
                    expected.push(("output.agent", "initial-agent".into()));
                }
            }
        }
        if committed {
            expected.extend([
                ("after.user", "committed".into()),
                ("after.session", "team:projected".into()),
            ]);
            if mode == "commit" {
                expected.push(("after.session", "organization:projected".into()));
            }
        }
        assert_eq!(events_snapshot(&events)?, expected, "{mode}");
        let state = writer.operation(|op| op.capture_state())?;
        assert_eq!(
            state.fixture_table("member").len()?,
            usize::from(committed),
            "{mode}"
        );
        assert_eq!(
            state.fixture_table("teamMember").len()?,
            usize::from(committed),
            "{mode}"
        );
        assert_eq!(
            state.fixture_table("user").len()?,
            usize::from(committed),
            "{mode}"
        );
        assert_eq!(
            state.fixture_table("session").contains_ref(&original)?,
            !committed,
            "{mode}"
        );
        assert_eq!(
            required(state.fixture_table("team").snapshot()?.first())?.get("memberCount"),
            Some(&Value::Number(if committed { 1.0 } else { 0.0 })),
            "{mode}"
        );
        assert_eq!(
            required(state.fixture_table("invitation").snapshot()?.first())?.get("status"),
            Some(&Value::from(
                if matches!(mode, "commit" | "cancel-organization") {
                    "accepted"
                } else {
                    "pending"
                }
            )),
            "{mode}"
        );
        let stored = required(
            state
                .fixture_table("session")
                .snapshot()?
                .into_iter()
                .next(),
        )?;
        if committed {
            assert_eq!(stored.get("activeTeamId"), Some(&Value::from("team")));
            assert_eq!(
                stored.get("activeOrganizationId"),
                Some(&if mode == "cancel-organization" {
                    Value::Null
                } else {
                    "organization".into()
                })
            );
            assert_eq!(
                stored.get("ipAddress"),
                Some(&Value::from(if mode == "cancel-organization" {
                    "team"
                } else {
                    "organization"
                }))
            );
            assert_eq!(stored.get("userAgent"), Some(&Value::from("initial-agent")));
            assert_eq!(original.shallow_fields()?, original_fields);
        } else {
            let mut expected = original_fields;
            if mode == "external" {
                let _ = expected.insert("userAgent".into(), "external-agent".into());
            }
            assert_eq!(stored, expected, "{mode}");
        }
    }
    Ok(())
}
