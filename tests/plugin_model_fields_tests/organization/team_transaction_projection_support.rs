use super::*;
use better_auth::plugins::organization::hooks::{
    OrganizationTeamMemberLimit, TeamMemberLimitPolicy,
};
use better_auth_core::user_fields::UserFieldFactory;

struct Limit(Events);

#[async_trait]
impl TeamMemberLimitPolicy for Limit {
    async fn maximum_members_per_team(
        &self,
        data: OrganizationTeamMemberLimit<'_>,
    ) -> AuthResult<usize> {
        let user_value = data.session.user_value()?;
        let user = required(user_value.as_object(), "Expected the capacity actor")?;
        self.0.push(
            "maximum",
            "callback",
            vec![
                data.organization_id.clone(),
                data.team_id.clone(),
                required(user.get("id")?, "Expected the capacity actor ID")?,
            ]
            .into(),
        )?;
        Ok(3)
    }
}

fn timestamp(events: &Events, model: &'static str, fail: bool) -> UserFieldConfig {
    let input = events.clone();
    let output = events.clone();
    UserFieldConfig {
        field_type: UserFieldType::Date,
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                let _ = required(value.as_date(), "Expected a native transaction timestamp")?;
                input.push(&format!("{model}.createdAt"), "input", "native-date".into())?;
                if fail {
                    return Err(AuthError::internal("member-create-failed"));
                }
                Ok(date(0).into())
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output.push(&format!("{model}.createdAt"), "output", value)?;
                Ok(date(0).into())
            })),
        }),
        ..Default::default()
    }
}

pub(super) async fn auth<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    events: &Events,
    run: Run,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut config.logger else {
            return Err(AuthError::internal(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    config.advanced.database.joins = Some(run.joins);
    let sequence = AtomicUsize::new(0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            Ok(Some(if request.model == "teamMember" {
                format!("teamMember-{}", sequence.fetch_add(1, Ordering::SeqCst) + 1)
            } else {
                format!("{}-a", request.model)
            }))
        })));
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    options.teams.maximum_members_per_team_callback = Some(Arc::new(Limit(events.clone())));
    options.schema.team = declaration([
        (
            "id",
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        ),
        (
            "name",
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        ),
    ]);
    let called = events.clone();
    let function: UserFieldFactory = UserFieldFactory::new(move || {
        called.push("team.name", "called", FieldValue::Undefined)?;
        Ok("called".into())
    });
    let function = FieldValue::Function(function.into());
    let name_events = events.clone();
    let organization_events = events.clone();
    let team = declaration([
        (
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        name_events.push("team.name", "output", value.clone())?;
                        Ok(if run.scenario.clone_at(value.as_str()) {
                            function.clone()
                        } else {
                            value
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "organizationId",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        organization_events.push("team.organizationId", "output", value.clone())?;
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ]);
    let mut session = declaration([(
        "updatedAt",
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(|| {
                Ok(date(0).into())
            })),
            transform: Some(FieldTransforms {
                input: Some({
                    let events = events.clone();
                    UserFieldTransform::new(move |value| {
                        let _ = required(
                            value.as_date(),
                            "Expected a native Session update timestamp",
                        )?;
                        events.push("session.updatedAt", "input", "native-date".into())?;
                        Ok(date(0).into())
                    })
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    for name in ["activeOrganizationId", "activeTeamId"] {
        let events = events.clone();
        let _ = session.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        events.push(&format!("session.{name}"), "input", value.clone())?;
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let invitation_events = events.clone();
    let invitation = declaration([(
        "status",
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    invitation_events.push("invitation.status", "output", value.clone())?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    BetterAuth::new(config)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (EntityRole::Team, team),
            (
                EntityRole::TeamMember,
                declaration([("createdAt", timestamp(events, "teamMember", false))]),
            ),
            (
                EntityRole::Member,
                declaration([(
                    "createdAt",
                    timestamp(events, "member", run.scenario == Scenario::MemberError),
                )]),
            ),
            (EntityRole::Session, session),
            (EntityRole::Invitation, invitation),
        ]))
        .build()
        .await
}

pub(super) fn expected_events(storage: &Storage, scenario: Scenario) -> Vec<FieldValue> {
    let mut events = if scenario.add() {
        Vec::new()
    } else {
        vec![
            event("invitation.status", "output", "pending".into()),
            event("invitation.status", "output", "accepted".into()),
        ]
    };
    let member_input = event("member.createdAt", "input", "native-date".into());
    let member_output = event("member.createdAt", "output", storage.stored_date(0));
    for (index, id) in scenario.team_ids().split(',').enumerate() {
        if scenario.mismatch() {
            break;
        }
        let name = if id == "team-a" { "Team A" } else { "Team B" };
        let parent = [
            event("team.name", "output", name.into()),
            event("team.organizationId", "output", "organization".into()),
        ];
        events.extend(parent.clone());
        if scenario.clone_at(Some(name)) {
            break;
        }
        if scenario.add() {
            events.extend([member_input.clone(), member_output.clone()]);
        }
        events.push(event(
            "maximum",
            "callback",
            vec!["organization".into(), id.into(), "user-b".into()].into(),
        ));
        events.extend(parent);
        events.extend([
            event("teamMember.createdAt", "input", "native-date".into()),
            event("teamMember.createdAt", "output", storage.stored_date(0)),
        ]);
        if index == 0 && !scenario.many() && !scenario.add() {
            events.extend([
                event("session.updatedAt", "input", "native-date".into()),
                event("session.activeTeamId", "input", id.into()),
            ]);
        }
    }
    if !scenario.add()
        && !scenario.mismatch()
        && !matches!(scenario, Scenario::AcceptClone | Scenario::SecondClone)
    {
        events.push(member_input);
        if scenario != Scenario::MemberError {
            events.push(member_output);
            events.extend([
                event("session.updatedAt", "input", "native-date".into()),
                event(
                    "session.activeOrganizationId",
                    "input",
                    "organization".into(),
                ),
            ]);
        }
    }
    if !scenario.add() && !scenario.success() {
        events.push(event("invitation.status", "output", "pending".into()));
    }
    events
}

fn column(storage: &Storage, native: &'static str, sql: &'static str) -> &'static str {
    if matches!(storage, Storage::Sqlite(_)) {
        sql
    } else {
        native
    }
}

pub(super) fn update_snapshot(
    storage: &Storage,
    scenario: Scenario,
    snapshot: &mut fixture::Snapshot,
) -> AuthResult<()> {
    if !scenario.success() {
        return Ok(());
    }
    let members = snapshot
        .get_mut("member")
        .ok_or_else(|| AuthError::internal("Missing Member snapshot"))?;
    members.insert(
        0,
        [
            ("id".into(), "member-a".into()),
            (
                column(storage, "organizationId", "organization_id").into(),
                "organization".into(),
            ),
            (column(storage, "userId", "user_id").into(), "user-b".into()),
            ("role".into(), "member".into()),
            (
                column(storage, "createdAt", "created_at").into(),
                storage.stored_date(0),
            ),
        ]
        .into(),
    );
    for (index, id) in scenario.team_ids().split(',').enumerate() {
        snapshot
            .get_mut("teamMember")
            .ok_or_else(|| AuthError::internal("Missing TeamMember snapshot"))?
            .push(
                [
                    ("id".into(), format!("teamMember-{}", index + 1).into()),
                    (column(storage, "teamId", "team_id").into(), id.into()),
                    (column(storage, "userId", "user_id").into(), "user-b".into()),
                    (
                        column(storage, "membershipKey", "membership_key").into(),
                        key(id, "user-b")?.into(),
                    ),
                    (
                        column(storage, "createdAt", "created_at").into(),
                        storage.stored_date(0),
                    ),
                ]
                .into(),
            );
        let team = snapshot
            .get_mut("team")
            .and_then(|rows| {
                rows.iter_mut()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(id))
            })
            .ok_or_else(|| AuthError::internal("Missing updated Team snapshot"))?;
        let _ = team.insert(
            column(storage, "memberCount", "member_count").into(),
            1.into(),
        );
    }
    if !scenario.add() {
        let invitation = snapshot
            .get_mut("invitation")
            .and_then(|rows| rows.first_mut())
            .ok_or_else(|| AuthError::internal("Missing Invitation snapshot"))?;
        let _ = invitation.insert("status".into(), "accepted".into());
        let session = snapshot
            .get_mut("session")
            .and_then(|rows| rows.first_mut())
            .ok_or_else(|| AuthError::internal("Missing Session snapshot"))?;
        let _ = session.insert(
            column(storage, "activeOrganizationId", "active_organization_id").into(),
            "organization".into(),
        );
        let _ = session.insert(
            column(storage, "updatedAt", "updated_at").into(),
            storage.stored_date(0),
        );
        if !scenario.many() {
            let _ = session.insert(
                column(storage, "activeTeamId", "active_team_id").into(),
                "team-a".into(),
            );
        }
    }
    Ok(())
}
