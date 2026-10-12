#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::member_contract_support::{
    Storage, date, memory_fixture, ordered, seed, sqlite_fixture,
};
use super::*;
use better_auth::plugins::organization::hooks::{OrganizationHooks, OrganizationTeamEvent};
use better_auth::server_api::EndpointInput;
use better_auth_core::id::{IdGeneration, IdGenerator};
use better_auth_core::{AuthRecordFields, CreateInvitation, HttpMethod, InvitationStatus};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

type Events = Arc<Mutex<Vec<FieldValue>>>;
type Ids = Arc<Mutex<String>>;
type Snapshot = std::collections::BTreeMap<String, Vec<FieldMap>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    MappedOwner,
    MovedOwner,
    DeletedTeam,
    InvitationError,
    AfterError,
    HiddenId,
    WrongProjectedOwner,
}

impl Case {
    const ALL: [Self; 7] = [
        Self::MappedOwner,
        Self::MovedOwner,
        Self::DeletedTeam,
        Self::InvitationError,
        Self::AfterError,
        Self::HiddenId,
        Self::WrongProjectedOwner,
    ];
}

fn declaration(fields: impl IntoIterator<Item = (&'static str, UserFieldConfig)>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            fields
                .into_iter()
                .map(|(name, field)| (name.into(), field))
                .collect(),
        ),
    }
}

fn event(field: &str, phase: &str, value: FieldValue) -> FieldValue {
    vec![field.into(), phase.into(), value].into()
}

fn record(events: &Events, field: &str, phase: &str, value: FieldValue) -> AuthResult<()> {
    trace_lock(events)?.push(event(field, phase, value));
    Ok(())
}

fn settings(ids: Ids) -> AuthResult<AuthConfig> {
    let mut settings = config();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut settings.logger else {
            return Err(AuthError::internal(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    settings.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(trace_lock(&ids)?.clone()))
        })));
    Ok(settings)
}

async fn team_schema(database: &DatabaseConnection) -> AuthResult<Vec<FieldMap>> {
    database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT json_object('type', type, 'name', name, 'table', tbl_name, 'sql', sql) AS value
             FROM sqlite_schema WHERE tbl_name = 'team' ORDER BY type, name",
        ))
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?
        .into_iter()
        .map(|row| {
            let value = row
                .try_get::<String>("", "value")
                .map_err(|error| AuthError::internal(error.to_string()))?;
            FieldMap::from_json(serde_json::from_str(&value)?)
        })
        .collect()
}

async fn make_original_owner_nullable(storage: &Storage) -> AuthResult<()> {
    let Storage::Sqlite(database) = storage else {
        return Ok(());
    };
    let before = storage.snapshot().await?;
    assert!(required(before.get("team"), "Expected Team table")?.is_empty());
    let mut schema = team_schema(database).await?;
    let table = required(
        schema
            .iter_mut()
            .find(|row| row.get("type").and_then(FieldValue::as_str) == Some("table")),
        "Expected Team table declaration",
    )?;
    let sql = required(
        table.get("sql").and_then(FieldValue::as_str),
        "Expected Team table SQL",
    )?;
    let (prefix, declaration) = required(
        sql.split_once("\"organization_id\" "),
        "Expected owner column declaration",
    )?;
    let (column, suffix) = required(
        declaration.split_once(','),
        "Expected following Team column",
    )?;
    let column_type = required(
        column.strip_suffix(" NOT NULL"),
        "Expected required owner column",
    )?;
    let sql = format!("{prefix}\"organization_id\" {column_type},{suffix}");
    let _ = table.insert("sql".into(), sql.clone().into());
    // Preserve the original table definition and indexes while making the remapped column optional.
    let statements = ["DROP TABLE \"team\"".to_owned(), sql].into_iter().chain(
        schema
            .iter()
            .filter(|row| row.get("type").and_then(FieldValue::as_str) != Some("table"))
            .filter_map(|row| {
                row.get("sql")
                    .and_then(FieldValue::as_str)
                    .map(str::to_owned)
            }),
    );
    for statement in statements {
        let _ = database
            .execute_raw(Statement::from_string(DbBackend::Sqlite, statement))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
    }
    assert_eq!(team_schema(database).await?, schema);
    assert_eq!(storage.snapshot().await?, before);
    Ok(())
}

async fn writer<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, ids: Ids) -> AuthResult<BetterAuth<S>> {
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    BetterAuth::new(settings(ids)?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (
                EntityRole::Team,
                declaration([(
                    "updatedAt",
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                            || Ok(date().into()),
                        )),
                        ..Default::default()
                    },
                )]),
            ),
            (
                EntityRole::TeamMember,
                declaration([(
                    "createdAt",
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(|_| Ok(date().into()))),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]),
            ),
        ]))
        .build()
        .await
}

async fn invitation<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    id: &str,
    owner: &str,
    status: InvitationStatus,
    teams: &str,
) -> AuthResult<()> {
    let mut input = CreateInvitation::new(
        owner,
        "user-b@fields.test",
        "member",
        "user-a",
        FieldDate::from_milliseconds(4_102_444_800_000.0),
    );
    input.id = Some(id.into());
    input.created_at = Some(date());
    input.status = Some(status);
    input.team_id = Some(teams.into());
    let result = store.create_invitation(input).await?;
    assert_eq!(result.id.field_value(), FieldValue::from(id));
    Ok(())
}

async fn seed_teams<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    writer: &dyn AuthStore<S>,
    ids: &Ids,
    case: Case,
) -> AuthResult<()> {
    let _ = seed(raw.clone(), false, "user-a").await?;
    let _ = raw
        .insert_organization(Organization {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: "other".into(),
            name: "Other".into(),
            slug: "other".into(),
            logo: None.into(),
            metadata: Some(FieldValue::from("{}")).into(),
            created_at: date().into(),
        })
        .await?;
    for (id, name) in [("target-team", "Target"), ("retained-team", "Retained")] {
        let mapped = id == "target-team" && case == Case::MappedOwner;
        let team = writer
            .create_team(CreateTeam {
                id: Some(id.into()),
                name: if mapped { "organization" } else { name }.into(),
                organization_id: if mapped { "other" } else { "organization" }.into(),
                created_at: Some(date()),
                updated_at: Some(date()),
                ..Default::default()
            })
            .await?;
        assert_eq!(team.id.field_value(), FieldValue::from(id));
        *trace_lock(ids)? = format!("{id}-member");
        let member = required(
            writer.add_team_member(&team.id, "user-b", None).await?,
            "Expected seeded TeamMember",
        )?;
        assert_eq!(
            member.id.field_value(),
            FieldValue::from(format!("{id}-member"))
        );
    }
    invitation(
        writer,
        "invitation-a",
        "organization",
        InvitationStatus::Pending,
        if case == Case::DeletedTeam {
            "retained-team"
        } else {
            "target-team,retained-team"
        },
    )
    .await?;
    invitation(
        writer,
        "invitation-other",
        "other",
        InvitationStatus::Pending,
        "target-team,retained-team",
    )
    .await?;
    invitation(
        writer,
        "invitation-accepted",
        "organization",
        InvitationStatus::Accepted,
        "target-team",
    )
    .await?;
    Ok(())
}

fn hook_fields(data: OrganizationTeamEvent<'_>) -> AuthResult<FieldValue> {
    Ok(FieldMap::from_iter([
        ("team".into(), data.team.field_values()?.into()),
        (
            "user".into(),
            data.user.cloned().unwrap_or(FieldValue::Undefined),
        ),
        (
            "organization".into(),
            data.organization.field_values()?.into(),
        ),
    ])
    .into())
}

struct Hooks<S: AuthSchema> {
    events: Events,
    writer: Arc<dyn AuthStore<S>>,
    case: Case,
}

#[async_trait]
impl<S: AuthSchema> OrganizationHooks for Hooks<S> {
    async fn before_delete_team(&self, data: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        record(&self.events, "beforeDeleteTeam", "hook", hook_fields(data)?)?;
        if matches!(self.case, Case::MovedOwner | Case::InvitationError) {
            let _ = self
                .writer
                .update_team(
                    "target-team",
                    UpdateTeam {
                        organization_id: Some("other".into()),
                        ..Default::default()
                    },
                )
                .await?;
        } else if self.case == Case::DeletedTeam {
            self.writer.delete_team("target-team").await?;
            invitation(
                self.writer.as_ref(),
                "invitation-recreated",
                "organization",
                InvitationStatus::Pending,
                "target-team,retained-team",
            )
            .await?;
        }
        Ok(())
    }

    async fn after_delete_team(&self, data: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        record(&self.events, "afterDeleteTeam", "hook", hook_fields(data)?)?;
        if self.case == Case::AfterError {
            return Err(AuthError::internal("team-after-hook-failed"));
        }
        Ok(())
    }
}

async fn reader<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    writer: Arc<dyn AuthStore<S>>,
    ids: Ids,
    events: &Events,
    case: Case,
) -> AuthResult<BetterAuth<S>> {
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    options.teams.allow_removing_all_teams = true;
    options.hooks = Some(Arc::new(Hooks {
        events: events.clone(),
        writer,
        case,
    }));
    if case == Case::HiddenId {
        options.schema.team = declaration([(
            "id",
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        )]);
    }
    let team_events = events.clone();
    let team = declaration([(
        "organizationId",
        UserFieldConfig {
            field_name: (case == Case::MappedOwner).then(|| "name".into()),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    record(&team_events, "team.organizationId", "output", value.clone())?;
                    Ok(if case == Case::WrongProjectedOwner {
                        "other".into()
                    } else {
                        value
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    let input_events = events.clone();
    let output_events = events.clone();
    let invitation = declaration([(
        "teamId",
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(&input_events, "invitation.teamId", "input", value.clone())?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(&output_events, "invitation.teamId", "output", value.clone())?;
                    if case == Case::InvitationError {
                        return Err(AuthError::internal("team-invitation-output-failed"));
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    )]);
    BetterAuth::new(settings(ids)?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (EntityRole::Team, team),
            (EntityRole::Invitation, invitation),
        ]))
        .build()
        .await
}

fn expected_hook(case: Case) -> FieldValue {
    let mut team = FieldMap::from_iter([
        (
            "name".into(),
            if case == Case::MappedOwner {
                "organization"
            } else {
                "Target"
            }
            .into(),
        ),
        ("organizationId".into(), "organization".into()),
        ("createdAt".into(), date().into()),
        ("updatedAt".into(), date().into()),
    ]);
    if case != Case::HiddenId {
        let _ = team.insert("id".into(), "target-team".into());
    }
    FieldMap::from_iter([
        ("team".into(), team.into()),
        ("user".into(), FieldValue::Undefined),
        (
            "organization".into(),
            FieldMap::from_iter([
                ("name".into(), "Organization".into()),
                ("slug".into(), "organization".into()),
                ("logo".into(), FieldValue::Null),
                ("createdAt".into(), date().into()),
                ("metadata".into(), "{}".into()),
                ("id".into(), "organization".into()),
            ])
            .into(),
        ),
    ])
    .into()
}

fn expected_events(case: Case) -> Vec<FieldValue> {
    let mut events = vec![event(
        "team.organizationId",
        "output",
        "organization".into(),
    )];
    if case == Case::WrongProjectedOwner {
        return events;
    }
    events.push(event("beforeDeleteTeam", "hook", expected_hook(case)));
    if case == Case::DeletedTeam {
        events.push(event("invitation.teamId", "output", "retained-team".into()));
    }
    events.push(event(
        "invitation.teamId",
        "output",
        "target-team,retained-team".into(),
    ));
    if case == Case::InvitationError {
        return events;
    }
    if case != Case::HiddenId {
        events.push(event("invitation.teamId", "input", "retained-team".into()));
        events.push(event("invitation.teamId", "output", "retained-team".into()));
    }
    events.push(event("afterDeleteTeam", "hook", expected_hook(case)));
    events
}

fn row_mut<'a>(snapshot: &'a mut Snapshot, table: &str, id: &str) -> AuthResult<&'a mut FieldMap> {
    snapshot
        .get_mut(table)
        .and_then(|rows| {
            rows.iter_mut()
                .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(id))
        })
        .ok_or_else(|| AuthError::internal(format!("Expected {table} row {id}")))
}

fn expected_storage(storage: &Storage, case: Case, snapshot: &mut Snapshot) -> AuthResult<()> {
    let column =
        |native: &'static str, sql: &'static str| if storage.memory() { native } else { sql };
    if case == Case::InvitationError {
        let _ = row_mut(snapshot, "team", "target-team")?.insert(
            column("organizationId", "organization_id").into(),
            "other".into(),
        );
        return Ok(());
    }
    if matches!(case, Case::HiddenId | Case::WrongProjectedOwner) {
        return Ok(());
    }
    for (table, id) in [
        ("team", "target-team"),
        ("teamMember", "target-team-member"),
    ] {
        snapshot
            .get_mut(table)
            .ok_or_else(|| AuthError::internal(format!("Expected {table} snapshot")))?
            .retain(|row| row.get("id").and_then(FieldValue::as_str) != Some(id));
    }
    let team_column = column("teamId", "team_id");
    let _ = row_mut(snapshot, "invitation", "invitation-a")?
        .insert(team_column.into(), "retained-team".into());
    if case == Case::DeletedTeam {
        let mut invitation = row_mut(snapshot, "invitation", "invitation-a")?.clone();
        let _ = invitation.insert("id".into(), "invitation-recreated".into());
        let rows = snapshot
            .get_mut("invitation")
            .ok_or_else(|| AuthError::internal("Expected Invitation snapshot"))?;
        rows.push(invitation);
        rows.sort_by(|left, right| {
            left.get("id")
                .and_then(FieldValue::as_str)
                .cmp(&right.get("id").and_then(FieldValue::as_str))
        });
    }
    Ok(())
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
) -> AuthResult<()> {
    if case == Case::MappedOwner {
        make_original_owner_nullable(&storage).await?;
    }
    let ids = Ids::default();
    let writer = writer(raw.clone(), ids.clone()).await?;
    seed_teams(raw.clone(), writer.store().as_ref(), &ids, case).await?;
    let mut snapshot = storage.snapshot().await?;
    assert_eq!(snapshot.len(), 9);
    if case == Case::MappedOwner {
        assert_eq!(
            row_mut(&mut snapshot, "team", "target-team")?.get(if storage.memory() {
                "organizationId"
            } else {
                "organization_id"
            }),
            Some(&FieldValue::from("other")),
        );
    }
    let events = Events::default();
    let reader = reader(raw, writer.store().clone(), ids, &events, case).await?;
    assert!(trace_lock(&events)?.is_empty());
    let response = reader
        .call_endpoint(
            HttpMethod::Post,
            "/organization/remove-team",
            EndpointInput {
                body: Some(json!({"teamId":"target-team", "organizationId":"organization"})),
                ..Default::default()
            },
        )
        .await;
    match case {
        Case::InvitationError | Case::AfterError => {
            let expected = if case == Case::InvitationError {
                "team-invitation-output-failed"
            } else {
                "team-after-hook-failed"
            };
            assert!(
                matches!(required(response.err(), "Native deletion must propagate callback failure")?,
                AuthError::Internal(message) if message == expected)
            );
        }
        Case::WrongProjectedOwner => {
            let error = required(response.err(), "Projected owner must determine access")?;
            assert_eq!(error.status_code()?, 400);
            ordered(
                &error.body_value()?,
                &FieldMap::from([
                    ("message".into(), "Team not found".into()),
                    ("code".into(), "TEAM_NOT_FOUND".into()),
                ])
                .into(),
            )?;
            let response = error
                .to_auth_response()
                .expect("fixture response succeeds")
                .into_http_response()?;
            assert_eq!(
                response.body.bytes()?.as_ref(),
                br#"{"message":"Team not found","code":"TEAM_NOT_FOUND"}"#.as_slice()
            );
        }
        _ => {
            let response = response?;
            assert_eq!(response.status, 200, "{case:?}");
            let expected =
                FieldMap::from_iter([("message".into(), "Team removed successfully.".into())]);
            ordered(&response.body.field_value()?, &expected.into())?;
            assert_eq!(
                response.body.bytes()?.as_ref(),
                br#"{"message":"Team removed successfully."}"#.as_slice()
            );
        }
    }
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events(case).into(),
    )?;
    expected_storage(&storage, case, &mut snapshot)?;
    assert_eq!(storage.snapshot().await?, snapshot, "{case:?}");
    Ok(())
}

#[tokio::test]
async fn memory_team_deletion_preserves_captured_scope_hooks_and_storage() -> AuthResult<()> {
    for case in Case::ALL {
        let (raw, storage) = memory_fixture();
        check(raw, storage, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_team_deletion_preserves_captured_scope_hooks_and_storage() -> AuthResult<()> {
    for case in Case::ALL {
        let (raw, storage) = sqlite_fixture().await?;
        check(raw, storage, case).await?;
    }
    Ok(())
}
