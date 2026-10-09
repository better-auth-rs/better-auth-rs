use super::*;
use better_auth_core::{
    AuthRecordFields, TeamMember,
    id::{IdGeneration, IdGenerator},
    user_fields::UserFieldReference,
};
use better_auth_seaorm::sea_orm::{
    ConnectOptions, ConnectionTrait, DatabaseConnection, DbBackend, Statement,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[path = "team_member_joins.rs"]
mod joins;
#[path = "team_member_recovery.rs"]
mod recovery;
#[path = "team_member_registration.rs"]
mod registration;
#[path = "team_member_removal.rs"]
mod removal;

fn date(offset: i64) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

fn key(team: &str, user: &str) -> AuthResult<String> {
    better_auth_core::organization_fields::team_membership_key_values(&team.into(), &user.into())
}

fn event(field: &str, phase: &str, value: FieldValue) -> FieldValue {
    vec![field.into(), phase.into(), value].into()
}

#[derive(Clone, Default)]
struct Events {
    values: Arc<Mutex<Vec<FieldValue>>>,
    dates: Arc<Mutex<Vec<FieldDate>>>,
}

impl Events {
    fn push(&self, field: &str, phase: &str, value: FieldValue) -> AuthResult<()> {
        trace_lock(&self.values)?.push(event(field, phase, value));
        Ok(())
    }

    fn take(&self) -> AuthResult<Vec<FieldValue>> {
        Ok(std::mem::take(&mut *trace_lock(&self.values)?))
    }

    fn service_date(&self, value: FieldValue) -> AuthResult<()> {
        trace_lock(&self.dates)?.push(
            required(
                value.as_date(),
                "TeamMember service input must be a native Date",
            )?
            .clone(),
        );
        self.push("createdAt", "input", "native-date".into())
    }

    fn assert_dates(&self, count: usize, started: i64, ended: i64) -> AuthResult<()> {
        let dates = trace_lock(&self.dates)?;
        assert_eq!(dates.len(), count);
        for date in dates.iter() {
            assert!(date.milliseconds() >= started as f64);
            assert!(date.milliseconds() <= ended as f64);
        }
        Ok(())
    }
}

fn identity(name: &'static str, events: &Events) -> UserFieldConfig {
    let input = events.clone();
    let output = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                input.push(name, "input", value.clone())?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output.push(name, "output", value.clone())?;
                Ok(value)
            })),
        }),
        ..Default::default()
    }
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

fn member(id: &str, team: &str, user: &str, created: FieldValue) -> FieldMap {
    [
        ("id".into(), id.into()),
        ("teamId".into(), team.into()),
        ("userId".into(), user.into()),
        ("createdAt".into(), created),
    ]
    .into()
}

fn team(id: &str, name: &str, count: Option<i64>) -> FieldMap {
    let mut row: FieldMap = [
        ("id".into(), id.into()),
        ("name".into(), name.into()),
        ("organizationId".into(), "organization".into()),
        ("createdAt".into(), date(0).into()),
        ("updatedAt".into(), date(0).into()),
    ]
    .into();
    if let Some(count) = count {
        let _ = row.insert("memberCount".into(), count.into());
    }
    row
}

enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    fn stored_date(&self, offset: i64) -> FieldValue {
        match self {
            Self::Memory(_) => date(offset).into(),
            Self::Sqlite(_) => format!("2030-01-01T00:00:{offset:02}.000Z").into(),
        }
    }

    fn stored(&self, mut row: FieldMap) -> FieldMap {
        if matches!(self, Self::Sqlite(_)) {
            for name in ["createdAt", "updatedAt"] {
                if let Some(FieldValue::Date(date)) = row.get(name) {
                    let offset = ((date.milliseconds() - 1_893_456_000_000.0) / 1_000.0) as i64;
                    let _ = row.insert(name.into(), self.stored_date(offset));
                }
            }
        }
        row
    }

    async fn rows(&self, role: EntityRole) -> AuthResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => store.storage_rows(role),
            Self::Sqlite(database) => {
                let (table, columns): (&str, &[(&str, &str)]) = match role {
                    EntityRole::TeamMember => (
                        "team_member",
                        &[
                            ("id", "id"),
                            ("teamId", "team_id"),
                            ("userId", "user_id"),
                            ("membershipKey", "membership_key"),
                            ("createdAt", "created_at"),
                        ],
                    ),
                    EntityRole::Team => (
                        "team",
                        &[
                            ("id", "id"),
                            ("name", "name"),
                            ("organizationId", "organization_id"),
                            ("createdAt", "created_at"),
                            ("updatedAt", "updated_at"),
                            ("memberCount", "member_count"),
                        ],
                    ),
                    _ => return Err(AuthError::internal("Unsupported TeamMember snapshot role")),
                };
                database
                    .query_all_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        format!("SELECT * FROM {table} ORDER BY id"),
                    ))
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .into_iter()
                    .map(|row| {
                        columns
                            .iter()
                            .map(|(name, column)| {
                                let value = if *name == "memberCount" {
                                    row.try_get::<i64>("", column).map(FieldValue::from)
                                } else {
                                    row.try_get::<Option<String>>("", column).map(|value| {
                                        value.map_or(FieldValue::Null, FieldValue::from)
                                    })
                                }
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                                Ok(((*name).into(), value))
                            })
                            .collect()
                    })
                    .collect()
            }
        }
    }

    async fn assert_rows(&self, members: Vec<FieldMap>, counts: [i64; 2]) -> AuthResult<()> {
        assert_eq!(
            self.rows(EntityRole::TeamMember).await?,
            members
                .into_iter()
                .map(|row| self.stored(row))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            self.rows(EntityRole::Team).await?,
            [
                self.stored(team("team-a", "Team A", Some(counts[0]))),
                self.stored(team("team-b", "Team B", Some(counts[1]))),
            ]
        );
        Ok(())
    }
}

async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<()> {
    for id in ["user-a", "user-b"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(id.into()),
                created_at: Some(date(0)),
                updated_at: Some(date(0)),
                ..CreateUser::new()
                    .with_name(id)
                    .with_email(format!("{id}@team-member-fields.test"))
            })
            .await?;
    }
    let _ = store
        .create_organization(CreateOrganization {
            id: Some("organization".into()),
            ..CreateOrganization::new("Organization", "organization")
        })
        .await?;
    for (id, name) in [("team-a", "Team A"), ("team-b", "Team B")] {
        let _ = store
            .create_team(CreateTeam {
                id: Some(id.into()),
                name: name.into(),
                organization_id: "organization".into(),
                created_at: Some(date(0)),
                updated_at: Some(date(0)),
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

async fn reader<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    fields: UserConfig,
    team_fields: Option<UserConfig>,
    before: bool,
    joins: bool,
    member_id: &'static str,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    config.advanced.database.joins = Some(joins);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            Ok(Some(if request.model == "teamMember" {
                member_id.into()
            } else {
                format!("{}-a", request.model)
            }))
        })));
    let mut organization = OrganizationConfig::default();
    organization.teams.enabled = true;
    let plugin = OrganizationPlugin::with_config(organization);
    let mut declarations = vec![(EntityRole::TeamMember, fields)];
    if let Some(fields) = team_fields {
        declarations.push((EntityRole::Team, fields));
    }
    let builder = BetterAuth::new(config).store_arc(raw);
    if before {
        builder
            .plugin(Fields(declarations))
            .plugin(plugin)
            .build()
            .await
    } else {
        builder
            .plugin(plugin)
            .plugin(Fields(declarations))
            .build()
            .await
    }
}

async fn memory_fixture() -> AuthResult<(Arc<dyn AuthStore<StatelessSchema>>, Storage)> {
    let store = EphemeralStore::new(Arc::new(config()));
    let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
    seed(raw.as_ref()).await?;
    Ok((raw, Storage::Memory(Box::new(store))))
}

async fn sqlite_fixture() -> AuthResult<(Arc<dyn AuthStore<BundledSchema>>, Storage)> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(SeaOrmStore::<BundledSchema>::new(
        config(),
        database.clone(),
    ));
    seed(raw.as_ref()).await?;
    Ok((raw, Storage::Sqlite(database)))
}

fn public(member: TeamMember) -> AuthResult<FieldMap> {
    member.field_values()
}

fn physical(id: &str, team: &str, user: &str, key: &str, created: i64) -> FieldMap {
    let mut row = member(id, team, user, date(created).into());
    let _ = row.insert("membershipKey".into(), key.into());
    row
}
