#![cfg(feature = "seaorm2")]

use async_trait::async_trait;
use better_auth::{
    BetterAuth,
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRecordFields, AuthRequest,
    AuthResponse, AuthResult, AuthRoute, AuthSchema, AuthStore, CreateOrganization, CreateTeam,
    CreateUser, FieldDate, FieldMap, FieldValue,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
        UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[path = "model_alias_order_tests/models.rs"]
mod models;

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

#[derive(Clone, Default)]
struct Events {
    enabled: Arc<AtomicBool>,
    values: Arc<Mutex<Vec<FieldValue>>>,
}

impl Events {
    fn output(&self, name: &'static str) -> UserFieldTransform {
        let events = self.clone();
        UserFieldTransform::new(move |value| {
            if events.enabled.load(Ordering::Relaxed) {
                events
                    .values
                    .lock()
                    .map_err(|_| AuthError::internal("Model alias event lock poisoned"))?
                    .push(vec![name.into(), value.clone()].into());
                if name == "team.name" {
                    return Ok(format!(
                        "Visible {}",
                        value
                            .as_str()
                            .ok_or_else(|| AuthError::internal("Expected the stored Team name"))?
                    )
                    .into());
                }
            }
            Ok(value)
        })
    }

    fn take(&self) -> AuthResult<Vec<FieldValue>> {
        Ok(std::mem::take(&mut *self.values.lock().map_err(|_| {
            AuthError::internal("Model alias event lock poisoned")
        })?))
    }
}

struct Badge(Events);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Badge {
    fn name(&self) -> &'static str {
        "model-alias-badge"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_custom_model(
            "badge",
            Some("shared"),
            UserConfig {
                additional_fields: Some(
                    [(
                        "label".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                output: Some(self.0.output("badge.label")),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct Policies {
    events: Events,
    reference: &'static str,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Policies {
    fn name(&self) -> &'static str {
        "model-alias-policies"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let output = |name| UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(self.events.output(name)),
                ..Default::default()
            }),
            ..Default::default()
        };
        context.register_model_schema(
            EntityRole::Team,
            Some("shared"),
            UserConfig {
                additional_fields: Some(
                    [
                        ("name".into(), output("team.name")),
                        (
                            "updatedAt".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Date,
                                on_update: Some(Arc::new(|| Ok(date().into()))),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            },
        )?;
        context.register_model_schema(
            EntityRole::TeamMember,
            None,
            UserConfig {
                additional_fields: Some(
                    [
                        (
                            "teamId".into(),
                            UserFieldConfig {
                                references: Some(UserFieldReference {
                                    model: self.reference.into(),
                                    field: "id".into(),
                                    ..Default::default()
                                }),
                                ..output("teamMember.teamId")
                            },
                        ),
                        ("userId".into(), output("teamMember.userId")),
                        ("membershipKey".into(), output("teamMember.membershipKey")),
                        (
                            "createdAt".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Date,
                                transform: Some(FieldTransforms {
                                    input: Some(UserFieldTransform::new(|_| Ok(date().into()))),
                                    output: Some(self.events.output("teamMember.createdAt")),
                                }),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            },
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config(joins: bool) -> AuthConfig {
    let mut config = AuthConfig::new("model-alias-order-contract-at-least-thirty-two-characters")
        .base_url("http://model-alias-order.test");
    config.advanced.database.joins = Some(joins);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(if request.model == "teamMember" {
                "member-a".into()
            } else {
                format!("{}-a", request.model)
            }))
        })));
    config
}

fn expected_team(visible: bool, count: bool) -> FieldMap {
    let mut row: FieldMap = [
        ("id".into(), "team-a".into()),
        (
            "name".into(),
            (if visible { "Visible Team A" } else { "Team A" }).into(),
        ),
        ("organizationId".into(), "organization".into()),
        ("createdAt".into(), date().into()),
        ("updatedAt".into(), date().into()),
    ]
    .into();
    if count {
        let _ = row.insert("memberCount".into(), 1.into());
    }
    row
}

fn membership_key() -> AuthResult<String> {
    better_auth_core::organization_fields::team_membership_key("team-a", "user-a")
}

enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    fn date(&self) -> FieldValue {
        match self {
            Self::Memory(_) => date().into(),
            Self::Sqlite(_) => "2030-01-01T00:00:00.000Z".into(),
        }
    }

    async fn rows(&self, role: EntityRole) -> AuthResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => store.storage_rows(role),
            Self::Sqlite(db) => {
                let (table, columns): (&str, &[&str]) = if role == EntityRole::Team {
                    (
                        "shared",
                        &[
                            "id",
                            "name",
                            "memberCount",
                            "organizationId",
                            "createdAt",
                            "updatedAt",
                        ],
                    )
                } else {
                    (
                        "teamMember",
                        &["id", "teamId", "userId", "membershipKey", "createdAt"],
                    )
                };
                db.query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT * FROM \"{table}\" ORDER BY id"),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .into_iter()
                .map(|row| {
                    columns
                        .iter()
                        .map(|name| {
                            let value = if *name == "memberCount" {
                                row.try_get::<i64>("", name).map(FieldValue::from)
                            } else {
                                row.try_get::<Option<String>>("", name)
                                    .map(|value| value.map_or(FieldValue::Null, FieldValue::from))
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

    async fn assert_rows(&self) -> AuthResult<()> {
        let mut team = expected_team(false, true);
        let _ = team.insert("createdAt".into(), self.date());
        let _ = team.insert("updatedAt".into(), self.date());
        assert_eq!(self.rows(EntityRole::Team).await?, [team]);
        let member: FieldMap = [
            ("id".into(), "member-a".into()),
            ("teamId".into(), "team-a".into()),
            ("userId".into(), "user-a".into()),
            ("membershipKey".into(), membership_key()?.into()),
            ("createdAt".into(), self.date()),
        ]
        .into();
        assert_eq!(self.rows(EntityRole::TeamMember).await?, [member]);
        Ok(())
    }
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    before: bool,
    reference: &'static str,
    joins: bool,
) -> AuthResult<()> {
    let events = Events::default();
    let mut organization = OrganizationConfig::default();
    organization.teams.enabled = true;
    let plugin = OrganizationPlugin::with_config(organization);
    let builder = BetterAuth::new(config(joins)).store_arc(raw);
    let badge = Badge(events.clone());
    let builder = if before {
        builder.plugin(badge).plugin(plugin)
    } else {
        builder.plugin(plugin).plugin(badge)
    };
    let auth = builder
        .plugin(Policies {
            events: events.clone(),
            reference,
        })
        .build()
        .await?;
    let store = auth.store();
    let _ = store
        .create_user(CreateUser {
            id: Some("user-a".into()),
            created_at: Some(date()),
            updated_at: Some(date()),
            ..CreateUser::new()
                .with_name("User A")
                .with_email("user-a@model-alias-order.test")
        })
        .await?;
    let _ = store
        .create_organization(CreateOrganization {
            id: Some("organization".into()),
            ..CreateOrganization::new("Organization", "organization")
        })
        .await?;
    let _ = store
        .create_team(CreateTeam {
            id: Some("team-a".into()),
            name: "Team A".into(),
            organization_id: "organization".into(),
            created_at: Some(date()),
            updated_at: Some(date()),
            ..Default::default()
        })
        .await?;
    assert!(
        store
            .add_team_member(&"team-a".into(), "user-a", None)
            .await?
            .is_some()
    );
    storage.assert_rows().await?;
    events.enabled.store(true, Ordering::Relaxed);
    let control = store
        .get_team_value(&"team-a".into())
        .await?
        .ok_or_else(|| AuthError::internal("Expected the control Team"))?;
    assert_eq!(control.field_values()?, expected_team(true, true));
    assert_eq!(
        events.take()?,
        [FieldValue::from(vec!["team.name".into(), "Team A".into()])]
    );
    for owner in ["user-a", "missing"] {
        let result = store.list_user_teams(owner).await;
        if before && reference == "shared" {
            let error = result.err().ok_or_else(|| {
                AuthError::internal("Expected alias-selected foreign-key failure")
            })?;
            assert!(matches!(&error, AuthError::Config(_)));
            assert_eq!(
                error.instrumentation_message(),
                "No foreign key found for model team and base model teamMember while performing join operation."
            );
            assert_eq!(events.take()?, []);
        } else {
            assert_eq!(
                result?
                    .into_iter()
                    .map(|team| team.field_values())
                    .collect::<AuthResult<Vec<_>>>()?,
                if owner == "missing" {
                    vec![]
                } else {
                    vec![expected_team(true, false)]
                }
            );
            let expected: Vec<FieldValue> = if owner == "missing" {
                vec![]
            } else {
                vec![
                    vec!["teamMember.teamId".into(), "team-a".into()].into(),
                    vec!["teamMember.userId".into(), "user-a".into()].into(),
                    vec!["teamMember.membershipKey".into(), membership_key()?.into()].into(),
                    vec!["teamMember.createdAt".into(), storage.date()].into(),
                    vec!["team.name".into(), "Team A".into()].into(),
                ]
            };
            assert_eq!(events.take()?, expected);
        }
        storage.assert_rows().await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_model_aliases_follow_mixed_plugin_declaration_order() -> AuthResult<()> {
    for before in [true, false] {
        for reference in ["shared", "team"] {
            for joins in [false, true] {
                let store = EphemeralStore::new(Arc::new(config(joins)));
                let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
                check(
                    raw,
                    Storage::Memory(Box::new(store)),
                    before,
                    reference,
                    joins,
                )
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_model_aliases_follow_mixed_plugin_declaration_order() -> AuthResult<()> {
    for before in [true, false] {
        for reference in ["shared", "team"] {
            for joins in [false, true] {
                let db = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&db)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let schema = Schema::new(db.get_database_backend());
                for table in [
                    schema.create_table_from_entity(models::team::Entity),
                    schema.create_table_from_entity(models::team_member::Entity),
                ] {
                    let _ = db
                        .execute(&table)
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                }
                let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(
                    SeaOrmStore::<BundledSchema>::new(config(joins), db.clone())
                        .with_organization_schema::<models::Organization>(),
                );
                check(raw, Storage::Sqlite(db), before, reference, joins).await?;
            }
        }
    }
    Ok(())
}
