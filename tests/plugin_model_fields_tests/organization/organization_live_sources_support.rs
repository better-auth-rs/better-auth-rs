pub(super) use super::super::member_contract_support::{
    Storage, date, memory_fixture, ordered, seed, sqlite_fixture,
};
use super::super::*;
use better_auth_core::id::{IdGeneration, IdGenerator};
use better_auth_core::{
    AuthRecordFields, CreateInvitation, CreateOrganizationRole, InvitationStatus,
    UpdateOrganizationRole,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

pub(super) type Events = Arc<Mutex<Vec<FieldValue>>>;
pub(super) type Snapshot = std::collections::BTreeMap<String, Vec<FieldMap>>;
pub(super) type Ids = Arc<Mutex<String>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Model {
    Organization,
    Invitation,
    Team,
    Role,
}

impl Model {
    pub(super) const ALL: [Self; 4] =
        [Self::Organization, Self::Invitation, Self::Team, Self::Role];
    pub(super) fn role(self) -> EntityRole {
        match self {
            Self::Organization => EntityRole::Organization,
            Self::Invitation => EntityRole::Invitation,
            Self::Team => EntityRole::Team,
            Self::Role => EntityRole::OrganizationRole,
        }
    }
    pub(super) fn table(self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Invitation => "invitation",
            Self::Team => "team",
            Self::Role => "organizationRole",
        }
    }
    pub(super) fn early(self) -> &'static str {
        match self {
            Self::Organization | Self::Team => "name",
            Self::Invitation | Self::Role => "organizationId",
        }
    }
    pub(super) fn late(self) -> &'static str {
        match self {
            Self::Organization => "metadata",
            Self::Invitation => "expiresAt",
            Self::Team => "organizationId",
            Self::Role => "permission",
        }
    }
    pub(super) fn changed(self) -> FieldValue {
        match self {
            Self::Organization | Self::Role => "{\"changed\":true}".into(),
            Self::Invitation => past().into(),
            Self::Team => "other".into(),
        }
    }
}

pub(super) fn past() -> FieldDate {
    FieldDate::from_milliseconds(1_577_836_800_000.0)
}
pub(super) fn declaration(
    fields: impl IntoIterator<Item = (&'static str, UserFieldConfig)>,
) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            fields
                .into_iter()
                .map(|(name, field)| (name.into(), field))
                .collect(),
        ),
    }
}
pub(super) fn event(events: &Events, name: &str, value: FieldValue) -> AuthResult<()> {
    trace_lock(events)?.push(vec![name.into(), value].into());
    Ok(())
}
pub(super) fn fixed_dates() -> UserConfig {
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
    )])
}

pub(super) async fn auth<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    ids: Ids,
    policies: Vec<(EntityRole, UserConfig)>,
) -> AuthResult<BetterAuth<S>> {
    auth_config(raw, ids, policies, OrganizationConfig::default()).await
}

pub(super) async fn auth_config<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    ids: Ids,
    policies: Vec<(EntityRole, UserConfig)>,
    mut plugin: OrganizationConfig,
) -> AuthResult<BetterAuth<S>> {
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
    plugin.dynamic_access_control = true;
    plugin.teams.enabled = true;
    let mut dates: Vec<_> = Model::ALL
        .into_iter()
        .map(|model| (model.role(), fixed_dates()))
        .collect();
    for (role, fields) in &mut dates {
        if matches!(role, EntityRole::Team | EntityRole::OrganizationRole) {
            let _ = fields.fields_mut().insert(
                "updatedAt".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(|| {
                        Ok(date().into())
                    })),
                    ..Default::default()
                },
            );
        }
    }
    BetterAuth::new(settings)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(dates))
        .plugin(Fields(policies))
        .build()
        .await
}

pub(super) async fn seed_parents<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<String> {
    let token = seed(raw.clone(), false, "user-a").await?;
    for id in ["source-parent", "other"] {
        let _ = raw
            .insert_organization(Organization {
                field_order: Default::default(),
                additional_fields: Default::default(),
                id: id.into(),
                name: id.into(),
                slug: id.into(),
                logo: None.into(),
                metadata: Some(FieldValue::from("{}")).into(),
                created_at: date().into(),
            })
            .await?;
    }
    Ok(token)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
pub(super) fn output<T: AuthRecordFields + serde::Serialize>(record: T) -> AuthResult<FieldMap> {
    let fields = record.field_values()?;
    assert_eq!(
        serde_json::to_vec(&record)?,
        serde_json::to_vec(&FieldValue::from(fields.clone()).json()?)?
    );
    Ok(fields)
}

pub(super) fn visible(model: Model, id: &str, label: &str) -> FieldMap {
    let mut fields = match model {
        Model::Organization => FieldMap::from_iter([
            ("name".into(), label.into()),
            ("slug".into(), format!("slug-{label}").into()),
            ("logo".into(), FieldValue::Null),
            ("createdAt".into(), date().into()),
            ("metadata".into(), "{}".into()),
        ]),
        Model::Invitation => FieldMap::from_iter([
            ("organizationId".into(), "source-parent".into()),
            ("email".into(), format!("{label}@fields.test").into()),
            ("role".into(), "member".into()),
            ("teamId".into(), FieldValue::Null),
            ("status".into(), "pending".into()),
            ("expiresAt".into(), date().into()),
            ("createdAt".into(), date().into()),
            ("inviterId".into(), "user-a".into()),
        ]),
        Model::Team => FieldMap::from_iter([
            ("name".into(), label.into()),
            ("memberCount".into(), 0.into()),
            ("organizationId".into(), "source-parent".into()),
            ("createdAt".into(), date().into()),
            ("updatedAt".into(), date().into()),
        ]),
        Model::Role => FieldMap::from_iter([
            ("organizationId".into(), "source-parent".into()),
            ("role".into(), label.into()),
            ("permission".into(), "{}".into()),
            ("createdAt".into(), date().into()),
            ("updatedAt".into(), date().into()),
        ]),
    };
    let _ = fields.insert("id".into(), id.into());
    fields
}

pub(super) async fn create<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    ids: &Ids,
    model: Model,
    id: &str,
    label: &str,
) -> AuthResult<FieldMap> {
    *trace_lock(ids)? = id.into();
    match model {
        Model::Organization => {
            let mut input = CreateOrganization::new(label, format!("slug-{label}"))
                .with_metadata(FieldMap::new().into());
            input.id = Some(id.into());
            input.logo = None.into();
            output(store.create_organization(input).await?)
        }
        Model::Invitation => {
            let mut input = CreateInvitation::new(
                "source-parent",
                format!("{label}@fields.test"),
                "member",
                "user-a",
                date(),
            );
            input.id = Some(id.into());
            input.created_at = Some(date());
            output(store.create_invitation(input).await?)
        }
        Model::Team => output(
            store
                .create_team(CreateTeam {
                    id: Some(id.into()),
                    name: label.to_owned().into(),
                    organization_id: "source-parent".into(),
                    created_at: Some(date()),
                    updated_at: Some(date()),
                    ..Default::default()
                })
                .await?,
        ),
        Model::Role => output(
            store
                .create_organization_role(CreateOrganizationRole {
                    organization_id: "source-parent".into(),
                    role: label.into(),
                    permission: FieldMap::new().into(),
                    additional_fields: [
                        ("createdAt".into(), date().into()),
                        ("updatedAt".into(), date().into()),
                    ]
                    .into(),
                })
                .await?,
        ),
    }
}

pub(super) async fn update<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: Model,
    id: &str,
) -> AuthResult<FieldMap> {
    match model {
        Model::Organization => output(
            store
                .update_organization(
                    id,
                    UpdateOrganization {
                        name: Some("Updated".into()),
                        ..Default::default()
                    },
                )
                .await?,
        ),
        Model::Invitation => output(required(
            store
                .update_invitation_status(id, InvitationStatus::Accepted)
                .await?,
            "Expected updated Invitation",
        )?),
        Model::Team => output(
            store
                .update_team(
                    id,
                    UpdateTeam {
                        name: Some("Updated".into()),
                        ..Default::default()
                    },
                )
                .await?,
        ),
        Model::Role => output(
            store
                .update_organization_role(
                    id,
                    UpdateOrganizationRole {
                        role: Some("Updated".into()),
                        ..Default::default()
                    },
                )
                .await?,
        ),
    }
}

pub(super) fn updated(model: Model, mut row: FieldMap) -> FieldMap {
    let (field, value) = match model {
        Model::Organization | Model::Team => ("name", "Updated"),
        Model::Invitation => ("status", "accepted"),
        Model::Role => ("role", "Updated"),
    };
    let _ = row.insert(field.into(), value.into());
    row
}

pub(super) async fn point<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: Model,
    id: &str,
) -> AuthResult<FieldMap> {
    match model {
        Model::Organization => output(required(
            store.get_organization_by_id_value(&id.into()).await?,
            "Expected Organization",
        )?),
        Model::Invitation => output(required(
            store.get_invitation_by_id_value(&id.into()).await?,
            "Expected Invitation",
        )?),
        Model::Team => output(required(
            store.get_team_value(&id.into()).await?,
            "Expected Team",
        )?),
        Model::Role => output(required(
            store.get_organization_role(id).await?,
            "Expected OrganizationRole",
        )?),
    }
}

pub(super) async fn list<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: Model,
) -> AuthResult<Vec<FieldMap>> {
    match model {
        Model::Organization => store
            .list_organizations_by_ids(&["source-a".into(), "source-b".into(), "source-c".into()])
            .await?
            .into_iter()
            .map(output)
            .collect(),
        Model::Invitation => store
            .list_organization_invitations_value(&"source-parent".into())
            .await?
            .into_iter()
            .map(output)
            .collect(),
        Model::Team => store
            .list_organization_teams_value(&"source-parent".into())
            .await?
            .into_iter()
            .map(output)
            .collect(),
        Model::Role => store
            .query_organization_roles_value(
                &"source-parent".into(),
                &["First".into(), "Second".into(), "Third".into()],
            )
            .await?
            .into_iter()
            .map(output)
            .collect(),
    }
}

pub(super) async fn mutate<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: Model,
    id: &str,
) -> AuthResult<()> {
    let changed = FieldMap::from_iter([("changed".into(), true.into())]);
    match model {
        Model::Organization => {
            let _ = store
                .update_organization(
                    id,
                    UpdateOrganization {
                        metadata: Some(changed.into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Model::Invitation => {
            let _ = store
                .update_invitation_expiry(
                    id,
                    chrono::DateTime::from_timestamp(1_577_836_800, 0)
                        .ok_or_else(|| AuthError::internal("Invalid fixed expiry"))?,
                )
                .await?;
        }
        Model::Team => {
            let _ = store
                .update_team(
                    id,
                    UpdateTeam {
                        organization_id: Some("other".into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Model::Role => {
            let _ = store
                .update_organization_role(
                    id,
                    UpdateOrganizationRole {
                        permission: Some(changed.into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
    }
    Ok(())
}

pub(super) async fn delete<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: Model,
    id: &str,
) -> AuthResult<()> {
    match model {
        Model::Organization => store.delete_organization_records(id).await,
        Model::Team => store.delete_team(id).await,
        Model::Role => {
            store
                .delete_organization_role_by_fields(&[("id".into(), id.into())].into())
                .await
        }
        Model::Invitation => Err(AuthError::internal(
            "Invitation has no ordinary single-row delete",
        )),
    }
}

pub(super) fn stored(storage: &Storage, row: &FieldMap) -> AuthResult<FieldMap> {
    row.iter()
        .map(|(name, value)| {
            let physical = if storage.memory() {
                name.as_str()
            } else {
                match name.as_str() {
                    "organizationId" => "organization_id",
                    "createdAt" => "created_at",
                    "updatedAt" => "updated_at",
                    "teamId" => "team_id",
                    "expiresAt" => "expires_at",
                    "inviterId" => "inviter_id",
                    "memberCount" => "member_count",
                    name => name,
                }
            };
            let value = if !storage.memory() && value.as_date().is_some() {
                FieldValue::from_json(required(value.json()?, "Expected Date JSON")?)?
            } else {
                value.clone()
            };
            Ok((physical.to_owned(), value))
        })
        .collect()
}

pub(super) fn replace(
    snapshot: &mut Snapshot,
    model: Model,
    id: &str,
    row: FieldMap,
) -> AuthResult<()> {
    let rows = snapshot
        .get_mut(model.table())
        .ok_or_else(|| AuthError::internal("Expected model storage"))?;
    rows.retain(|row| row.get("id").and_then(FieldValue::as_str) != Some(id));
    rows.push(row);
    rows.sort_by(|left, right| {
        left.get("id")
            .and_then(FieldValue::as_str)
            .cmp(&right.get("id").and_then(FieldValue::as_str))
    });
    Ok(())
}

pub(super) async fn check_storage(
    storage: &Storage,
    expected: &mut Snapshot,
    model: Model,
    ids: &[&str],
    started: i64,
) -> AuthResult<()> {
    let actual = storage.snapshot_with_roles(true).await?;
    if let (Model::Organization, Storage::Sqlite(database)) = (model, storage) {
        let rows = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id, updated_at FROM organization".to_owned(),
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        for row in rows {
            let id: String = row
                .try_get("", "id")
                .map_err(|error| AuthError::internal(error.to_string()))?;
            if !ids.contains(&id.as_str()) {
                continue;
            }
            let timestamp: chrono::DateTime<chrono::Utc> = row
                .try_get("", "updated_at")
                .map_err(|error| AuthError::internal(error.to_string()))?;
            assert!(
                (started..=chrono::Utc::now().timestamp_millis())
                    .contains(&timestamp.timestamp_millis())
            );
            let value = actual
                .get("organization")
                .and_then(|rows| {
                    rows.iter()
                        .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(id.as_str()))
                })
                .and_then(|row| row.get("updated_at"))
                .ok_or_else(|| AuthError::internal("Expected private Organization timestamp"))?;
            let row = expected
                .get_mut("organization")
                .and_then(|rows| {
                    rows.iter_mut()
                        .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(id.as_str()))
                })
                .ok_or_else(|| AuthError::internal("Expected Organization row"))?;
            let _ = row.insert("updated_at".into(), value.clone());
        }
    }
    assert_eq!(actual, *expected);
    Ok(())
}
