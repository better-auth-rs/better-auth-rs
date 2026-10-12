use super::*;
use better_auth::plugins::organization::hooks::{OrganizationHooks, OrganizationMemberEvent};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

const CHANGED: &str = r#"{"source":"changed"}"#;
const INITIAL: &str = r#"{"source":"initial"}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Metadata {
    Parsed,
    Undefined,
    Omitted,
    FinalParseError,
}

fn organization(storage: &Storage, mode: Metadata) -> FieldMap {
    let mut fields = FieldMap::from_iter([
        ("name".into(), "Created".into()),
        ("slug".into(), "created".into()),
        ("logo".into(), FieldValue::Null),
        ("createdAt".into(), date().into()),
    ]);
    if mode != Metadata::Omitted {
        let value = if mode == Metadata::Parsed {
            FieldMap::from_iter([(
                "source".into(),
                if storage.memory() {
                    "changed"
                } else {
                    "initial"
                }
                .into(),
            )])
            .into()
        } else if mode == Metadata::FinalParseError {
            "bad-json".into()
        } else {
            FieldValue::Undefined
        };
        let _ = fields.insert("metadata".into(), value);
    }
    let _ = fields.insert("id".into(), "organization-a".into());
    if mode == Metadata::Omitted {
        let _ = fields.insert("metadata".into(), FieldValue::Undefined);
    }
    fields
}

fn created_member() -> FieldMap {
    FieldMap::from_iter([
        ("organizationId".into(), "organization-a".into()),
        ("userId".into(), "user-a".into()),
        ("role".into(), "owner".into()),
        ("createdAt".into(), date().into()),
        ("id".into(), "member-a".into()),
    ])
}

struct Hooks(Events);

#[async_trait]
impl OrganizationHooks for Hooks {
    async fn after_add_member(&self, data: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        event(
            &self.0,
            [
                "afterAddMember".into(),
                data.organization.field_values()?.into(),
                data.member.field_values()?.into(),
            ],
        )
    }

    async fn after_create_organization(&self, data: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        event(
            &self.0,
            [
                "afterCreateOrganization".into(),
                data.organization.field_values()?.into(),
                data.member.field_values()?.into(),
            ],
        )
    }
}

pub(super) async fn check_storage(
    storage: &Storage,
    mut expected: Snapshot,
    started: i64,
    finished: i64,
    organization_id: &str,
) -> AuthResult<()> {
    let actual = storage.snapshot_with_roles(true).await?;
    if let Storage::Sqlite(database) = storage {
        let row = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT updated_at FROM organization WHERE id = ?",
                [organization_id.into()],
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?
            .ok_or_else(|| AuthError::internal("Expected private Organization timestamp"))?;
        let timestamp = row
            .try_get::<chrono::DateTime<chrono::Utc>>("", "updated_at")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        assert!((started..=finished).contains(&timestamp.timestamp_millis()));
        let observed = actual
            .get("organization")
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(organization_id))
            })
            .and_then(|row| row.get("updated_at"))
            .ok_or_else(|| AuthError::internal("Expected stored private Organization timestamp"))?;
        let expected_row = expected
            .get_mut("organization")
            .and_then(|rows| {
                rows.iter_mut()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(organization_id))
            })
            .ok_or_else(|| AuthError::internal("Expected created Organization storage row"))?;
        let _ = expected_row.insert("updated_at".into(), observed.clone());
    }
    assert_eq!(actual, expected);
    Ok(())
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    mode: Metadata,
    native: bool,
) -> AuthResult<()> {
    let token = seed(raw.clone(), false, "user-a").await?;
    raw.delete_member("owner-member").await?;
    let mut before = storage.snapshot_with_roles(true).await?;
    let writer = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .build()
        .await?;
    let events = Events::default();
    let mut plugin = OrganizationConfig {
        dynamic_access_control: true,
        hooks: Some(Arc::new(Hooks(events.clone()))),
        ..Default::default()
    };
    plugin.teams.enabled = true;
    plugin.teams.default_team = false;
    if mode == Metadata::Omitted {
        plugin.schema.organization = declaration([(
            "metadata",
            UserFieldConfig {
                field_type: UserFieldType::Json,
                returned: Some(false),
                ..Default::default()
            },
        )]);
    }
    let policies = declaration([
        ("createdAt", fixed_creation("organization", &events)),
        (
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let writer = writer.store().clone();
                        let events = events.clone();
                        move |value| {
                            let writer = writer.clone();
                            let events = events.clone();
                            async move {
                                event(
                                    &events,
                                    ["organization.name".into(), "output".into(), value.clone()],
                                )?;
                                let _ = writer
                                    .update_organization(
                                        "organization-a",
                                        UpdateOrganization {
                                            metadata: Some(CHANGED.into()),
                                            ..Default::default()
                                        },
                                    )
                                    .await?;
                                Ok(value)
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "metadata",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            event(
                                &events,
                                [
                                    "organization.metadata".into(),
                                    "output".into(),
                                    value.clone(),
                                ],
                            )?;
                            Ok(if mode == Metadata::Undefined {
                                FieldValue::Undefined
                            } else if mode == Metadata::FinalParseError {
                                r#""bad-json""#.into()
                            } else {
                                value
                            })
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ]);
    let auth = BetterAuth::new(settings()?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(vec![
            (EntityRole::Organization, policies),
            (
                EntityRole::Member,
                declaration([("createdAt", fixed_creation("member", &events))]),
            ),
            (
                EntityRole::Session,
                declaration([(
                    "updatedAt",
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        on_update: Some(better_auth_core::user_fields::UserFieldFactory::new({
                            let events = events.clone();
                            move || {
                                event(&events, ["session.updatedAt".into(), "onUpdate".into()])?;
                                Ok(date().into())
                            }
                        })),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new({
                                let events = events.clone();
                                move |value| {
                                    assert!(
                                        value.as_date().is_some(),
                                        "Session update supplies a native Date"
                                    );
                                    event(
                                        &events,
                                        [
                                            "session.updatedAt".into(),
                                            "input".into(),
                                            "native-date".into(),
                                        ],
                                    )?;
                                    Ok(date().into())
                                }
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]),
            ),
        ]))
        .build()
        .await?;
    let started = chrono::Utc::now().timestamp_millis();
    let fails = mode == Metadata::FinalParseError;
    let actual = call(&auth, &token, native, "create", json!({"name":"Created","slug":"created","logo":null,"metadata":{"source":"initial"},"keepCurrentActiveOrganization":!fails})).await;
    let finished = chrono::Utc::now().timestamp_millis();
    let org = organization(&storage, mode);
    let mut hook_org = org.clone();
    if mode == Metadata::Omitted {
        let _ = hook_org.remove("metadata");
    }
    let member = created_member();
    let mut expected = org.clone();
    let _ = expected.insert(
        "members".into(),
        vec![FieldValue::from(member.clone())].into(),
    );
    if fails {
        if native {
            let error = actual
                .err()
                .ok_or_else(|| AuthError::internal("Expected final metadata parse failure"))?;
            let raw = required(
                error.raw_value(),
                "Expected native final metadata parse error",
            )?;
            assert_eq!(raw.model_property("name")?, "SyntaxError".into());
            assert!(!error.is_api_error()?);
        } else {
            let actual = actual?;
            assert_eq!(actual.status, 500);
            assert!(actual.body.bytes()?.is_empty());
        }
    } else {
        response(actual?, native, 200, &expected.into())?;
    }
    let mut expected_events: Vec<FieldValue> = vec![
        vec![
            "organization.createdAt".into(),
            "input".into(),
            "native-date".into(),
        ]
        .into(),
        vec![
            "organization.name".into(),
            "output".into(),
            "Created".into(),
        ]
        .into(),
    ];
    expected_events.push(
        vec![
            "organization.metadata".into(),
            "output".into(),
            if storage.memory() { CHANGED } else { INITIAL }.into(),
        ]
        .into(),
    );
    expected_events.extend([
        vec![
            "member.createdAt".into(),
            "input".into(),
            "native-date".into(),
        ]
        .into(),
        vec![
            "afterAddMember".into(),
            hook_org.clone().into(),
            member.clone().into(),
        ]
        .into(),
        vec![
            "afterCreateOrganization".into(),
            hook_org.into(),
            member.clone().into(),
        ]
        .into(),
    ]);
    if fails {
        expected_events.extend([
            vec!["session.updatedAt".into(), "onUpdate".into()].into(),
            vec![
                "session.updatedAt".into(),
                "input".into(),
                "native-date".into(),
            ]
            .into(),
        ]);
        let sessions = before
            .get_mut("session")
            .ok_or_else(|| AuthError::internal("Expected Session storage table"))?;
        assert_eq!(sessions.len(), 1);
        let session = required(sessions.first_mut(), "Expected active Session")?;
        let _ = session.insert(
            if storage.memory() {
                "activeOrganizationId"
            } else {
                "active_organization_id"
            }
            .into(),
            "organization-a".into(),
        );
        session.extend(stored(
            &storage,
            [("updatedAt".into(), date().into())].into(),
        ));
    }
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    let mut persisted = org;
    let _ = persisted.insert("metadata".into(), CHANGED.into());
    append(&mut before, "organization", stored(&storage, persisted))?;
    append(&mut before, "member", stored(&storage, member))?;
    check_storage(&storage, before, started, finished, "organization-a").await
}

#[tokio::test]
async fn memory_organization_create_consumes_live_metadata_and_preserves_own_undefined()
-> AuthResult<()> {
    for mode in [
        Metadata::Parsed,
        Metadata::Undefined,
        Metadata::Omitted,
        Metadata::FinalParseError,
    ] {
        for native in [false, true] {
            let (raw, storage) = memory_fixture();
            check(raw, storage, mode, native).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_organization_create_consumes_snapshot_metadata_and_preserves_own_undefined()
-> AuthResult<()> {
    for mode in [
        Metadata::Parsed,
        Metadata::Undefined,
        Metadata::Omitted,
        Metadata::FinalParseError,
    ] {
        for native in [false, true] {
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, mode, native).await?;
        }
    }
    Ok(())
}
