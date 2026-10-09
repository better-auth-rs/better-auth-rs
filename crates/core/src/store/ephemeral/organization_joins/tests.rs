use super::*;
use crate::FieldDate;
use crate::organization_fields::{OrganizationFields, team_membership_key_values};
use crate::store::TeamStore;
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    UserFieldType,
};

type Events = Arc<Mutex<Vec<Value>>>;

fn date(offset: i64) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

fn key(team: &str) -> AuthResult<String> {
    team_membership_key_values(&team.into(), &"user-a".into())
}

fn event(name: &str, value: Value) -> Value {
    vec![name.into(), "output".into(), value].into()
}

fn callback(name: &'static str, events: &Events) -> UserFieldTransform {
    let events = Arc::clone(events);
    UserFieldTransform::new(move |value| {
        events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?
            .push(event(name, value.clone()));
        Ok(if name == "createdAt" {
            date(1).into()
        } else {
            value
        })
    })
}

fn team(id: &str, name: &str, count: bool) -> FieldMap {
    let mut row: FieldMap = [
        ("id".into(), id.into()),
        ("name".into(), name.into()),
        ("organizationId".into(), "organization".into()),
        ("createdAt".into(), date(0).into()),
        ("updatedAt".into(), date(0).into()),
    ]
    .into();
    if count {
        let _ = row.insert("memberCount".into(), 0.into());
    }
    row
}

fn member(team_id: &str) -> AuthResult<FieldMap> {
    Ok([
        ("id".into(), "member-a".into()),
        ("teamId".into(), team_id.into()),
        ("userId".into(), "user-a".into()),
        ("membershipKey".into(), key(team_id)?.into()),
        ("createdAt".into(), date(0).into()),
    ]
    .into())
}

fn member_events(team_id: &str) -> AuthResult<Vec<Value>> {
    Ok(vec![
        event("teamId", team_id.into()),
        event("userId", "user-a".into()),
        event("membershipKey", key(team_id)?.into()),
        event("createdAt", date(0).into()),
    ])
}

#[tokio::test]
async fn native_user_team_joins_group_duplicate_parent_ids_before_projection() -> AuthResult<()> {
    for native in [false, true] {
        let mut config = (*test_config()).clone();
        config.advanced.database.joins = Some(native);
        let mut store = EphemeralStore::new(Arc::new(config));
        let events = Events::default();
        let mut organization = OrganizationFields::default();
        let _ = organization.team.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(callback("team.name", &events)),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        store.configure_organization_fields(organization.clone())?;
        store
            .model_fields
            .register_organization_schema(&organization, true);
        let fields = ["teamId", "userId", "membershipKey", "createdAt"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    UserFieldConfig {
                        field_type: if name == "createdAt" {
                            UserFieldType::Date
                        } else {
                            UserFieldType::String
                        },
                        references: (name == "teamId").then(|| UserFieldReference {
                            model: "team".into(),
                            field: "id".into(),
                            ..Default::default()
                        }),
                        transform: Some(FieldTransforms {
                            output: Some(callback(name, &events)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
            })
            .collect();
        store.model_fields.register(
            EntityRole::TeamMember,
            UserConfig {
                additional_fields: Some(fields),
            },
        );
        let members = vec![member("team-a")?, member("team-b")?];
        let teams = vec![
            team("team-a", "Team A", true),
            team("team-b", "Team B", true),
        ];
        {
            let mut state = store.lock()?;
            for row in &members {
                state.team_members.push(row.clone());
            }
            for row in &teams {
                state.teams.push(row.clone());
            }
        }
        let actual = store
            .list_user_teams("user-a")
            .await?
            .iter()
            .map(AuthRecordFields::field_values)
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(
            actual,
            if native {
                vec![team("team-b", "Team B", false)]
            } else {
                vec![
                    team("team-a", "Team A", false),
                    team("team-b", "Team B", false),
                ]
            }
        );
        let first = member_events("team-a")?;
        let second = member_events("team-b")?;
        let mut expected = if native {
            first
        } else {
            first
                .into_iter()
                .zip(second)
                .flat_map(|(a, b)| [a, b])
                .collect()
        };
        if !native {
            expected.push(event("team.name", "Team A".into()));
        }
        expected.push(event("team.name", "Team B".into()));
        assert_eq!(
            *events
                .lock()
                .map_err(|error| AuthError::internal(error.to_string()))?,
            expected
        );
        assert_eq!(store.storage_rows(EntityRole::TeamMember)?, members);
        assert_eq!(store.storage_rows(EntityRole::Team)?, teams);
    }
    Ok(())
}

#[tokio::test]
async fn team_details_null_query_matches_missing_id_without_coercing_native_join() -> AuthResult<()>
{
    for native in [false, true] {
        for missing_id in [false, true] {
            for selector in [Value::Null, Value::Undefined] {
                let mut config = (*test_config()).clone();
                config.advanced.database.joins = Some(native);
                let mut store = EphemeralStore::new(Arc::new(config));
                let events = Events::default();
                let mut organization = OrganizationFields::default();
                let _ = organization.team.fields_mut().insert(
                    "name".into(),
                    UserFieldConfig {
                        transform: Some(FieldTransforms {
                            output: Some(callback("team.name", &events)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                );
                store.configure_organization_fields(organization.clone())?;
                store
                    .model_fields
                    .register_organization_schema(&organization, true);
                store.model_fields.register(
                    EntityRole::TeamMember,
                    UserConfig {
                        additional_fields: Some(
                            [(
                                "teamId".into(),
                                UserFieldConfig {
                                    references: Some(UserFieldReference {
                                        model: "team".into(),
                                        field: "id".into(),
                                        ..Default::default()
                                    }),
                                    transform: Some(FieldTransforms {
                                        output: Some(callback("member.teamId", &events)),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                },
                            )]
                            .into(),
                        ),
                    },
                );
                let mut parent = team("unused", "No typed ID", true);
                if missing_id {
                    let _ = parent.shift_remove("id");
                } else {
                    let _ = parent.insert("id".into(), Value::Null);
                }
                let children = [true, false].map(|missing_reference| {
                    let mut fields: FieldMap = [
                        (
                            "id".into(),
                            if missing_reference { "missing" } else { "null" }.into(),
                        ),
                        ("userId".into(), "user-a".into()),
                        ("createdAt".into(), date(0).into()),
                    ]
                    .into();
                    if !missing_reference {
                        let _ = fields.insert("teamId".into(), Value::Null);
                    }
                    fields
                });
                {
                    let mut state = store.lock()?;
                    state.teams.push(parent.clone());
                    for child in &children {
                        state.team_members.push(child.clone());
                    }
                }
                let found = missing_id || selector.is_null();
                let result = store.get_team_details_value(&selector, None, true).await?;
                let mut expected_events = Vec::new();
                if found {
                    let result =
                        result.expect("Memory null query must select a missing or null ID");
                    let (team, members) = result.into_public_parts(&UserConfig::default())?;
                    let value = if missing_id {
                        Value::Undefined
                    } else {
                        Value::Null
                    };
                    let mut expected = parent.clone();
                    let _ = expected.shift_remove("memberCount");
                    let _ = expected.insert("id".into(), value.clone());
                    assert_eq!(team.field_values()?, expected);
                    expected_events.push(event("team.name", "No typed ID".into()));
                    let expected_members = if native {
                        let mut child = children[usize::from(!missing_id)].clone();
                        let _ = child.insert("teamId".into(), value.clone());
                        expected_events.push(event("member.teamId", value));
                        vec![child]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(
                        members
                            .expect("Requested membership page must be present")
                            .iter()
                            .map(AuthRecordFields::field_values)
                            .collect::<AuthResult<Vec<_>>>()?,
                        expected_members,
                    );
                } else {
                    assert!(result.is_none());
                }
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|error| AuthError::internal(error.to_string()))?,
                    expected_events
                );
                assert_eq!(store.storage_rows(EntityRole::Team)?, [parent]);
                assert_eq!(store.storage_rows(EntityRole::TeamMember)?, children);
            }
        }
    }
    Ok(())
}
