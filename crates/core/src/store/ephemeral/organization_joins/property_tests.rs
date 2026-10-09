//! Native relation callbacks retain raw child rows across committed writes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The relation contract propagates setup failures and asserts callback values, identity, and durable storage."
)]

use super::*;
use crate::FieldDate;
use crate::organization_fields::OrganizationFields;
use crate::store::{RuntimeStore, TeamStore};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};

#[derive(Clone, Copy)]
enum Relation {
    MemberUser,
    TeamMembers,
    MembershipTeam,
}

impl Relation {
    fn roles(self) -> (EntityRole, EntityRole, &'static str, &'static str, bool) {
        match self {
            Self::MemberUser => (EntityRole::Member, EntityRole::User, "user", "name", false),
            Self::TeamMembers => (
                EntityRole::Team,
                EntityRole::TeamMember,
                "teamMember",
                "userId",
                true,
            ),
            Self::MembershipTeam => (
                EntityRole::TeamMember,
                EntityRole::Team,
                "team",
                "name",
                false,
            ),
        }
    }
}

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

fn copy(value: &Value) -> AuthResult<Value> {
    crate::StructuredCloneContext::new().clone_value(value)
}

fn joined(row: &FieldMap, many: bool) -> Value {
    let value = Value::from(row.clone());
    if many { vec![value].into() } else { value }
}

fn output(transform: UserFieldTransform) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(transform),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn fields_mut(
    fields: &mut OrganizationFields,
    role: EntityRole,
) -> AuthResult<&mut crate::user_fields::UserConfig> {
    match role {
        EntityRole::Member => Ok(&mut fields.member),
        EntityRole::Team => Ok(&mut fields.team),
        _ => Err(AuthError::internal(
            "Membership declarations use ModelFields",
        )),
    }
}

async fn check(relation: Relation, native: bool, alias: bool, reject: bool) -> AuthResult<()> {
    let (parent_role, child_role, child_model, label, many) = relation.roles();
    let physical = if alias {
        format!("linked_{child_model}")
    } else {
        child_model.into()
    };
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(native);
    let writer = EphemeralStore::new(Arc::new(config.clone()));
    let mut member: FieldMap = [
        ("id".into(), "member".into()),
        ("organizationId".into(), "organization".into()),
        ("userId".into(), "user".into()),
        ("role".into(), "member".into()),
        ("createdAt".into(), date().into()),
    ]
    .into();
    let user: FieldMap = [
        ("id".into(), "user".into()),
        ("name".into(), "Before".into()),
        ("email".into(), "raw-relation@example.test".into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), Value::Null),
        ("createdAt".into(), date().into()),
        ("updatedAt".into(), date().into()),
    ]
    .into();
    let mut team: FieldMap = [
        ("id".into(), "team".into()),
        ("name".into(), "Before".into()),
        ("organizationId".into(), "organization".into()),
        ("memberCount".into(), 1.into()),
        ("createdAt".into(), date().into()),
        ("updatedAt".into(), date().into()),
    ]
    .into();
    let mut membership: FieldMap = [
        ("id".into(), "membership".into()),
        ("teamId".into(), "team".into()),
        ("userId".into(), "user".into()),
        ("membershipKey".into(), "membership-key".into()),
        ("createdAt".into(), date().into()),
    ]
    .into();
    let parent = match relation {
        Relation::MemberUser => &mut member,
        Relation::TeamMembers => &mut team,
        Relation::MembershipTeam => &mut membership,
    };
    let _ = parent.insert(physical.clone(), "stored-parent-property".into());
    {
        let mut state = writer.lock()?;
        state.members.push(member);
        state.users.push(UserView::from_field_values(user)?);
        state.teams.push(team);
        state.team_members.push(membership);
    }
    let before_parent = writer.storage_rows(parent_role)?;
    let before_child = writer.storage_rows(child_role)?.remove(0);
    let mut after_child = before_child.clone();
    let _ = after_child.insert(label.into(), "After".into());
    let before = if native {
        joined(&before_child, many)
    } else {
        "stored-parent-property".into()
    };
    let after = if native {
        joined(&after_child, many)
    } else {
        "stored-parent-property".into()
    };
    let events = Arc::new(Mutex::new(Vec::<(&'static str, Value)>::new()));
    let held = Arc::new(Mutex::new(Value::Undefined));
    let collision = {
        let (writer, events, held, before, after) = (
            writer.clone(),
            events.clone(),
            held.clone(),
            before.clone(),
            after.clone(),
        );
        UserFieldTransform::new_async(move |value| {
            let (writer, events, held, before, after) = (
                writer.clone(),
                events.clone(),
                held.clone(),
                before.clone(),
                after.clone(),
            );
            async move {
                assert_eq!(copy(&value)?, before);
                *held
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))? = value.clone();
                events
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push(("collision", copy(&value)?));
                match relation {
                    Relation::MemberUser => {
                        let _ = writer
                            .update_user(
                                "user",
                                UpdateUser {
                                    name: Some("After".to_owned()).into(),
                                    additional_fields: [("updatedAt".into(), date().into())].into(),
                                    ..Default::default()
                                },
                            )
                            .await?;
                    }
                    Relation::MembershipTeam => {
                        let _ = writer
                            .update_team(
                                "team",
                                crate::UpdateTeam {
                                    name: Some("After".into()),
                                    updated_at: Some(date().into()),
                                    ..Default::default()
                                },
                            )
                            .await?;
                    }
                    Relation::TeamMembers => {
                        // The public TeamMember store exposes no update operation; model a backend writer.
                        let state = writer.lock()?;
                        let mut row = state
                            .team_members
                            .get_mut("membership")?
                            .ok_or_else(|| AuthError::internal("Expected membership"))?;
                        let _ = row.insert("userId".into(), "After".into());
                    }
                }
                events
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push(("write", writer.storage_rows(child_role)?.remove(0).into()));
                assert_eq!(copy(&value)?, after);
                events
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push(("after", copy(&value)?));
                if reject {
                    return Err(AuthError::type_error("raw-organization-relation-rejected"));
                }
                Ok(value)
            }
        })
    };
    let mirror = {
        let (events, held, after) = (events.clone(), held.clone(), after.clone());
        UserFieldTransform::new(move |value| {
            assert!(
                value.strict_equals(
                    &*held
                        .lock()
                        .map_err(|error| AuthError::internal(error.to_string()))?
                )
            );
            assert_eq!(copy(&value)?, after);
            events
                .lock()
                .map_err(|error| AuthError::internal(error.to_string()))?
                .push(("mirror", copy(&value)?));
            Ok(value)
        })
    };
    let child_output = {
        let events = events.clone();
        output(UserFieldTransform::new(move |value| {
            events
                .lock()
                .map_err(|error| AuthError::internal(error.to_string()))?
                .push(("child", value.clone()));
            Ok(format!(
                "visible:{}",
                value
                    .as_str()
                    .ok_or_else(|| AuthError::internal("Expected child label"))?
            )
            .into())
        }))
    };
    let mut organization = OrganizationFields::default();
    let mut membership_fields = crate::user_fields::UserConfig::default();
    let parent_fields = if parent_role == EntityRole::TeamMember {
        &mut membership_fields
    } else {
        fields_mut(&mut organization, parent_role)?
    };
    let _ = parent_fields
        .fields_mut()
        .insert(physical.clone(), output(collision));
    let _ = parent_fields.fields_mut().insert(
        "relationMirror".into(),
        UserFieldConfig {
            field_name: Some(physical.clone()),
            ..output(mirror)
        },
    );
    if child_role == EntityRole::User {
        let _ = config.user.fields_mut().insert(label.into(), child_output);
    } else if child_role == EntityRole::TeamMember {
        let _ = membership_fields
            .fields_mut()
            .insert(label.into(), child_output);
    } else {
        let _ = fields_mut(&mut organization, child_role)?
            .fields_mut()
            .insert(label.into(), child_output);
    }
    let mut models = crate::plugin_runtime::ModelFields::default();
    models.register_organization_schema(&organization, true);
    models.extend(EntityRole::TeamMember, membership_fields);
    models.set_model_name(child_role, Some(&physical))?;
    let reader = writer.with_runtime(Arc::new(config), Vec::new(), models)?;
    let result: AuthResult<Value> = async {
        match relation {
            Relation::MemberUser => Ok(reader
                .get_member_by_id_with_user("member")
                .await?
                .ok_or_else(|| AuthError::internal("Expected Member"))?
                .user
                .name
                .field_value()),
            Relation::TeamMembers => {
                let result = reader
                    .get_team_details_value(&"team".into(), None, true)
                    .await?
                    .ok_or_else(|| AuthError::internal("Expected Team"))?;
                let (parent, members) = result.into_public_parts(&Default::default())?;
                let raw = held
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .clone();
                assert!(
                    parent
                        .additional_fields
                        .get("relationMirror")
                        .is_some_and(|mirror| mirror.strict_equals(&raw))
                );
                let child = members
                    .ok_or_else(|| AuthError::internal("Expected membership page"))?
                    .remove(0);
                if native {
                    let raw_child = raw
                        .as_array()
                        .and_then(|rows| rows.first())
                        .ok_or_else(|| AuthError::internal("Expected raw membership"))?;
                    assert!(
                        child
                            .created_at
                            .field_value()
                            .strict_equals(&raw_child.model_property("createdAt")?)
                    );
                }
                Ok(child.user_id.field_value())
            }
            Relation::MembershipTeam => Ok(reader
                .list_user_teams("user")
                .await?
                .remove(0)
                .name
                .field_value()),
        }
    }
    .await;
    if reject {
        assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "raw-organization-relation-rejected")
        );
    } else {
        assert_eq!(result?, Value::from("visible:After"));
    }
    let mut expected = vec![
        ("collision", before),
        ("write", after_child.clone().into()),
        ("after", after.clone()),
    ];
    if !reject {
        expected.extend([("mirror", after), ("child", "After".into())]);
    }
    assert_eq!(
        *events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?,
        expected
    );
    assert_eq!(writer.storage_rows(parent_role)?, before_parent);
    assert_eq!(writer.storage_rows(child_role)?, vec![after_child]);
    Ok(())
}

#[tokio::test]
async fn organization_relations_share_live_properties_and_preserve_writes_after_failure()
-> AuthResult<()> {
    for relation in [
        Relation::MemberUser,
        Relation::TeamMembers,
        Relation::MembershipTeam,
    ] {
        for native in [false, true] {
            for alias in [false, true] {
                for reject in [false, true] {
                    check(relation, native, alias, reject).await?;
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn full_details_resolve_mapped_references_after_parent_projection_for_fallback()
-> AuthResult<()> {
    for native in [false, true] {
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let trace = |name: &'static str, replacement: Option<&'static str>| {
            let events = events.clone();
            output(UserFieldTransform::new(move |value| {
                events
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push(name.into());
                Ok(replacement.map_or(value, Value::from))
            }))
        };
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(native);
        let _ = config
            .user
            .fields_mut()
            .insert("name".into(), trace("user", None));
        let store = EphemeralStore::new(Arc::new(config));
        let mut fields = OrganizationFields::default();
        let _ = fields.organization.fields_mut().insert(
            "lookup".into(),
            UserFieldConfig {
                field_name: Some("route_key".into()),
                ..trace("parent", Some("route-b"))
            },
        );
        let events_for_collision = events.clone();
        let _ = fields.organization.fields_mut().insert(
            "member".into(),
            output(UserFieldTransform::new(move |value| {
                if native {
                    let rows = value
                        .as_array()
                        .ok_or_else(|| AuthError::internal("Expected raw member page"))?;
                    assert_eq!(rows.len(), 1);
                    assert_eq!(
                        rows.first()
                            .ok_or_else(|| AuthError::internal("Expected raw member"))?
                            .model_property("org_ref")?,
                        Value::from("route-a")
                    );
                } else {
                    assert_eq!(value, Value::from("stored-member-property"));
                }
                events_for_collision
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push("raw-members".into());
                Ok(value)
            })),
        );
        for schema in [&mut fields.member, &mut fields.invitation, &mut fields.team] {
            let _ = schema.fields_mut().insert(
                "organizationId".into(),
                UserFieldConfig {
                    field_name: Some("org_ref".into()),
                    references: Some(crate::user_fields::UserFieldReference {
                        model: "organization".into(),
                        field: "lookup".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let _ = fields
            .invitation
            .fields_mut()
            .insert("role".into(), trace("invitation", None));
        let _ = fields
            .member
            .fields_mut()
            .insert("role".into(), trace("member", None));
        let _ = fields
            .team
            .fields_mut()
            .insert("name".into(), trace("team", None));
        store.configure_organization_fields(fields)?;
        {
            let mut state = store.lock()?;
            state.organizations.push(
                [
                    ("id".into(), "organization".into()),
                    ("name".into(), "Organization".into()),
                    ("slug".into(), "organization".into()),
                    ("createdAt".into(), date().into()),
                    ("route_key".into(), "route-a".into()),
                    ("member".into(), "stored-member-property".into()),
                ]
                .into(),
            );
            for suffix in ["a", "b"] {
                let id = format!("user-{suffix}");
                state.users.push(UserView::from_field_values(
                    [
                        ("id".into(), id.clone().into()),
                        ("name".into(), suffix.into()),
                        ("email".into(), format!("{suffix}@full-details.test").into()),
                        ("emailVerified".into(), true.into()),
                        ("image".into(), Value::Null),
                        ("createdAt".into(), date().into()),
                        ("updatedAt".into(), date().into()),
                    ]
                    .into(),
                )?);
                state.members.push(
                    [
                        ("id".into(), format!("member-{suffix}").into()),
                        ("org_ref".into(), format!("route-{suffix}").into()),
                        ("userId".into(), id.clone().into()),
                        ("role".into(), "member".into()),
                        ("createdAt".into(), date().into()),
                    ]
                    .into(),
                );
                state.invitations.push(
                    [
                        ("id".into(), format!("invitation-{suffix}").into()),
                        ("org_ref".into(), format!("route-{suffix}").into()),
                        ("email".into(), format!("{suffix}@full-details.test").into()),
                        ("role".into(), "member".into()),
                        ("teamId".into(), Value::Null),
                        ("status".into(), "pending".into()),
                        ("inviterId".into(), id.into()),
                        ("createdAt".into(), date().into()),
                        ("expiresAt".into(), date().into()),
                    ]
                    .into(),
                );
                state.teams.push(
                    [
                        ("id".into(), format!("team-{suffix}").into()),
                        ("org_ref".into(), format!("route-{suffix}").into()),
                        ("name".into(), suffix.into()),
                        ("memberCount".into(), 0.into()),
                        ("createdAt".into(), date().into()),
                        ("updatedAt".into(), date().into()),
                    ]
                    .into(),
                );
            }
        }
        let roles = [
            EntityRole::Organization,
            EntityRole::Invitation,
            EntityRole::Member,
            EntityRole::Team,
            EntityRole::User,
        ];
        let before = roles
            .iter()
            .map(|role| store.storage_rows(*role))
            .collect::<AuthResult<Vec<_>>>()?;
        let result = store
            .get_organization_details(OrganizationDetailsQuery {
                organization: OrganizationKey::Id("organization"),
                members_limit: None,
                users_limit: 100.0,
                include_teams: true,
            })
            .await?
            .ok_or_else(|| AuthError::internal("Expected full organization"))?;
        let suffix = if native { "a" } else { "b" };
        assert_eq!(result.members.len(), 1);
        assert_eq!(result.invitations.len(), 1);
        assert_eq!(
            result
                .members
                .first()
                .ok_or_else(|| AuthError::internal("Expected member"))?
                .member
                .id,
            format!("member-{suffix}")
        );
        assert_eq!(
            result
                .invitations
                .first()
                .ok_or_else(|| AuthError::internal("Expected invitation"))?
                .id,
            format!("invitation-{suffix}")
        );
        assert_eq!(
            result
                .teams
                .ok_or_else(|| AuthError::internal("Expected teams"))?
                .first()
                .ok_or_else(|| AuthError::internal("Expected team"))?
                .id,
            format!("team-{suffix}")
        );
        assert_eq!(
            result.organization.additional_fields.get("lookup"),
            Some(&Value::from("route-b"))
        );
        assert!(!result.organization.additional_fields.contains_key("member"));
        assert_eq!(
            *events
                .lock()
                .map_err(|error| AuthError::internal(error.to_string()))?,
            [
                "parent",
                "raw-members",
                "invitation",
                "member",
                "team",
                "user"
            ]
        );
        assert_eq!(
            roles
                .iter()
                .map(|role| store.storage_rows(*role))
                .collect::<AuthResult<Vec<_>>>()?,
            before
        );
    }
    Ok(())
}
