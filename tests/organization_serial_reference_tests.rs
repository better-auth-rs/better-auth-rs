use better_auth_core::{
    AuthConfig, AuthResult, CreateInvitation, CreateMember, CreateOrganization,
    CreateOrganizationRole, CreateSession, CreateTeam, CreateUser, FieldMap, FieldValue,
    InvitationStatus, Member, TeamMember, UpdateOrganization, UpdateOrganizationRole, UpdateTeam,
    id::IdGeneration,
    organization_fields::OrganizationFields,
    store::{
        EphemeralStore, InvitationStore, ListOrganizationMembersParams, MemberStore, MemberUser,
        OrganizationDetailsQuery, OrganizationKey, OrganizationRoleKey, OrganizationRoleStore,
        OrganizationStore, SessionStore, TeamStore, UserStore,
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    },
};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

#[path = "organization_serial_reference_tests/lifecycle.rs"]
mod lifecycle;

const EMAIL: &str = "user@organization-serial.test";

fn config(joins: bool) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-organization-serial-secret-at-least-32-characters");
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    config.advanced.database.joins = Some(joins);
    config
}

fn reference(trace: Option<Arc<Mutex<Vec<Value>>>>) -> UserFieldConfig {
    let input_trace = trace.clone();
    UserFieldConfig {
        field_name: Some("stored_reference".into()),
        references: Some(UserFieldReference {
            model: "user".into(),
            field: "id".into(),
        }),
        default_value: Some(FieldValue::from(" 001 ")),
        on_update: Some(Arc::new(|| FieldValue::from(" 1 "))),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                if let Some(trace) = &input_trace {
                    trace.lock().unwrap().push(json!(["input", value.json()?]));
                }
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => FieldValue::from(value.as_str().unwrap().trim()),
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                if let Some(trace) = &trace {
                    trace.lock().unwrap().push(json!(["output", value.json()?]));
                }
                Ok(value)
            })),
        }),
        ..Default::default()
    }
}

fn present(value: Option<Value>) -> Value {
    value.unwrap_or_else(|| json!({"$undefined":true}))
}

fn selected(row: impl serde::Serialize) -> AuthResult<Value> {
    let row = serde_json::to_value(row)?;
    Ok(present(row.get("reference").cloned()))
}

fn member(row: &Member) -> Value {
    json!({"id":row.id,"organizationId":row.organization_id,"userId":row.user_id,"role":row.role})
}

fn joined_member(row: &MemberUser) -> Value {
    let mut value = member(&row.member);
    value["userIdFromJoin"] = json!(row.user.id);
    value
}

fn team_members(rows: Vec<TeamMember>) -> Value {
    json!(
        rows.iter()
            .map(|row| json!({"teamId":row.team_id,"userId":row.user_id}))
            .collect::<Vec<_>>()
    )
}

async fn user(store: &EphemeralStore) -> AuthResult<String> {
    Ok(store
        .create_user(CreateUser {
            name: Some("User".into()).into(),
            email: Some(EMAIL.into()),
            email_verified: Some(true),
            ..Default::default()
        })
        .await?
        .id
        .typed()?
        .clone())
}

#[tokio::test]
async fn organization_reference_fields_match_pinned_callback_values_and_projection()
-> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-serial-references-1.7.6.json"
    ))?;
    let mut families = Map::new();
    for model in [
        "organization",
        "member",
        "invitation",
        "team",
        "organizationRole",
    ] {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let schema = UserConfig {
            additional_fields: Some([("reference".into(), reference(Some(trace.clone())))].into()),
        };
        let mut fields = OrganizationFields::default();
        match model {
            "organization" => fields.organization = schema,
            "member" => fields.member = schema,
            "invitation" => fields.invitation = schema,
            "team" => fields.team = schema,
            "organizationRole" => fields.organization_role = schema,
            _ => unreachable!(),
        }
        let store = EphemeralStore::new(Arc::new(config(false)));
        store.configure_organization_fields(fields)?;
        let _ = user(&store).await?;
        if model != "organization" {
            let _ = store
                .create_organization(CreateOrganization::new("Organization", "ordinary"))
                .await?;
        }
        let (created, updated) = match model {
            "organization" => {
                let row = store
                    .create_organization(CreateOrganization::new("Organization", "ordinary"))
                    .await?;
                let updated = store
                    .update_organization(
                        row.id.typed()?,
                        UpdateOrganization {
                            name: Some("Updated".into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                (selected(row)?, selected(updated)?)
            }
            "member" => {
                let row = store
                    .create_member(CreateMember::new("001", "001", "owner"))
                    .await?;
                let updated = store.update_member_role(row.id.typed()?, "admin").await?;
                (selected(row)?, selected(updated)?)
            }
            "invitation" => {
                let row = store
                    .create_invitation(CreateInvitation::new(
                        "001",
                        EMAIL,
                        "member",
                        "001",
                        "2100-01-01T00:00:00Z"
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .unwrap()
                            .into(),
                    ))
                    .await?;
                let updated = store
                    .update_invitation_status(row.id.typed()?, InvitationStatus::Canceled)
                    .await?;
                (selected(row)?, selected(updated)?)
            }
            "team" => {
                let row = store
                    .create_team(CreateTeam {
                        name: "Team".into(),
                        organization_id: "001".into(),
                        ..Default::default()
                    })
                    .await?;
                let updated = store
                    .update_team(
                        row.id.typed()?,
                        UpdateTeam {
                            name: Some("Updated".into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                (selected(row)?, selected(updated)?)
            }
            "organizationRole" => {
                let row = store
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: "001".into(),
                        role: "viewer".into(),
                        permission: FieldValue::from(FieldMap::new()),
                        additional_fields: Default::default(),
                    })
                    .await?;
                let updated = store
                    .update_organization_role(
                        row.id.typed()?,
                        UpdateOrganizationRole {
                            role: Some("updated".into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                (selected(row)?, selected(updated)?)
            }
            _ => unreachable!(),
        };
        let _ = families.insert(
            model.into(),
            json!({"created":created,"updated":updated,"trace":*trace.lock().unwrap()}),
        );
    }
    assert_eq!(Value::Object(families), fixture["families"]);
    Ok(())
}

#[tokio::test]
async fn organization_serial_queries_joins_and_ordinary_lifecycle_match_upstream() -> AuthResult<()>
{
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-serial-references-1.7.6.json"
    ))?;
    let actual = vec![
        lifecycle::observe(false).await?,
        lifecycle::observe(true).await?,
    ];
    assert_eq!(json!(actual), fixture["lifecycles"]);
    Ok(())
}

#[tokio::test]
async fn explicit_native_reference_replacement_retains_ordinary_string_storage() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-serial-references-1.7.6.json"
    ))?;
    let outputs = Arc::new(Mutex::new(Vec::new()));
    let trace = outputs.clone();
    let store = EphemeralStore::new(Arc::new(config(false)));
    store.configure_organization_fields(OrganizationFields {
        organization_role: UserConfig {
            additional_fields: Some(
                [(
                    "organizationId".into(),
                    UserFieldConfig {
                        field_name: Some("stored_organization_id".into()),
                        transform: Some(FieldTransforms {
                            output: Some(UserFieldTransform::new(move |value| {
                                trace.lock().unwrap().push(value.json()?);
                                Ok(value)
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
        ..Default::default()
    })?;
    let _ = user(&store).await?;
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "ordinary"))
        .await?;
    let created = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: organization.id.typed()?.clone(),
            role: "viewer".into(),
            permission: FieldValue::from(FieldMap::new()),
            additional_fields: Default::default(),
        })
        .await?;
    let read = store
        .find_organization_role(
            organization.id.typed()?,
            OrganizationRoleKey::Name("viewer"),
        )
        .await?
        .expect("ordinary replaced-reference role exists");
    assert_eq!(
        json!({"created":created.organization_id,"read":read.organization_id,"outputs":*outputs.lock().unwrap()}),
        fixture["replacement"]
    );
    Ok(())
}
