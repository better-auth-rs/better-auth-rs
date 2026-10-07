use super::*;
use better_auth::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use better_auth_core::{
    CreateOrganization, CreateTeam, Organization, UpdateOrganization, UpdateTeam,
};

fn policy(field: &'static str, events: &Arc<Mutex<Vec<Value>>>) -> UserFieldConfig {
    let input_events = events.clone();
    let output_events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&input_events)?.push(json!([field, "input", value.json()?]));
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => required(value.as_str(), "Expected a string field callback value")?
                        .trim()
                        .into(),
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                trace_lock(&output_events)?.push(json!([field, "output", value.json()?]));
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => format!(
                        "{}:custom",
                        required(value.as_str(), "Expected a string field callback value")?
                    )
                    .into(),
                })
            })),
        }),
        ..Default::default()
    }
}

fn visible(row: &Organization) -> AuthResult<Value> {
    Ok(json!({"name": row.name.json()?, "logo": row.logo.json()?.unwrap_or(Value::Null)}))
}

async fn registration<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    order: &str,
) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let custom = Fields(vec![
        (
            EntityRole::Organization,
            UserConfig {
                additional_fields: Some(
                    [
                        ("name".into(), policy("organization.name", &events)),
                        (
                            "logo".into(),
                            UserFieldConfig {
                                default_value: Some(" Default ".into()),
                                on_update: Some(Arc::new(|| Ok(" Updated ".into()))),
                                ..policy("organization.logo", &events)
                            },
                        ),
                    ]
                    .into(),
                ),
            },
        ),
        (
            EntityRole::Team,
            fields("name", policy("team.name", &events)),
        ),
    ]);
    let own_events = events.clone();
    let mut organization = OrganizationConfig::default();
    organization.teams.enabled = true;
    organization.schema.organization = fields(
        "name",
        UserFieldConfig {
            required: Some(true),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    trace_lock(&own_events)?.push(json!([
                        "organization.name",
                        "own-output",
                        value.json()?
                    ]));
                    Ok(match value {
                        FieldValue::Undefined => FieldValue::Undefined,
                        value => format!(
                            "{}:own",
                            required(value.as_str(), "Expected a string field callback value")?
                        )
                        .into(),
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let plugin = OrganizationPlugin::with_config(organization);
    let builder = BetterAuth::new(config()).store_arc(raw);
    let auth = if order == "before" {
        builder.plugin(custom).plugin(plugin).build().await?
    } else {
        builder.plugin(plugin).plugin(custom).build().await?
    };
    let store = auth.store();
    let org = store
        .create_organization(CreateOrganization::new(" Acme ", "acme"))
        .await?;
    let organization_created = visible(&org)?;
    let updated = store
        .update_organization(
            org.id.typed()?,
            UpdateOrganization {
                name: Some(" Renamed ".into()),
                ..Default::default()
            },
        )
        .await?;
    let organization_updated = visible(&updated)?;
    let team = store
        .create_team(CreateTeam {
            name: " Team ".into(),
            organization_id: org.id.clone(),
            ..Default::default()
        })
        .await?;
    let team_created = json!({"name": team.name.json()?});
    let team = store
        .update_team(
            team.id.typed()?,
            UpdateTeam {
                name: Some(" Next ".into()),
                ..Default::default()
            },
        )
        .await?;
    let listed = store
        .list_organizations_by_ids(&[org.id.typed()?.clone()])
        .await?
        .iter()
        .map(visible)
        .collect::<AuthResult<Vec<_>>>()?;
    let actual = json!({
        "backend": backend, "order": order,
        "organizationCreated": organization_created, "organizationUpdated": organization_updated,
        "teamCreated": team_created, "teamUpdated": {"name": team.name.json()?},
        "listed": listed, "events": *trace_lock(&events)?,
    });
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/organization-plugin-fields.json"))?;
    let expected = required(
        fixture.get("cases").and_then(Value::as_array),
        "Expected captured Organization field cases",
    )?
    .iter()
    .find(|case| {
        case.get("backend") == Some(&json!(backend)) && case.get("order") == Some(&json!(order))
    })
    .ok_or_else(|| AuthError::internal("Missing captured Organization field case"))?;
    assert_eq!(&actual, expected);
    Ok(())
}

#[tokio::test]
async fn memory_organization_registration_follows_plugin_order() -> AuthResult<()> {
    for order in ["before", "after"] {
        registration(memory(), "memory", order).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_organization_registration_follows_plugin_order() -> AuthResult<()> {
    for order in ["before", "after"] {
        registration(sqlite().await?, "sqlite", order).await?;
    }
    Ok(())
}
