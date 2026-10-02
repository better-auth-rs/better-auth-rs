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
                input_events
                    .lock()
                    .unwrap()
                    .push(json!([field, "input", value]));
                Ok(value.map(|value| json!(value.as_str().unwrap().trim())))
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output_events
                    .lock()
                    .unwrap()
                    .push(json!([field, "output", value]));
                Ok(value.map(|value| json!(format!("{}:custom", value.as_str().unwrap()))))
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
                                default_value: Some(json!(" Default ")),
                                on_update: Some(Arc::new(|| json!(" Updated "))),
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
                    own_events.lock().unwrap().push(json!([
                        "organization.name",
                        "own-output",
                        value
                    ]));
                    Ok(value.map(|value| json!(format!("{}:own", value.as_str().unwrap()))))
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
        "listed": listed, "events": *events.lock().unwrap(),
    });
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/organization-plugin-fields.json"))?;
    let expected = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["backend"] == backend && case["order"] == order)
        .unwrap();
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
