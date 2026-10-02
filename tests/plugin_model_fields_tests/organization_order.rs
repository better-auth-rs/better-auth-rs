use super::*;
use better_auth::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use better_auth_core::{
    CreateInvitation, CreateMember, CreateOrganization, CreateOrganizationRole, CreateTeam,
    InvitationStatus, UpdateOrganization, UpdateOrganizationRole, UpdateTeam,
    organization_fields::OrganizationFields,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Schema};

#[path = "../../compat-tests/rust-server/src/organization_fields/models.rs"]
#[allow(
    unreachable_pub,
    reason = "The shared SeaORM fixture derives require public model types"
)]
mod models;

type Events = Arc<Mutex<Vec<Value>>>;

fn names(model: &str) -> &'static [&'static str] {
    match model {
        "organization" => &["logo", "name"],
        "team" => &["name"],
        "invitation" => &["status", "role"],
        _ => &["role"],
    }
}

fn policy(field: &'static str, events: &Events) -> UserFieldConfig {
    let input = events.clone();
    let output = events.clone();
    UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                input.lock().unwrap().push(json!([field, "input", value]));
                Ok(value.map(|value| json!(value.as_str().unwrap().trim())))
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output.lock().unwrap().push(json!([field, "output", value]));
                Ok(value.map(|value| {
                    if matches!(field, "name" | "logo" | "label") {
                        json!(format!("{}:out", value.as_str().unwrap()))
                    } else {
                        value
                    }
                }))
            })),
        }),
        ..Default::default()
    }
}

fn declared(model: &str, events: &Events) -> UserConfig {
    let default = events.clone();
    let update = events.clone();
    let mut result = fields(
        "label",
        UserFieldConfig {
            field_name: Some(
                if model == "member" {
                    "stored_label"
                } else {
                    "storedLabel"
                }
                .into(),
            ),
            default_value_fn: Some(Arc::new(move || {
                default.lock().unwrap().push(json!(["label", "default"]));
                json!(" Label ")
            })),
            on_update: Some(Arc::new(move || {
                update.lock().unwrap().push(json!(["label", "onUpdate"]));
                json!(" Updated ")
            })),
            ..policy("label", events)
        },
    );
    for field in names(model) {
        let _ = result
            .fields_mut()
            .insert((*field).into(), policy(field, events));
    }
    if model == "organization" {
        let logo = result.fields_mut().get_mut("logo").unwrap();
        let default = events.clone();
        logo.default_value_fn = Some(Arc::new(move || {
            default.lock().unwrap().push(json!(["logo", "default"]));
            json!(" Logo ")
        }));
        let update = events.clone();
        logo.on_update = Some(Arc::new(move || {
            update.lock().unwrap().push(json!(["logo", "onUpdate"]));
            json!(" Next Logo ")
        }));
    }
    result
}

fn schema(model: &str, fields: UserConfig) -> OrganizationFields {
    let mut schema = OrganizationFields::default();
    *match model {
        "organization" => &mut schema.organization,
        "team" => &mut schema.team,
        "member" => &mut schema.member,
        "invitation" => &mut schema.invitation,
        "organizationRole" => &mut schema.organization_role,
        _ => unreachable!("The pinned fixture contains five Organization models"),
    } = fields;
    schema
}

async fn sqlite_custom() -> AuthResult<Arc<dyn AuthStore<BundledSchema>>> {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("SQLite fixture connects");
    migrator::run_migrations(&database)
        .await
        .expect("SQLite fixture migrates");
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(models::organization::Entity),
        schema.create_table_from_entity(models::member::Entity),
        schema.create_table_from_entity(models::invitation::Entity),
        schema.create_table_from_entity(models::team::Entity),
        schema.create_table_from_entity(models::team_member::Entity),
        schema.create_table_from_entity(models::organization_role::Entity),
    ] {
        let _ = database
            .execute(&statement)
            .await
            .expect("Organization fixture creates its typed tables");
    }
    Ok(Arc::new(
        SeaOrmStore::<BundledSchema>::new(config(), database)
            .with_organization_schema::<models::Models>(),
    ))
}

fn visible(model: &str, row: &Value) -> Value {
    std::iter::once("label")
        .chain(names(model).iter().copied())
        .map(|field| (field.into(), row[field].clone()))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

async fn capture<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    model: &str,
    mode: &str,
) -> AuthResult<Value> {
    let events = Events::default();
    let mut declaration = declared(model, &events);
    let store = if mode == "direct" {
        raw.configure_organization_fields(schema(model, declaration))?;
        raw.clone()
    } else {
        let label = declaration.fields_mut().shift_remove("label").unwrap();
        let custom = Fields(vec![(EntityRole::Organization, fields("label", label))]);
        let mut options = OrganizationConfig::default();
        options.teams.enabled = true;
        options.schema = schema(model, declaration);
        let organization = OrganizationPlugin::with_config(options);
        let builder = BetterAuth::new(config()).store_arc(raw.clone());
        let auth = if mode == "before" {
            builder.plugin(custom).plugin(organization).build().await?
        } else {
            builder.plugin(organization).plugin(custom).build().await?
        };
        auth.store().clone()
    };
    let user = owner(store.as_ref(), "ordinary-order").await?;
    let parent = if model == "organization" {
        None
    } else {
        Some(
            store
                .create_organization(CreateOrganization::new("Parent", "parent"))
                .await?,
        )
    };
    let parent_id = parent
        .as_ref()
        .map(|row| row.id.typed().unwrap().as_str())
        .unwrap_or("");
    let created = match model {
        "organization" => serde_json::to_value(
            store
                .create_organization(CreateOrganization::new(" Acme ", "acme"))
                .await?,
        )?,
        "team" => serde_json::to_value(
            store
                .create_team(CreateTeam {
                    name: " Team ".into(),
                    organization_id: parent_id.into(),
                    ..Default::default()
                })
                .await?,
        )?,
        "member" => serde_json::to_value(
            store
                .create_member(CreateMember::new(parent_id, &user, "member"))
                .await?,
        )?,
        "invitation" => serde_json::to_value(
            store
                .create_invitation(CreateInvitation::new(
                    parent_id,
                    "invitee@order.test",
                    "member",
                    &user,
                    chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
                        .unwrap()
                        .to_utc(),
                ))
                .await?,
        )?,
        "organizationRole" => serde_json::to_value(
            store
                .create_organization_role(CreateOrganizationRole {
                    additional_fields: Default::default(),
                    organization_id: parent_id.into(),
                    role: "reader".into(),
                    permission: json!({"organization": ["read"]}),
                })
                .await?,
        )?,
        _ => unreachable!(),
    };
    let id = created["id"].as_str().unwrap();
    let updated = match model {
        "organization" => serde_json::to_value(
            store
                .update_organization(
                    id,
                    UpdateOrganization {
                        name: Some(" Renamed ".into()),
                        ..Default::default()
                    },
                )
                .await?,
        )?,
        "team" => serde_json::to_value(
            store
                .update_team(
                    id,
                    UpdateTeam {
                        name: Some(" Next ".into()),
                        ..Default::default()
                    },
                )
                .await?,
        )?,
        "member" => serde_json::to_value(store.update_member_role(id, "member").await?)?,
        "invitation" => serde_json::to_value(
            store
                .update_invitation_status(id, InvitationStatus::Pending)
                .await?,
        )?,
        "organizationRole" => serde_json::to_value(
            store
                .update_organization_role(
                    id,
                    UpdateOrganizationRole {
                        role: Some("reader".into()),
                        ..Default::default()
                    },
                )
                .await?,
        )?,
        _ => unreachable!(),
    };
    let found = match model {
        "organization" => serde_json::to_value(store.get_organization_by_id(id).await?.unwrap())?,
        "team" => serde_json::to_value(store.get_team(id).await?.unwrap())?,
        "member" => serde_json::to_value(store.get_member_by_id(id).await?.unwrap())?,
        "invitation" => serde_json::to_value(store.get_invitation_by_id(id).await?.unwrap())?,
        "organizationRole" => {
            serde_json::to_value(store.get_organization_role(id).await?.unwrap())?
        }
        _ => unreachable!(),
    };
    if mode != "direct" {
        let stored = raw.get_organization_by_id(id).await?.unwrap();
        assert_eq!(stored.name.typed()?, "Renamed");
        assert_eq!(stored.logo.typed()?.as_deref(), Some("Next Logo"));
    }
    let events = events.lock().unwrap().clone();
    Ok(json!({
        "backend": backend, "model": model, "mode": mode,
        "created": visible(model, &created), "updated": visible(model, &updated),
        "found": visible(model, &found), "events": events,
    }))
}

#[tokio::test]
async fn memory_raw_and_runtime_organization_fields_match_upstream_order() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/organization-direct-order-1.7.6.json"
    ))?;
    for expected in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "memory")
    {
        let actual = capture(
            memory(),
            "memory",
            expected["model"].as_str().unwrap(),
            expected["mode"].as_str().unwrap(),
        )
        .await?;
        assert_eq!(&actual, expected);
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_raw_and_runtime_organization_fields_match_upstream_order() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/organization-direct-order-1.7.6.json"
    ))?;
    for expected in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "sqlite")
    {
        let actual = capture(
            sqlite_custom().await?,
            "sqlite",
            expected["model"].as_str().unwrap(),
            expected["mode"].as_str().unwrap(),
        )
        .await?;
        assert_eq!(&actual, expected);
    }
    Ok(())
}
