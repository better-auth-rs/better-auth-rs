use super::*;
use better_auth::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use better_auth_core::{
    CreateInvitation, CreateMember, CreateOrganization, CreateOrganizationRole, CreateTeam,
    InvitationStatus, UpdateOrganization, UpdateOrganizationRole, UpdateTeam,
    organization_fields::OrganizationFields,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Schema};

#[path = "../../compat-tests/rust-server/src/organization_fields/models.rs"]
#[expect(
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
                trace_lock(&input)?.push(json!([field, "input", value.json()?]));
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => required(
                        value.as_str(),
                        "Organization input policy requires a string",
                    )?
                    .trim()
                    .into(),
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                trace_lock(&output)?.push(json!([field, "output", value.json()?]));
                Ok(
                    if !value.is_undefined() && matches!(field, "name" | "logo" | "label") {
                        format!(
                            "{}:out",
                            required(
                                value.as_str(),
                                "Organization output policy requires a string"
                            )?
                        )
                        .into()
                    } else {
                        value
                    },
                )
            })),
        }),
        ..Default::default()
    }
}

#[expect(
    clippy::expect_used,
    reason = "Default and onUpdate callbacks cannot return errors; a poisoned trace lock must fail the field-order contract"
)]
fn declared(model: &str, events: &Events) -> AuthResult<UserConfig> {
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
                trace_lock(&default)
                    .expect("Label default trace lock must remain available")
                    .push(json!(["label", "default"]));
                Ok(" Label ".into())
            })),
            on_update: Some(Arc::new(move || {
                trace_lock(&update)
                    .expect("Label update trace lock must remain available")
                    .push(json!(["label", "onUpdate"]));
                Ok(" Updated ".into())
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
        let logo = required(
            result.fields_mut().get_mut("logo"),
            "Organization field order must declare logo",
        )?;
        let default = events.clone();
        logo.default_value_fn = Some(Arc::new(move || {
            trace_lock(&default)
                .expect("Logo default trace lock must remain available")
                .push(json!(["logo", "default"]));
            Ok(" Logo ".into())
        }));
        let update = events.clone();
        logo.on_update = Some(Arc::new(move || {
            trace_lock(&update)
                .expect("Logo update trace lock must remain available")
                .push(json!(["logo", "onUpdate"]));
            Ok(" Next Logo ".into())
        }));
    }
    Ok(result)
}

fn schema(model: &str, fields: UserConfig) -> AuthResult<OrganizationFields> {
    let mut schema = OrganizationFields::default();
    *match model {
        "organization" => &mut schema.organization,
        "team" => &mut schema.team,
        "member" => &mut schema.member,
        "invitation" => &mut schema.invitation,
        "organizationRole" => &mut schema.organization_role,
        _ => {
            return Err(AuthError::internal(format!(
                "Unknown Organization fixture model: {model}"
            )));
        }
    } = fields;
    Ok(schema)
}

async fn sqlite_custom() -> AuthResult<Arc<dyn AuthStore<BundledSchema>>> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| {
            AuthError::internal(format!(
                "Cannot connect Organization field-order fixture: {error}"
            ))
        })?;
    migrator::run_migrations(&database).await.map_err(|error| {
        AuthError::internal(format!(
            "Cannot migrate Organization field-order fixture: {error}"
        ))
    })?;
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(models::organization::Entity),
        schema.create_table_from_entity(models::member::Entity),
        schema.create_table_from_entity(models::invitation::Entity),
        schema.create_table_from_entity(models::team::Entity),
        schema.create_table_from_entity(models::team_member::Entity),
        schema.create_table_from_entity(models::organization_role::Entity),
    ] {
        let _ = database.execute(&statement).await.map_err(|error| {
            AuthError::internal(format!(
                "Cannot create Organization field-order tables: {error}"
            ))
        })?;
    }
    Ok(Arc::new(
        SeaOrmStore::<BundledSchema>::new(config(), database)
            .with_organization_schema::<models::Models>(),
    ))
}

fn visible(model: &str, row: &Value) -> AuthResult<Value> {
    std::iter::once("label")
        .chain(names(model).iter().copied())
        .map(|field| {
            Ok((
                field.into(),
                required(
                    row.get(field),
                    "Organization projection must contain each declared field",
                )?
                .clone(),
            ))
        })
        .collect::<AuthResult<serde_json::Map<_, _>>>()
        .map(Value::Object)
}

async fn capture<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    model: &str,
    mode: &str,
) -> AuthResult<Value> {
    let events = Events::default();
    let mut declaration = declared(model, &events)?;
    let store = if mode == "direct" {
        raw.configure_organization_fields(schema(model, declaration)?)?;
        raw.clone()
    } else {
        let label = required(
            declaration.fields_mut().shift_remove("label"),
            "Field-order fixture must declare label",
        )?;
        let custom = Fields(vec![(EntityRole::Organization, fields("label", label))]);
        let mut options = OrganizationConfig::default();
        options.teams.enabled = true;
        options.schema = schema(model, declaration)?;
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
        .map(|row| row.id.typed().map(String::as_str))
        .transpose()?
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
                        .map_err(|error| {
                            AuthError::internal(format!(
                                "Invalid Organization fixture expiration: {error}"
                            ))
                        })?
                        .to_utc()
                        .into(),
                ))
                .await?,
        )?,
        "organizationRole" => serde_json::to_value(
            store
                .create_organization_role(CreateOrganizationRole {
                    additional_fields: Default::default(),
                    organization_id: parent_id.into(),
                    role: "reader".into(),
                    permission: FieldMap::from([(
                        "organization".into(),
                        vec!["read".into()].into(),
                    )])
                    .into(),
                })
                .await?,
        )?,
        _ => {
            return Err(AuthError::internal(format!(
                "Unknown Organization fixture model: {model}"
            )));
        }
    };
    let id = required(
        created.get("id").and_then(Value::as_str),
        "Created Organization record must have a string ID",
    )?;
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
        _ => {
            return Err(AuthError::internal(format!(
                "Unknown Organization fixture model: {model}"
            )));
        }
    };
    let found = match model {
        "organization" => serde_json::to_value(required(
            store.get_organization_by_id(id).await?,
            "Updated organization must remain stored",
        )?)?,
        "team" => serde_json::to_value(required(
            store.get_team(id).await?,
            "Updated team must remain stored",
        )?)?,
        "member" => serde_json::to_value(required(
            store.get_member_by_id(id).await?,
            "Updated member must remain stored",
        )?)?,
        "invitation" => serde_json::to_value(required(
            store.get_invitation_by_id(id).await?,
            "Updated invitation must remain stored",
        )?)?,
        "organizationRole" => serde_json::to_value(required(
            store.get_organization_role(id).await?,
            "Updated organization role must remain stored",
        )?)?,
        _ => {
            return Err(AuthError::internal(format!(
                "Unknown Organization fixture model: {model}"
            )));
        }
    };
    if mode != "direct" {
        let stored = required(
            raw.get_organization_by_id(id).await?,
            "Organization field-order fixture must remain stored",
        )?;
        assert_eq!(stored.name.typed()?, "Renamed");
        assert_eq!(stored.logo.typed()?.as_deref(), Some("Next Logo"));
    }
    let events = trace_lock(&events)?.clone();
    Ok(json!({
        "backend": backend, "model": model, "mode": mode,
        "created": visible(model, &created)?, "updated": visible(model, &updated)?,
        "found": visible(model, &found)?, "events": events,
    }))
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The Memory contract must assert each complete captured field-order observation"
)]
async fn memory_raw_and_runtime_organization_fields_match_upstream_order() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/organization-direct-order-1.7.6.json"
    ))?;
    for expected in required(
        fixture.get("cases").and_then(Value::as_array),
        "Organization fixture must contain cases",
    )?
    .iter()
    .filter(|case| case.get("backend").and_then(Value::as_str) == Some("memory"))
    {
        let actual = capture(
            memory(),
            "memory",
            required(
                expected.get("model").and_then(Value::as_str),
                "Organization case must name a model",
            )?,
            required(
                expected.get("mode").and_then(Value::as_str),
                "Organization case must name a mode",
            )?,
        )
        .await?;
        assert_eq!(&actual, expected);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The SQLite contract must assert each complete captured field-order observation"
)]
async fn sqlite_raw_and_runtime_organization_fields_match_upstream_order() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/organization-direct-order-1.7.6.json"
    ))?;
    for expected in required(
        fixture.get("cases").and_then(Value::as_array),
        "Organization fixture must contain cases",
    )?
    .iter()
    .filter(|case| case.get("backend").and_then(Value::as_str) == Some("sqlite"))
    {
        let actual = capture(
            sqlite_custom().await?,
            "sqlite",
            required(
                expected.get("model").and_then(Value::as_str),
                "Organization case must name a model",
            )?,
            required(
                expected.get("mode").and_then(Value::as_str),
                "Organization case must name a mode",
            )?,
        )
        .await?;
        assert_eq!(&actual, expected);
    }
    Ok(())
}
