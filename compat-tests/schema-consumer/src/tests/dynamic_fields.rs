use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::{
    AuthConfig, BetterAuth, FieldValue, SchemaValue,
    config::{UserFieldConfig, UserFieldType},
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
    prelude::{CreateOrganization, CreateTeam},
    seaorm::{Database, SeaOrmStore, sea_orm::EntityTrait},
};
use serde_json::json;

mod generated {
    include!(env!("BETTER_AUTH_DYNAMIC_SCHEMA"));
}

#[tokio::test]
async fn generated_builtin_replacement_types_preserve_storage_and_wire_values() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    let mut organization = OrganizationConfig::default();
    organization.schema.organization.fields_mut().extend([
        (
            "name".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                required: Some(false),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(|value| {
                        Ok(if value.as_f64() == Some(99.0) {
                            FieldValue::Undefined
                        } else {
                            value
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "slug".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                required: Some(true),
                ..Default::default()
            },
        ),
        (
            "logo".into(),
            UserFieldConfig {
                field_type: UserFieldType::Boolean,
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "createdAt".into(),
            UserFieldConfig {
                input: Some(false),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(|_| {
                        Ok("2000-01-02T03:04:05+02:00".into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "updatedAt".into(),
            UserFieldConfig {
                default_value: Some("public".into()),
                required: Some(false),
                ..Default::default()
            },
        ),
    ]);
    organization.schema.team.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            required: Some(false),
            ..Default::default()
        },
    );
    let config = AuthConfig::new("consumer-dynamic-secret-at-least-32-characters");
    let auth = BetterAuth::<generated::AppAuthSchema>::new(config.clone())
        .store(
            SeaOrmStore::<generated::AppAuthSchema>::new(config, database.clone())
                .with_organization_schema::<generated::AppOrganizationSchema>(),
        )
        .plugin(OrganizationPlugin::with_config(organization))
        .build()
        .await
        .unwrap();
    for (index, (name, wire_name)) in [
        (json!(7.0), Some(json!(7))),
        (json!(null), Some(json!(null))),
        (json!(99.0), None),
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = CreateOrganization::new("ignored", "ignored");
        input.name = SchemaValue::Dynamic(FieldValue::from_json(name.clone()).unwrap());
        input.slug = SchemaValue::Dynamic(FieldValue::from_json(json!(index)).unwrap());
        input.logo = SchemaValue::Dynamic(true.into());
        let organization = auth.store().create_organization(input).await.unwrap();
        let wire = serde_json::to_value(&organization).unwrap();
        assert_eq!(wire.get("name"), wire_name.as_ref());
        assert_eq!(wire["createdAt"], "2000-01-02T03:04:05+02:00");
        assert_eq!(wire["logo"], true);
        assert_eq!(wire["updatedAt"], "public");
        let found = auth
            .store()
            .get_organization_by_slug_value(&FieldValue::from_json(json!(index)).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, organization.id);
        let stored = generated::organization::Entity::find_by_id(organization.id.typed().unwrap())
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.name.map(f64::from), name.as_f64());
        let team = auth
            .store()
            .create_team(CreateTeam {
                name: SchemaValue::Dynamic(
                    FieldValue::from_json(json!({"label": "structured"})).unwrap(),
                ),
                organization_id: organization.id,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(team).unwrap()["name"],
            json!({"label": "structured"})
        );
    }
}
