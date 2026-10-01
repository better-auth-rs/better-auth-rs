use better_auth::{
    AuthConfig, BetterAuth, SchemaValue,
    config::{UserFieldConfig, UserFieldType},
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
    prelude::{CreateOrganization, CreateTeam},
    seaorm::{Database, SeaOrmStore, sea_orm::EntityTrait},
};
use serde_json::json;
use std::sync::Arc;

mod generated {
    include!(env!("BETTER_AUTH_DYNAMIC_SCHEMA"));
}

#[tokio::test]
async fn generated_builtin_replacement_types_preserve_storage_and_wire_values() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    let mut organization = OrganizationConfig::default();
    organization.schema.organization.additional_fields.extend([
        (
            "name".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                required: Some(false),
                output_transform: Some(Arc::new(|value| {
                    Ok(value.filter(|value| value.as_f64() != Some(99.0)))
                })),
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
                input: false,
                input_transform: Some(Arc::new(|_| Ok(Some(json!("2000-01-02T03:04:05+02:00"))))),
                ..Default::default()
            },
        ),
        (
            "updatedAt".into(),
            UserFieldConfig {
                default_value: Some(json!("public")),
                required: Some(false),
                ..Default::default()
            },
        ),
    ]);
    organization.schema.team.additional_fields.insert(
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
    for (index, name) in [json!(7.0), json!(null), json!(99.0)]
        .into_iter()
        .enumerate()
    {
        let mut input = CreateOrganization::new("ignored", "ignored");
        input.name = SchemaValue::Dynamic(name.clone());
        input.slug = SchemaValue::Dynamic(json!(index));
        input.logo = SchemaValue::Dynamic(json!(true));
        let organization = auth.store().create_organization(input).await.unwrap();
        let wire = serde_json::to_value(&organization).unwrap();
        if name == json!(99.0) {
            assert!(wire.get("name").is_none());
        } else {
            assert_eq!(wire["name"], name);
        }
        assert_eq!(wire["createdAt"], "2000-01-02T03:04:05+02:00");
        assert_eq!(wire["logo"], true);
        assert_eq!(wire["updatedAt"], "public");
        let found = auth
            .store()
            .get_organization_by_slug_value(&json!(index))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, organization.id);
        let stored = generated::organization::Entity::find_by_id(&organization.id)
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.name.map(f64::from), name.as_f64());
        let team = auth
            .store()
            .create_team(CreateTeam {
                name: SchemaValue::Dynamic(json!({"label": "structured"})),
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
