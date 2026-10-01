use better_auth::config::UserFieldTransform;
use better_auth::config::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth::plugins::organization::OrganizationConfig;
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Schema,
};
use serde_json::{Value, json};
use std::sync::Arc;
#[path = "organization_fields/models.rs"]
pub mod models;

fn suffix(value: Option<Value>, suffix: &str) -> better_auth::AuthResult<Option<Value>> {
    let value = match value {
        None => "undefined".to_owned(),
        Some(Value::String(value)) => value,
        Some(value) => value.to_string(),
    };
    Ok(Some(json!(format!("{value}:{suffix}"))))
}

fn fields() -> UserConfig {
    UserConfig {
        additional_fields: [
            (
                "label".into(),
                UserFieldConfig {
                    required: Some(false),
                    field_name: Some("storedLabel".into()),
                    default_value: Some(json!("guest")),
                    input_transform: Some(UserFieldTransform::new(|value| suffix(value, "in"))),
                    output_transform: Some(UserFieldTransform::new(|value| suffix(value, "out"))),
                    ..Default::default()
                },
            ),
            (
                "secret".into(),
                UserFieldConfig {
                    required: Some(false),
                    returned: false,
                    default_value: Some(json!("hidden")),
                    ..Default::default()
                },
            ),
            (
                "protected".into(),
                UserFieldConfig {
                    required: Some(false),
                    input: false,
                    default_value: Some(json!("server")),
                    ..Default::default()
                },
            ),
            (
                "marker".into(),
                UserFieldConfig {
                    required: Some(false),
                    default_value: Some(json!("created")),
                    on_update: Some(Arc::new(|| json!("updated"))),
                    ..Default::default()
                },
            ),
            (
                "score".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    required: Some(false),
                    default_value: Some(json!(1)),
                    validator: Some(Arc::new(|value| {
                        if value.as_f64().is_some_and(|value| value >= 0.0) {
                            Ok(value)
                        } else {
                            Err(better_auth::AuthError::bad_request(
                                "score must be nonnegative",
                            ))
                        }
                    })),
                    ..Default::default()
                },
            ),
            (
                "tags".into(),
                UserFieldConfig {
                    field_type: UserFieldType::StringArray,
                    required: Some(false),
                    default_value: Some(json!(["starter"])),
                    ..Default::default()
                },
            ),
            (
                "payload".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    required: Some(false),
                    default_value: Some(json!({"theme":"system"})),
                    ..Default::default()
                },
            ),
        ]
        .into(),
    }
}

pub fn configure(config: &mut OrganizationConfig) {
    config.teams.maximum_members_per_team = Some(1);
    config.schema.organization = fields();
    config.schema.member = fields();
    config
        .schema
        .member
        .additional_fields
        .get_mut("label")
        .expect("the shared field configuration includes label")
        .field_name = Some("stored_label".into());
    config.schema.invitation = fields();
    config.schema.team = fields();
    config.schema.organization_role = fields();
    config.schema.organization.additional_fields.extend([
        (
            "requiredTag".into(),
            UserFieldConfig {
                required: Some(true),
                default_value: Some(json!("fallback")),
                ..Default::default()
            },
        ),
        ("implicitTag".into(), UserFieldConfig::default()),
        (
            "category".into(),
            UserFieldConfig {
                field_type: UserFieldType::Enum(vec!["basic".into(), "pro".into()]),
                required: Some(false),
                default_value: Some(json!("basic")),
                ..Default::default()
            },
        ),
        (
            "joinedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                required: Some(false),
                default_value: Some(json!("2020-01-02T03:04:05.000Z")),
                ..Default::default()
            },
        ),
    ]);
    let _ = config.schema.organization_role.additional_fields.insert(
        "roleRequired".into(),
        UserFieldConfig {
            required: Some(true),
            default_value: Some(json!("role-default")),
            ..Default::default()
        },
    );
}

pub async fn create_tables(database: &DatabaseConnection) -> Result<(), DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(models::organization::Entity),
        schema.create_table_from_entity(models::member::Entity),
        schema.create_table_from_entity(models::invitation::Entity),
        schema.create_table_from_entity(models::team::Entity),
        schema.create_table_from_entity(models::team_member::Entity),
        schema.create_table_from_entity(models::organization_role::Entity),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}

pub async fn reset(database: &DatabaseConnection) -> Result<(), DbErr> {
    let _ = models::team_member::Entity::delete_many()
        .exec(database)
        .await?;
    let _ = models::team::Entity::delete_many().exec(database).await?;
    let _ = models::invitation::Entity::delete_many()
        .exec(database)
        .await?;
    let _ = models::member::Entity::delete_many().exec(database).await?;
    let _ = models::organization_role::Entity::delete_many()
        .exec(database)
        .await?;
    let _ = models::organization::Entity::delete_many()
        .exec(database)
        .await?;
    Ok(())
}
