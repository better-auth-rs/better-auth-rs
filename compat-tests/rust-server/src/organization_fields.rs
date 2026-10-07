use better_auth::__private_core::{FieldMap, FieldValue as Value};
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::config::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth::plugins::organization::OrganizationConfig;
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Schema,
};
use std::sync::Arc;
#[path = "organization_fields/models.rs"]
pub mod models;

fn suffix(value: Value, suffix: &str) -> better_auth::AuthResult<Value> {
    let mut text = value.display_utf16()?.as_utf16().to_vec();
    text.extend(format!(":{suffix}").encode_utf16());
    Ok(better_auth::__private_core::Utf16String::from_units(text).into())
}

fn fields(label_column: &str) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        required: Some(false),
                        field_name: Some(label_column.into()),
                        default_value: Some(Value::from("guest")),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(|value| suffix(value, "in"))),
                            output: Some(UserFieldTransform::new(|value| suffix(value, "out"))),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "secret".into(),
                    UserFieldConfig {
                        required: Some(false),
                        returned: Some(false),
                        default_value: Some(Value::from("hidden")),
                        ..Default::default()
                    },
                ),
                (
                    "protected".into(),
                    UserFieldConfig {
                        required: Some(false),
                        input: Some(false),
                        default_value: Some(Value::from("server")),
                        ..Default::default()
                    },
                ),
                (
                    "marker".into(),
                    UserFieldConfig {
                        required: Some(false),
                        default_value: Some(Value::from("created")),
                        on_update: Some(Arc::new(|| Value::from("updated"))),
                        ..Default::default()
                    },
                ),
                (
                    "score".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        required: Some(false),
                        default_value: Some(Value::from(1)),
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
                        default_value: Some(Value::from(vec![Value::from("starter")])),
                        ..Default::default()
                    },
                ),
                (
                    "payload".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        required: Some(false),
                        default_value: Some(Value::from(FieldMap::from([(
                            "theme".into(),
                            Value::from("system"),
                        )]))),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    }
}

pub fn configure(config: &mut OrganizationConfig) {
    config.teams.maximum_members_per_team = Some(1);
    config.schema.organization = fields("storedLabel");
    config.schema.member = fields("stored_label");
    config.schema.invitation = fields("storedLabel");
    config.schema.team = fields("storedLabel");
    config.schema.organization_role = fields("storedLabel");
    config.schema.organization.fields_mut().extend([
        (
            "requiredTag".into(),
            UserFieldConfig {
                required: Some(true),
                default_value: Some(Value::from("fallback")),
                ..Default::default()
            },
        ),
        ("implicitTag".into(), UserFieldConfig::default()),
        (
            "category".into(),
            UserFieldConfig {
                field_type: UserFieldType::Enum(vec!["basic".into(), "pro".into()]),
                required: Some(false),
                default_value: Some(Value::from("basic")),
                ..Default::default()
            },
        ),
        (
            "joinedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                required: Some(false),
                default_value: Some(Value::from("2020-01-02T03:04:05.000Z")),
                ..Default::default()
            },
        ),
    ]);
    let _ = config.schema.organization_role.fields_mut().insert(
        "roleRequired".into(),
        UserFieldConfig {
            required: Some(true),
            default_value: Some(Value::from("role-default")),
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
