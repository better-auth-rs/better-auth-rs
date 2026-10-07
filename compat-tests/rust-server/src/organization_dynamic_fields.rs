use better_auth::FieldValue;
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::config::{UserFieldConfig, UserFieldType};
use better_auth::plugins::organization::OrganizationConfig;
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Schema,
};

pub fn configure(config: &mut OrganizationConfig) {
    config.teams.enabled = true;
    config.teams.default_team = false;
    let raw_date = UserFieldConfig {
        input: Some(false),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Ok("2000-01-02T03:04:05+02:00".into())
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    config.schema.organization.fields_mut().extend([
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
            "logo".into(),
            UserFieldConfig {
                field_type: UserFieldType::Boolean,
                required: Some(false),
                ..Default::default()
            },
        ),
        ("createdAt".into(), raw_date.clone()),
        (
            "updatedAt".into(),
            UserFieldConfig {
                required: Some(false),
                default_value: Some("public-updated".into()),
                ..Default::default()
            },
        ),
    ]);
    config.schema.team.fields_mut().extend([
        (
            "name".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "createdAt".into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        ),
        ("updatedAt".into(), raw_date),
        (
            "memberCount".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                required: Some(false),
                default_value: Some(17.into()),
                ..Default::default()
            },
        ),
    ]);
}

pub mod organization {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "organization")]
    #[sea_orm(table_name = "dynamic_organization")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<f64>,
        pub slug: String,
        pub logo: Option<bool>,
        pub metadata: Option<Json>,
        pub created_at: String,
        pub auth_updated_at: DateTimeUtc,
        #[serde(rename = "updatedAt")]
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub mod team {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team")]
    #[sea_orm(table_name = "dynamic_team")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<Json>,
        pub organization_id: String,
        pub created_at: Option<String>,
        pub updated_at: Option<String>,
        #[serde(rename = "memberCount")]
        #[sea_orm(column_name = "memberCount")]
        pub member_count: Option<f64>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
type Base = crate::organization_fields::models::Models;
pub type Models = better_auth_seaorm::OrganizationModels<
    organization::Model,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::Member,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::Invitation,
    team::Model,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::TeamMember,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::OrganizationRole,
>;

pub async fn create_tables(database: &DatabaseConnection) -> Result<(), DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(organization::Entity),
        schema.create_table_from_entity(team::Entity),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}
pub async fn reset(database: &DatabaseConnection) -> Result<(), DbErr> {
    let _ = team::Entity::delete_many().exec(database).await?;
    let _ = organization::Entity::delete_many().exec(database).await?;
    Ok(())
}
