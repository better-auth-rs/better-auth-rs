use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::{FieldMap, FieldValue};
use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
use serde::Serialize;

mod session;

#[derive(better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "user")]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTimeUtc>,
    pub metadata: Json,
    pub department: Option<String>,
    pub cohort: Option<String>,
    #[serde(rename = "changedMarker")]
    pub changed_marker: Option<String>,
    pub enabled: Option<bool>,
    pub tags: Option<Json>,
    pub ratings: Option<Json>,
    pub preferences: Option<Json>,
    #[serde(rename = "joinedAt")]
    pub joined_at: Option<DateTimeUtc>,
    pub level: Option<String>,
    #[serde(rename = "storedLabel")]
    pub stored_label: Option<String>,
    pub alias: Option<String>,
    #[serde(rename = "optionalAlias")]
    pub optional_alias: Option<String>,
    #[serde(rename = "internalCode")]
    pub internal_code: Option<String>,
    #[serde(rename = "secretNote")]
    pub secret_note: Option<String>,
    pub score: Option<f64>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub struct Schema;
impl better_auth::AuthSchema for Schema {
    type User = Model;
    type Session = session::Model;
    type Account = better_auth_seaorm::store::entities::account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}

pub fn configure(config: &mut better_auth::AuthConfig) {
    use better_auth::config::{CookieCacheConfig, UserFieldConfig, UserFieldType};
    use std::sync::Arc;
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        ..Default::default()
    });
    config.user.additional_fields = Some(
        [
            (
                "changedMarker".into(),
                UserFieldConfig {
                    required: Some(false),
                    default_value: Some("created".into()),
                    on_update: Some(Arc::new(|| "updated".into())),
                    ..Default::default()
                },
            ),
            (
                "department".into(),
                UserFieldConfig {
                    required: Some(true),
                    ..Default::default()
                },
            ),
            (
                "alias".into(),
                UserFieldConfig {
                    default_value: Some("guest".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(|value| suffix(value, "in"))),
                        output: Some(UserFieldTransform::new(|value| suffix(value, "out"))),
                    }),
                    ..Default::default()
                },
            ),
            (
                "optionalAlias".into(),
                UserFieldConfig {
                    required: Some(false),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(|value| suffix(value, "in"))),
                        output: Some(UserFieldTransform::new(|value| suffix(value, "out"))),
                    }),
                    ..Default::default()
                },
            ),
            (
                "internalCode".into(),
                UserFieldConfig {
                    input: Some(false),
                    default_value: Some("server".into()),
                    ..Default::default()
                },
            ),
            (
                "secretNote".into(),
                UserFieldConfig {
                    returned: Some(false),
                    default_value: Some("hidden".into()),
                    ..Default::default()
                },
            ),
            (
                "score".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    default_value: Some(1.into()),
                    validator: Some(Arc::new(|value| {
                        if value.as_f64().is_some_and(|score| score >= 0.0) {
                            Ok(value)
                        } else {
                            Err(better_auth::AuthError::FieldInput {
                                code: "VALIDATION_ERROR",
                                message: "score must be nonnegative".into(),
                            })
                        }
                    })),
                    ..Default::default()
                },
            ),
        ]
        .into(),
    );
    for (name, field_type, default_value) in [
        ("enabled", UserFieldType::Boolean, FieldValue::from(true)),
        (
            "tags",
            UserFieldType::StringArray,
            vec!["starter".into()].into(),
        ),
        (
            "ratings",
            UserFieldType::NumberArray,
            vec![1.into(), 2.into()].into(),
        ),
        (
            "preferences",
            UserFieldType::Json,
            FieldMap::from([("theme".into(), "system".into())]).into(),
        ),
        (
            "level",
            UserFieldType::Enum(vec!["basic".into(), "pro".into()]),
            "basic".into(),
        ),
    ] {
        config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                required: Some(false),
                default_value: Some(default_value),
                ..Default::default()
            },
        );
    }
    config.user.fields_mut().insert(
        "cohort".into(),
        UserFieldConfig {
            required: Some(false),
            default_value_fn: Some(Arc::new(|| "factory".into())),
            ..Default::default()
        },
    );
    config.user.fields_mut().insert(
        "joinedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            required: Some(false),
            default_value_fn: Some(Arc::new(|| "2020-01-02T03:04:05.000Z".into())),
            ..Default::default()
        },
    );
    config.user.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("storedLabel".into()),
            default_value: Some("public-label".into()),
            ..Default::default()
        },
    );
}

pub async fn add_columns(
    database: &better_auth_seaorm::DatabaseConnection,
) -> Result<(), better_auth_seaorm::sea_orm::DbErr> {
    use better_auth_seaorm::sea_orm::ConnectionTrait;
    for column in [
        "department TEXT",
        "cohort TEXT",
        "changed_marker TEXT",
        "enabled BOOLEAN",
        "tags TEXT",
        "ratings TEXT",
        "preferences TEXT",
        "joined_at TEXT",
        "level TEXT",
        "stored_label TEXT",
        "alias TEXT",
        "optional_alias TEXT",
        "internal_code TEXT",
        "secret_note TEXT",
        "score REAL",
    ] {
        database
            .execute_unprepared(&format!("ALTER TABLE users ADD COLUMN {column}"))
            .await?;
    }
    database
        .execute_unprepared("ALTER TABLE sessions ADD COLUMN device_label TEXT")
        .await?;
    database
        .execute_unprepared("ALTER TABLE sessions ADD COLUMN internal_note TEXT")
        .await?;
    database
        .execute_unprepared("ALTER TABLE sessions ADD COLUMN validated_label TEXT")
        .await?;
    database
        .execute_unprepared("ALTER TABLE sessions ADD COLUMN settings TEXT")
        .await?;
    Ok(())
}

fn suffix(value: FieldValue, suffix: &str) -> better_auth::AuthResult<FieldValue> {
    let text = match value {
        FieldValue::String(value) => value,
        value => value.stringify()?.unwrap_or_else(|| "undefined".into()),
    };
    Ok(format!("{text}:{suffix}").into())
}

pub async fn disabled_router(
    mut config: better_auth::AuthConfig,
    database: better_auth_seaorm::DatabaseConnection,
) -> better_auth::AuthResult<axum::Router> {
    use better_auth::integrations::axum::AxumIntegration;
    use std::sync::Arc;
    let auth = Arc::new(
        better_auth::AuthBuilder::<Schema>::new(config.clone())
            .store(better_auth_seaorm::SeaOrmStore::<Schema>::new(
                config.clone(),
                database.clone(),
            ))
            .plugin(better_auth::plugins::SessionManagementPlugin::new())
            .build()
            .await?,
    );
    let disabled = axum::Router::new()
        .nest("/__test/disabled", auth.clone().axum_router())
        .with_state(auth);
    config
        .user
        .fields_mut()
        .get_mut("department")
        .unwrap()
        .returned = Some(false);
    config.user.fields_mut().get_mut("alias").unwrap().returned = Some(false);
    let hidden = Arc::new(
        better_auth::AuthBuilder::<Schema>::new(config.clone())
            .store(better_auth_seaorm::SeaOrmStore::<Schema>::new(
                config, database,
            ))
            .plugin(better_auth::plugins::SessionManagementPlugin::new())
            .build()
            .await?,
    );
    Ok(disabled.merge(
        axum::Router::new()
            .nest("/__test/hidden", hidden.clone().axum_router())
            .with_state(hidden),
    ))
}
