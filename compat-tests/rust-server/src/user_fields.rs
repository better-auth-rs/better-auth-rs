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
    use serde_json::json;
    use std::sync::Arc;
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: true,
        ..Default::default()
    });
    config.user.additional_fields = [
        (
            "changedMarker".into(),
            UserFieldConfig {
                required: Some(false),
                default_value: Some(json!("created")),
                on_update: Some(Arc::new(|| json!("updated"))),
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
                default_value: Some(json!("guest")),
                input_transform: Some(Arc::new(|value| suffix(value, "in"))),
                output_transform: Some(Arc::new(|value| suffix(value, "out"))),
                ..Default::default()
            },
        ),
        (
            "optionalAlias".into(),
            UserFieldConfig {
                required: Some(false),
                input_transform: Some(Arc::new(|value| suffix(value, "in"))),
                output_transform: Some(Arc::new(|value| suffix(value, "out"))),
                ..Default::default()
            },
        ),
        (
            "internalCode".into(),
            UserFieldConfig {
                input: false,
                default_value: Some(json!("server")),
                ..Default::default()
            },
        ),
        (
            "secretNote".into(),
            UserFieldConfig {
                returned: false,
                default_value: Some(json!("hidden")),
                ..Default::default()
            },
        ),
        (
            "score".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                default_value: Some(json!(1)),
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
    .into();
    for (name, field_type, default_value) in [
        ("enabled", UserFieldType::Boolean, json!(true)),
        ("tags", UserFieldType::StringArray, json!(["starter"])),
        ("ratings", UserFieldType::NumberArray, json!([1, 2])),
        (
            "preferences",
            UserFieldType::Json,
            json!({ "theme": "system" }),
        ),
        (
            "level",
            UserFieldType::Enum(vec!["basic".into(), "pro".into()]),
            json!("basic"),
        ),
    ] {
        config.user.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                field_type,
                required: Some(false),
                default_value: Some(default_value),
                ..Default::default()
            },
        );
    }
    config.user.additional_fields.insert(
        "cohort".into(),
        UserFieldConfig {
            required: Some(false),
            default_value_fn: Some(Arc::new(|| json!("factory"))),
            ..Default::default()
        },
    );
    config.user.additional_fields.insert(
        "joinedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            required: Some(false),
            default_value_fn: Some(Arc::new(|| json!("2020-01-02T03:04:05.000Z"))),
            ..Default::default()
        },
    );
    config.user.additional_fields.insert(
        "label".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("storedLabel".into()),
            default_value: Some(json!("public-label")),
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
    Ok(())
}

fn suffix(
    value: Option<serde_json::Value>,
    suffix: &str,
) -> better_auth::AuthResult<Option<serde_json::Value>> {
    let text = match value {
        None => "undefined".to_owned(),
        Some(serde_json::Value::String(value)) => value,
        Some(value) => value.to_string(),
    };
    Ok(Some(serde_json::json!(format!("{text}:{suffix}"))))
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
        .additional_fields
        .get_mut("department")
        .unwrap()
        .returned = false;
    config
        .user
        .additional_fields
        .get_mut("alias")
        .unwrap()
        .returned = false;
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
