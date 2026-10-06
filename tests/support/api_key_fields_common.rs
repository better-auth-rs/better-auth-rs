use better_auth::seaorm::{
    OrganizationModels, PluginModels, SeaOrmPluginModel,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
};
use better_auth::{AuthConfig, seaorm::SeaOrmStore};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{device_code, passkey, two_factor},
};

macro_rules! api_key_model {
    ($module:ident, $name:literal) => {
        #[expect(
            unreachable_pub,
            reason = "SeaORM entity derives require public fixture types"
        )]
        pub mod $module {
            use better_auth::seaorm::{
                AuthEntity,
                sea_orm::{self, entity::prelude::*},
            };

            #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = "api_key")]
            #[sea_orm(table_name = "ordinary_api_key_fields")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[serde(rename = "stored_enabled_flag")]
                #[sea_orm(column_name = "stored_enabled_flag")]
                pub enabled_flag: Option<bool>,
                #[serde(rename = "stored_disabled_flag")]
                #[sea_orm(column_name = "stored_disabled_flag")]
                pub disabled_flag: Option<bool>,
                #[serde(rename = "stored_labels")]
                #[sea_orm(column_name = "stored_labels")]
                pub labels: Option<Json>,
                #[serde(rename = "stored_scores")]
                #[sea_orm(column_name = "stored_scores")]
                pub scores: Option<Json>,
                #[serde(rename = "stored_short_date")]
                #[sea_orm(column_name = "stored_short_date")]
                pub short_date: Option<DateTimeUtc>,
                #[serde(rename = "stored_invalid_date")]
                #[sea_orm(column_name = "stored_invalid_date")]
                pub invalid_date: Option<DateTimeUtc>,
                #[sea_orm(column_name = $name)]
                pub name: Option<String>,
                pub start: Option<String>,
                pub prefix: Option<String>,
                #[serde(rename = "stored_key")]
                #[sea_orm(column_name = "stored_key")]
                pub key_hash: String,
                #[serde(rename = "stored_owner")]
                #[sea_orm(column_name = "stored_owner")]
                pub reference_id: String,
                pub config_id: String,
                pub refill_interval: Option<f64>,
                pub refill_amount: Option<f64>,
                pub last_refill_at: Option<DateTimeUtc>,
                pub enabled: bool,
                pub rate_limit_enabled: bool,
                pub rate_limit_time_window: Option<f64>,
                pub rate_limit_max: Option<f64>,
                #[serde(rename = "stored_count")]
                #[sea_orm(column_name = "stored_count")]
                pub request_count: Option<f64>,
                pub remaining: Option<f64>,
                pub last_request: Option<DateTimeUtc>,
                pub expires_at: Option<DateTimeUtc>,
                pub created_at: DateTimeUtc,
                pub updated_at: DateTimeUtc,
                pub permissions: Option<String>,
                pub metadata: Option<String>,
                #[serde(rename = "stored_label")]
                #[sea_orm(column_name = "stored_label")]
                pub label: Option<String>,
                #[serde(rename = "stored_activation")]
                #[sea_orm(column_name = "stored_activation")]
                pub activated_at: Option<DateTimeUtc>,
                #[serde(rename = "stored_details")]
                #[sea_orm(column_name = "stored_details")]
                pub details: Option<better_auth::seaorm::SqlText>,
                #[serde(rename = "stored_revision")]
                #[sea_orm(column_name = "stored_revision")]
                pub revision: Option<better_auth::seaorm::SqlNumber>,
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

pub(crate) use api_key_model;

self::api_key_model!(model, "name");

pub(crate) type Plugins<M = model::Model> =
    PluginModels<M, device_code::Model, passkey::Model, two_factor::Model>;

pub(crate) async fn sqlite(
    config: AuthConfig,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins>,
    DatabaseConnection,
) {
    sqlite_for::<model::Model>(config).await
}

#[expect(
    clippy::expect_used,
    reason = "Fixture setup must create the isolated database and required tables"
)]
pub(crate) async fn sqlite_for<M: SeaOrmPluginModel<Record = better_auth_core::ApiKey>>(
    config: AuthConfig,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins<M>>,
    DatabaseConnection,
) {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("API Key fixture database connects");
    migrator::run_migrations(&database)
        .await
        .expect("API Key fixture core tables migrate");
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(M::Entity::default());
    let _ = database
        .execute_raw(backend.build(&statement))
        .await
        .expect("API Key fixture table is created");
    (
        SeaOrmStore::<BundledSchema>::new(config, database.clone())
            .with_plugin_schema::<Plugins<M>>(),
        database,
    )
}
