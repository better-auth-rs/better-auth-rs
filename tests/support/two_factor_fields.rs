use better_auth::seaorm::{
    OrganizationModels, PluginModels,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
};
use better_auth::{AuthConfig, seaorm::SeaOrmStore};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{api_key, device_code, passkey},
};

#[expect(
    unreachable_pub,
    reason = "SeaORM entity derives require public fixture types"
)]
pub mod model {
    use better_auth::seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "two_factor", native_two_factor)]
    #[sea_orm(table_name = "ordinary_two_factor_fields")]
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
        pub user_id: String,
        #[serde(rename = "stored_secret")]
        #[sea_orm(column_name = "stored_secret")]
        pub secret: String,
        pub backup_codes: String,
        pub verified: Option<bool>,
        pub failed_verification_count: Option<i64>,
        pub locked_until: Option<DateTimeUtc>,
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

pub(crate) type Plugins =
    PluginModels<api_key::Model, device_code::Model, passkey::Model, model::Model>;

#[expect(
    clippy::expect_used,
    reason = "Fixture setup must fail if the isolated database or required tables cannot be created"
)]
pub(crate) async fn sqlite(
    config: AuthConfig,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins>,
    DatabaseConnection,
) {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("TwoFactor fixture database connects");
    migrator::run_migrations(&database)
        .await
        .expect("TwoFactor fixture core tables migrate");
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(model::Entity);
    let _ = database
        .execute_raw(backend.build(&statement))
        .await
        .expect("TwoFactor fixture table is created");
    (
        SeaOrmStore::<BundledSchema>::new(config, database.clone()).with_plugin_schema::<Plugins>(),
        database,
    )
}
