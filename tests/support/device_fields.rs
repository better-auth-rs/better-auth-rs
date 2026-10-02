use better_auth::seaorm::{
    OrganizationModels, PluginModels,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
};
use better_auth::{AuthConfig, seaorm::SeaOrmStore};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::api_key,
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
    #[auth(role = "device_code")]
    #[sea_orm(table_name = "ordinary_device_fields")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub device_code: String,
        pub user_code: String,
        pub user_id: Option<String>,
        pub expires_at: DateTimeUtc,
        pub status: String,
        pub last_polled_at: Option<DateTimeUtc>,
        #[sea_orm(column_type = "Integer", nullable)]
        pub polling_interval: Option<better_auth::seaorm::SqlNumber>,
        #[serde(rename = "stored_client_id")]
        #[sea_orm(column_name = "stored_client_id")]
        pub client_id: Option<String>,
        pub scope: Option<String>,
        #[serde(rename = "stored_label")]
        #[sea_orm(column_name = "stored_label")]
        pub label: Option<String>,
        #[serde(rename = "stored_activation")]
        #[sea_orm(column_name = "stored_activation")]
        pub activated_at: Option<DateTimeUtc>,
        #[serde(rename = "stored_details")]
        #[sea_orm(column_name = "stored_details")]
        pub details: Option<Json>,
        #[serde(rename = "stored_revision")]
        #[sea_orm(column_name = "stored_revision")]
        pub revision: Option<better_auth::seaorm::SqlNumber>,
        pub unconfigured: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) type Plugins = PluginModels<api_key::Model, model::Model>;

#[expect(
    clippy::expect_used,
    reason = "The SQLite fixture must connect before the contract can run"
)]
pub(crate) async fn sqlite(
    config: AuthConfig,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins>,
    DatabaseConnection,
) {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("ordinary Device fixture database connects");
    setup(config, database).await
}

#[expect(
    clippy::expect_used,
    reason = "The fixture must create its required core and Device tables before the contract can run"
)]
pub(crate) async fn setup(
    config: AuthConfig,
    database: DatabaseConnection,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins>,
    DatabaseConnection,
) {
    migrator::run_migrations(&database)
        .await
        .expect("ordinary Device fixture core tables migrate");
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(model::Entity);
    let _ = database
        .execute_raw(backend.build(&statement))
        .await
        .expect("ordinary Device fixture table is created");
    (
        SeaOrmStore::<BundledSchema>::new(config, database.clone()).with_plugin_schema::<Plugins>(),
        database,
    )
}
