use better_auth::seaorm::{
    OrganizationModels, PluginModels,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
};
use better_auth::{AuthConfig, seaorm::SeaOrmStore};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{api_key, device_code, two_factor},
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
    #[auth(role = "passkey", native_passkey)]
    #[sea_orm(table_name = "ordinary_passkey_fields")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub public_key: String,
        #[serde(rename = "stored_owner")]
        #[sea_orm(column_name = "stored_owner")]
        pub user_id: String,
        pub credential_id: String,
        #[serde(rename = "stored_counter")]
        #[sea_orm(column_name = "stored_counter")]
        pub counter: i64,
        pub device_type: String,
        pub backed_up: bool,
        pub transports: Option<String>,
        pub created_at: Option<DateTimeUtc>,
        pub aaguid: Option<String>,
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
    PluginModels<api_key::Model, device_code::Model, model::Model, two_factor::Model>;

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
        .expect("Passkey fixture database connects");
    migrator::run_migrations(&database)
        .await
        .expect("Passkey fixture core tables migrate");
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(model::Entity);
    let _ = database
        .execute_raw(backend.build(&statement))
        .await
        .expect("Passkey fixture table is created");
    (
        SeaOrmStore::<BundledSchema>::new(config, database.clone()).with_plugin_schema::<Plugins>(),
        database,
    )
}
