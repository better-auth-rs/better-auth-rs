use better_auth::seaorm::{
    OrganizationModels, PluginModels,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
};
use better_auth::{AuthConfig, seaorm::SeaOrmStore};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{api_key, device_code, jwk, passkey, two_factor},
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
    #[auth(role = "wallet_address")]
    #[sea_orm(table_name = "ordinary_wallet_fields")]
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
        pub address: String,
        pub chain_id: i64,
        pub is_primary: bool,
        pub created_at: DateTimeUtc,
        #[serde(rename = "stored_label")]
        #[sea_orm(column_name = "stored_label")]
        pub label: Option<String>,
        pub note: Option<String>,
        #[serde(rename = "stored_settings")]
        #[sea_orm(column_name = "stored_settings")]
        pub settings: Option<Json>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) type Plugins = PluginModels<
    api_key::Model,
    device_code::Model,
    passkey::Model,
    two_factor::Model,
    jwk::Model,
    model::Model,
>;

#[expect(
    clippy::expect_used,
    reason = "Fixture setup must fail immediately if the isolated database cannot be created"
)]
pub(crate) async fn sqlite(
    config: AuthConfig,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins>,
    DatabaseConnection,
) {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("ordinary Wallet fixture database connects");
    migrator::run_migrations(&database)
        .await
        .expect("ordinary Wallet fixture core tables migrate");
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(model::Entity);
    let _ = database
        .execute_raw(backend.build(&statement))
        .await
        .expect("ordinary Wallet fixture table is created");
    (
        SeaOrmStore::<BundledSchema>::new(config, database.clone()).with_plugin_schema::<Plugins>(),
        database,
    )
}
