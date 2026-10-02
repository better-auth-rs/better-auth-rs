use better_auth::AuthConfig;
use better_auth::seaorm::{
    OrganizationModels, PluginModels, SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbErr, Schema},
};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{api_key, device_code, passkey, two_factor},
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
    #[auth(role = "jwk")]
    #[sea_orm(table_name = "ordinary_json_text")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub public_key: String,
        pub private_key: String,
        pub created_at: DateTimeUtc,
        pub expires_at: Option<DateTimeUtc>,
        pub alg: Option<String>,
        pub crv: Option<String>,
        #[serde(rename = "stored_settings")]
        #[sea_orm(column_name = "stored_settings", column_type = "Text", nullable)]
        pub settings: Option<String>,
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
    model::Model,
>;

pub(crate) async fn sqlite(
    config: AuthConfig,
) -> Result<
    (
        SeaOrmStore<BundledSchema, OrganizationModels, Plugins>,
        DatabaseConnection,
    ),
    DbErr,
> {
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(model::Entity);
    let _ = database.execute_raw(backend.build(&statement)).await?;
    Ok((
        SeaOrmStore::<BundledSchema>::new(config, database.clone()).with_plugin_schema::<Plugins>(),
        database,
    ))
}
