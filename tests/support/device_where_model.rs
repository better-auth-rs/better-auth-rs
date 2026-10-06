use better_auth::{
    AuthConfig,
    seaorm::{OrganizationModels, PluginModels, SeaOrmStore, sea_orm::*},
};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::api_key,
};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture types"
)]
pub mod model {
    use better_auth::seaorm::{
        AuthEntity, SqlNumber,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "device_code")]
    #[sea_orm(table_name = "device_where_contract")]
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
        pub polling_interval: Option<SqlNumber>,
        pub client_id: Option<String>,
        pub scope: Option<String>,
        #[sea_orm(column_name = "stored_label")]
        #[serde(rename = "stored_label")]
        pub label: Option<String>,
        #[sea_orm(column_name = "stored_quantity", column_type = "Integer", nullable)]
        #[serde(rename = "stored_quantity")]
        pub quantity: Option<SqlNumber>,
        #[sea_orm(column_name = "stored_flag")]
        #[serde(rename = "stored_flag")]
        pub flag: Option<bool>,
        #[sea_orm(column_name = "stored_moment")]
        #[serde(rename = "stored_moment")]
        pub moment: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_labels", column_type = "JsonBinary", nullable)]
        #[serde(rename = "stored_labels")]
        pub labels: Option<Json>,
        #[sea_orm(column_name = "stored_payload", column_type = "JsonBinary", nullable)]
        #[serde(rename = "stored_payload")]
        pub payload: Option<Json>,
        #[sea_orm(column_name = "stored_ownerRef")]
        #[serde(rename = "stored_ownerRef")]
        pub owner_ref: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) type Store =
    SeaOrmStore<BundledSchema, OrganizationModels, PluginModels<api_key::Model, model::Model>>;

pub(crate) async fn setup(
    config: AuthConfig,
    database: DatabaseConnection,
) -> Result<Store, DbErr> {
    migrator::run_migrations(&database).await?;
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(model::Entity);
    let _ = database.execute_raw(backend.build(&statement)).await?;
    Ok(SeaOrmStore::<BundledSchema>::new(config, database).with_plugin_schema())
}
