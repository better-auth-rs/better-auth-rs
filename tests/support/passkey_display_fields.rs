use better_auth::{
    AuthConfig,
    seaorm::{
        OrganizationModels, PluginModels, SeaOrmPluginModel, SeaOrmStore,
        sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
    },
};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{api_key, device_code, two_factor},
};

macro_rules! passkey_model {
    ($module:ident, $name:literal, $aaguid:literal $(, $extra:ident)?) => {
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
            #[auth(role = "passkey", native_passkey)]
            #[sea_orm(table_name = "ordinary_mapped_passkey")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[serde(rename = $name)]
                #[sea_orm(column_name = $name)]
                pub name: Option<String>,
                #[sea_orm(column_name = "publicKey")]
                pub public_key: String,
                #[sea_orm(column_name = "userId")]
                pub user_id: String,
                #[sea_orm(column_name = "credentialID")]
                pub credential_id: String,
                pub counter: i64,
                #[sea_orm(column_name = "deviceType")]
                pub device_type: String,
                #[sea_orm(column_name = "backedUp")]
                pub backed_up: bool,
                pub transports: Option<String>,
                #[sea_orm(column_name = "createdAt")]
                pub created_at: Option<DateTimeUtc>,
                #[serde(rename = $aaguid)]
                #[sea_orm(column_name = $aaguid)]
                pub aaguid: Option<String>,
                $(pub $extra: Option<String>,)?
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

passkey_model!(default, "name", "aaguid");
passkey_model!(renamed, "stored_name", "stored_aaguid");
passkey_model!(
    renamed_independent,
    "stored_name",
    "stored_aaguid",
    independent_label
);

pub(crate) type Plugins<M> = PluginModels<api_key::Model, device_code::Model, M, two_factor::Model>;

#[expect(
    clippy::expect_used,
    reason = "Fixture setup must create the isolated database and required tables"
)]
pub(crate) async fn sqlite<M: SeaOrmPluginModel<Record = better_auth_core::Passkey>>(
    config: AuthConfig,
) -> (
    SeaOrmStore<BundledSchema, OrganizationModels, Plugins<M>>,
    DatabaseConnection,
) {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("mapped Passkey database connects");
    migrator::run_migrations(&database)
        .await
        .expect("mapped Passkey core tables migrate");
    let backend = database.get_database_backend();
    let statement = Schema::new(backend).create_table_from_entity(M::Entity::default());
    let _ = database
        .execute_raw(backend.build(&statement))
        .await
        .expect("mapped Passkey table is created");
    (
        SeaOrmStore::<BundledSchema>::new(config, database.clone())
            .with_plugin_schema::<Plugins<M>>(),
        database,
    )
}
