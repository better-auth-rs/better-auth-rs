use better_auth::{
    AuthConfig, AuthSchema,
    seaorm::{OrganizationModels, PluginModels, SeaOrmStore, sea_orm::*},
};
use better_auth_seaorm::store::{
    __private_test_support::{bundled_schema::BundledSchema, migrator},
    entities::{account, api_key, session, verification},
};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture types"
)]
pub mod model {
    use better_auth::seaorm::{
        AuthEntity, ReferenceId, SqlNumber,
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
        #[sea_orm(
            column_name = "stored_ownerRef",
            column_type = "String(sea_orm::sea_query::StringLen::None)",
            nullable
        )]
        #[serde(rename = "stored_ownerRef")]
        pub owner_ref: Option<ReferenceId>,
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

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture types"
)]
pub mod serial_user {
    use better_auth::seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "device_where_serial_users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture types"
)]
pub mod serial_device {
    use better_auth::seaorm::{
        AuthEntity, SqlNumber,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "device_code")]
    #[sea_orm(table_name = "device_where_serial_contract")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub device_code: String,
        pub user_code: String,
        #[auth(reference = false)]
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
        #[auth(reference)]
        #[sea_orm(column_name = "stored_ownerRef")]
        #[serde(rename = "stored_ownerRef")]
        pub owner_ref: Option<i32>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::serial_user::Entity",
            from = "Column::OwnerRef",
            to = "super::serial_user::Column::Id"
        )]
        Owner,
    }
    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) struct SerialSchema;

impl AuthSchema for SerialSchema {
    type User = serial_user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}

pub(crate) type SerialStore = SeaOrmStore<
    SerialSchema,
    OrganizationModels,
    PluginModels<api_key::Model, serial_device::Model>,
>;

pub(crate) async fn setup_serial(
    config: AuthConfig,
    database: DatabaseConnection,
) -> Result<SerialStore, DbErr> {
    let backend = database.get_database_backend();
    let schema = Schema::new(backend);
    let user = schema.create_table_from_entity(serial_user::Entity);
    let _ = database.execute_raw(backend.build(&user)).await?;
    let device = schema.create_table_from_entity(serial_device::Entity);
    let _ = database.execute_raw(backend.build(&device)).await?;
    Ok(SeaOrmStore::<SerialSchema>::new(config, database).with_plugin_schema())
}

pub(crate) async fn drop_serial(database: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = database.get_database_backend();
    for table in [
        serial_device::Entity.table_ref(),
        serial_user::Entity.table_ref(),
    ] {
        let statement = sea_query::Table::drop().table(table).to_owned();
        let _ = database.execute_raw(backend.build(&statement)).await?;
    }
    Ok(())
}
