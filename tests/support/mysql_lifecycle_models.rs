use better_auth_core::AuthSchema;
use better_auth_seaorm::store::entities;

pub(super) struct Schema;

impl AuthSchema for Schema {
    type User = user::Model;
    type Session = session::Model;
    type Account = entities::account::Model;
    type Verification = verification::Model;
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture model types"
)]
mod user {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[serde(rename_all = "camelCase")]
    #[auth(role = "user")]
    #[sea_orm(table_name = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture model types"
)]
mod session {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[serde(rename_all = "camelCase")]
    #[auth(role = "session", row_presence)]
    #[sea_orm(table_name = "session")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        pub token: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "ipAddress")]
        pub ip_address: Option<String>,
        #[sea_orm(column_name = "userAgent")]
        pub user_agent: Option<String>,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture model types"
)]
mod verification {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[serde(rename_all = "camelCase")]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "verification")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        pub value: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
