use super::*;

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
pub(super) mod user {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "user")]
    #[sea_orm(table_name = "member_join_user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub stored_member_ref: Option<String>,
        pub lookup: Option<String>,
        pub stored_lookup: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
pub(super) mod member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "member")]
    #[sea_orm(table_name = "member_join_member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub user_id: String,
        pub role: String,
        pub created_at: DateTimeUtc,
        pub label: Option<String>,
        pub detail: Option<String>,
        pub stored_owner_ref: Option<String>,
        pub lookup: Option<String>,
        pub stored_lookup: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) struct Core;
impl AuthSchema for Core {
    type User = user::Model;
    type Session = entities::session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

pub(super) type Organizations =
    better_auth_seaorm::OrganizationModels<entities::organization::Model, member::Model>;
