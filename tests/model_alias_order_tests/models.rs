use better_auth_seaorm::{OrganizationModels, store::entities};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
pub(super) mod team {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team")]
    #[sea_orm(table_name = "shared")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "memberCount")]
        pub member_count: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
pub(super) mod team_member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team_member")]
    #[sea_orm(table_name = "teamMember")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "teamId")]
        pub team_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "membershipKey")]
        pub membership_key: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) type Organization = OrganizationModels<
    entities::organization::Model,
    entities::member::Model,
    entities::invitation::Model,
    team::Model,
    team_member::Model,
>;
