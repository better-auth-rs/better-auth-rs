use better_auth_core::AuthMember;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, AuthMember)]
#[sea_orm(table_name = "member")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "organizationId")]
    #[auth(column = "organizationId")]
    pub organization_id: String,
    #[sea_orm(column_name = "userId")]
    #[auth(column = "userId")]
    pub user_id: String,
    pub role: String,
    #[sea_orm(column_name = "createdAt")]
    #[auth(column = "createdAt")]
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
