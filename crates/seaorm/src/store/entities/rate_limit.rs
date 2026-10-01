use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "rate_limit")]
#[sea_orm(table_name = "rate_limit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub key: String,
    #[sea_orm(column_type = "Integer")]
    pub count: crate::SqlNumber,
    pub last_request: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
