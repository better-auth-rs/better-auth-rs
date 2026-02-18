use better_auth_core::AuthVerification;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, AuthVerification)]
#[sea_orm(table_name = "verification")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[sea_orm(column_name = "expiresAt")]
    #[auth(column = "expiresAt")]
    pub expires_at: DateTimeUtc,
    #[sea_orm(column_name = "createdAt")]
    #[auth(column = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    #[auth(column = "updatedAt")]
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
