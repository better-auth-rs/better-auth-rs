use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "organization")]
#[sea_orm(table_name = "organization")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<String>,
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updated_at")]
    pub auth_updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
