use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub expires_at: DateTimeUtc,
    pub token: String,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
