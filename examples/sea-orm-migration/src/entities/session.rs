use better_auth_core::AuthSession;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, AuthSession)]
#[sea_orm(table_name = "session")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "expiresAt")]
    #[auth(column = "expiresAt")]
    pub expires_at: DateTimeUtc,
    pub token: String,
    #[sea_orm(column_name = "createdAt")]
    #[auth(column = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    #[auth(column = "updatedAt")]
    pub updated_at: DateTimeUtc,
    #[sea_orm(column_name = "ipAddress")]
    #[auth(column = "ipAddress")]
    pub ip_address: Option<String>,
    #[sea_orm(column_name = "userAgent")]
    #[auth(column = "userAgent")]
    pub user_agent: Option<String>,
    #[sea_orm(column_name = "userId")]
    #[auth(column = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "impersonatedBy")]
    #[auth(column = "impersonatedBy")]
    pub impersonated_by: Option<String>,
    #[sea_orm(column_name = "activeOrganizationId")]
    #[auth(column = "activeOrganizationId")]
    pub active_organization_id: Option<String>,
    #[auth(default = "true")]
    pub active: bool,
    // --- Application-specific columns ---
    pub device_id: Option<String>,
    pub country: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
