use better_auth_core::AuthUser;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthUser)]
#[sea_orm(table_name = "user")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[auth(field = "name")]
    pub name: Option<String>,
    pub email: Option<String>,
    #[sea_orm(column_name = "emailVerified")]
    #[auth(default = "false", column = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    #[sea_orm(column_name = "displayUsername")]
    #[auth(column = "displayUsername")]
    pub display_username: Option<String>,
    #[sea_orm(column_name = "twoFactorEnabled")]
    #[auth(default = "false", column = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    #[auth(default = "false")]
    pub banned: bool,
    #[sea_orm(column_name = "banReason")]
    #[auth(column = "banReason")]
    pub ban_reason: Option<String>,
    #[sea_orm(column_name = "banExpires")]
    #[auth(column = "banExpires")]
    pub ban_expires: Option<DateTimeUtc>,
    pub metadata: Json,
    #[sea_orm(column_name = "createdAt")]
    #[auth(column = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    #[auth(column = "updatedAt")]
    pub updated_at: DateTimeUtc,
    // --- Application-specific columns ---
    #[auth(default = "\"free\".to_string()")]
    pub plan: String,
    pub stripe_customer_id: Option<String>,
    pub phone: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
