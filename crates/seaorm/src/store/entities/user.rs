use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(crate::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "user")]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    #[sea_orm(default_value = false)]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    #[sea_orm(default_value = false)]
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTimeUtc>,
    #[sea_orm(default_expr = "Expr::cust(\"('{}')\")")]
    pub metadata: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
