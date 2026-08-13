use better_auth_core::AuthUser;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthUser)]
#[sea_orm(table_name = "users")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[auth(field = "name")]
    pub name: Option<String>,
    #[sea_orm(unique, indexed)]
    pub email: Option<String>,
    #[auth(default = "false")]
    pub email_verified: bool,
    pub image: Option<String>,
    #[sea_orm(unique, indexed)]
    pub username: Option<String>,
    pub display_username: Option<String>,
    #[auth(default = "false")]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    #[auth(default = "false")]
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTimeUtc>,
    pub metadata: Json,
    #[sea_orm(indexed)]
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    // --- Application-specific columns ---
    #[auth(default = "\"free\".to_string()")]
    pub plan: String,
    pub stripe_customer_id: Option<String>,
    pub phone: Option<String>,

    // Relations
    #[sea_orm(has_many)]
    pub accounts: HasMany<super::account::Entity>,
    #[sea_orm(has_many)]
    pub sessions: HasMany<super::session::Entity>,
    #[sea_orm(has_many)]
    pub members: HasMany<super::member::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
