use better_auth_core::AuthSession;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthSession)]
#[sea_orm(table_name = "sessions")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(indexed)]
    pub expires_at: DateTimeUtc,
    #[sea_orm(unique, indexed)]
    pub token: String,
    #[sea_orm(indexed)]
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[sea_orm(indexed)]
    pub user_id: String,
    pub impersonated_by: Option<String>,
    #[sea_orm(indexed)]
    pub active_organization_id: Option<String>,
    #[auth(default = "true")]
    #[sea_orm(indexed)]
    pub active: bool,
    // --- Application-specific columns ---
    pub device_id: Option<String>,
    pub country: Option<String>,

    // Relations
    #[sea_orm(belongs_to, from = "user_id", to = "id")]
    pub user: HasOne<super::user::Entity>,
    #[sea_orm(belongs_to, from = "active_organization_id", to = "id")]
    pub organization: HasOne<super::organization::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
