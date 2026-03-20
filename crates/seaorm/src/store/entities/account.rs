use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(crate::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "account")]
#[sea_orm(table_name = "accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub account_id: String,
    pub provider_id: String,
    pub user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTimeUtc>,
    pub refresh_token_expires_at: Option<DateTimeUtc>,
    pub scope: Option<String>,
    pub password: Option<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
