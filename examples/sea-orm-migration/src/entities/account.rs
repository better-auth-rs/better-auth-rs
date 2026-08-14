use better_auth_core::AuthAccount;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthAccount)]
#[sea_orm(table_name = "accounts")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(indexed)]
    pub account_id: String,
    #[sea_orm(indexed)]
    pub provider_id: String,
    #[sea_orm(indexed)]
    pub user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTimeUtc>,
    pub refresh_token_expires_at: Option<DateTimeUtc>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[sea_orm(indexed)]
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,

    // Relations
    #[sea_orm(belongs_to, from = "user_id", to = "id")]
    pub user: HasOne<super::user::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
