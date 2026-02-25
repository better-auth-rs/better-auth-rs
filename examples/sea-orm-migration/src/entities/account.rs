use better_auth_core::AuthAccount;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, AuthAccount)]
#[sea_orm(table_name = "account")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "accountId")]
    #[auth(column = "accountId")]
    pub account_id: String,
    #[sea_orm(column_name = "providerId")]
    #[auth(column = "providerId")]
    pub provider_id: String,
    #[sea_orm(column_name = "userId")]
    #[auth(column = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "accessToken")]
    #[auth(column = "accessToken")]
    pub access_token: Option<String>,
    #[sea_orm(column_name = "refreshToken")]
    #[auth(column = "refreshToken")]
    pub refresh_token: Option<String>,
    #[sea_orm(column_name = "idToken")]
    #[auth(column = "idToken")]
    pub id_token: Option<String>,
    #[sea_orm(column_name = "accessTokenExpiresAt")]
    #[auth(column = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "refreshTokenExpiresAt")]
    #[auth(column = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<DateTimeUtc>,
    pub scope: Option<String>,
    pub password: Option<String>,
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
