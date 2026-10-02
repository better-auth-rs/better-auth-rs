use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
use serde::Serialize;

#[derive(better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "account")]
#[sea_orm(table_name = "native_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_name = "row_id")]
    pub id: String,
    pub account_id: String,
    pub provider_id: String,
    #[sea_orm(column_name = "owner_ref")]
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
    #[sea_orm(column_name = "label_value")]
    #[serde(rename = "label_value")]
    pub display_label: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
