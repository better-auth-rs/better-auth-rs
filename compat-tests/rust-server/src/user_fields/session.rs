use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
use serde::Serialize;

#[derive(better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "session")]
#[sea_orm(table_name = "sessions")]
#[serde(rename_all = "camelCase")]
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
    pub active_team_id: Option<String>,
    pub active: bool,
    pub device_label: Option<String>,
    pub internal_note: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
