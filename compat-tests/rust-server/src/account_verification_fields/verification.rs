use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
use serde::Serialize;

#[derive(better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "verification")]
#[sea_orm(table_name = "verifications")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub stored_label: Option<String>,
    pub hidden: Option<String>,
    pub protected: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
