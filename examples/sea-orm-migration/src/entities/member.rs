use better_auth_core::AuthMember;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthMember)]
#[sea_orm(table_name = "member")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(indexed)]
    pub organization_id: String,
    #[sea_orm(indexed)]
    pub user_id: String,
    pub role: String,
    pub created_at: DateTimeUtc,

    // Relations
    #[sea_orm(belongs_to, from = "organization_id", to = "id")]
    pub organization: HasOne<super::organization::Entity>,
    #[sea_orm(belongs_to, from = "user_id", to = "id")]
    pub user: HasOne<super::user::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
