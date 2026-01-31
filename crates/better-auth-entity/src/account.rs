use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use sea_orm::prelude::async_trait::async_trait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "account")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub account_id: String,
    pub provider_id: String,
    pub user_id: Uuid,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    #[schema(value_type = String, format = DateTime)]
    pub access_token_expires_at: Option<DateTimeWithTimeZone>,
    #[schema(value_type = String, format = DateTime)]
    pub refresh_token_expires_at: Option<DateTimeWithTimeZone>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[sea_orm(default_value = "now()")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: DateTimeWithTimeZone,
    #[sea_orm(default_value = "now()")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

#[async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert && self.id.is_not_set() {
            let uuid = Uuid::new_v4();
            self.id = Set(uuid);
        }
        Ok(self)
    }
}
