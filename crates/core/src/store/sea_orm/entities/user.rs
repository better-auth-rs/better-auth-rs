use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTimeUtc>,
    pub metadata: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
