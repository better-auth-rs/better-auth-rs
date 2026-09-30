use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "two_factor")]
#[sea_orm(table_name = "two_factor")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub secret: String,
    pub backup_codes: String,
    pub user_id: String,
    pub verified: bool,
    pub failed_verification_count: i64,
    pub locked_until: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
