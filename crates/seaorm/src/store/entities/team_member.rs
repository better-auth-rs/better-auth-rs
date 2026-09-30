use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "team_member")]
#[sea_orm(table_name = "team_member")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub team_id: String,
    pub user_id: String,
    #[sea_orm(unique)]
    pub membership_key: Option<String>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
impl From<Model> for better_auth_core::TeamMember {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            team_id: model.team_id,
            user_id: model.user_id,
            created_at: model.created_at,
        }
    }
}
