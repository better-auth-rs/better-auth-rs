use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "organization_role")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub organization_id: String,
    pub role: String,
    pub permission: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
impl From<Model> for better_auth_core::OrganizationRole {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            organization_id: model.organization_id,
            role: model.role,
            permission: model.permission,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}
