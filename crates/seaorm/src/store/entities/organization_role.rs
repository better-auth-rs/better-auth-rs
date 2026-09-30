use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "organization_role")]
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
            additional_fields: Default::default(),
            id: model.id,
            organization_id: model.organization_id.into(),
            role: model.role.into(),
            permission: model.permission.into(),
            created_at: model.created_at.into(),
            updated_at: model.updated_at.into(),
        }
    }
}
