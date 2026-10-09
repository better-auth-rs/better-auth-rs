use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "team")]
#[sea_orm(table_name = "team")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub created_at: DateTimeUtc,
    pub updated_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "member_count")]
    pub member_count: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
impl From<Model> for better_auth_core::Team {
    fn from(model: Model) -> Self {
        Self {
            additional_fields: Default::default(),
            field_order: Default::default(),
            id: model.id.into(),
            name: model.name.into(),
            organization_id: model.organization_id.into(),
            created_at: model.created_at.into(),
            updated_at: model
                .updated_at
                .map(better_auth_core::FieldDate::from)
                .into(),
        }
    }
}
