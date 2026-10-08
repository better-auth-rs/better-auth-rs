use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
#[auth(role = "jwk")]
#[sea_orm(table_name = "jwks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTimeUtc,
    pub expires_at: Option<DateTimeUtc>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for better_auth_core::Jwk {
    fn from(model: Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.into(),
            public_key: model.public_key.into(),
            private_key: model.private_key.into(),
            created_at: better_auth_core::FieldDate::from(model.created_at).into(),
            expires_at: model
                .expires_at
                .map(better_auth_core::FieldDate::from)
                .into(),
            alg: model.alg.into(),
            crv: model.crv.into(),
        }
    }
}
