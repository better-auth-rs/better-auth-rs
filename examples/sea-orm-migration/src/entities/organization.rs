use better_auth_core::AuthOrganization;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthOrganization)]
#[sea_orm(table_name = "organization")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    #[sea_orm(unique, indexed)]
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<Json>,
    #[sea_orm(indexed)]
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    // --- Application-specific columns ---
    pub billing_email: Option<String>,
    #[auth(default = "\"free\".to_string()")]
    pub plan: String,

    // Relations
    #[sea_orm(has_many)]
    pub members: HasMany<super::member::Entity>,
    #[sea_orm(has_many)]
    pub invitations: HasMany<super::invitation::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
