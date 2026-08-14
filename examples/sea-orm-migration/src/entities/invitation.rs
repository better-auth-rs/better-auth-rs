use better_auth_core::{AuthInvitation, InvitationStatus};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthInvitation)]
#[sea_orm(table_name = "invitation")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(indexed)]
    pub organization_id: String,
    #[sea_orm(indexed)]
    pub email: String,
    pub role: String,
    /// Stored as TEXT in the database. `#[sea_orm(ignore)]` tells Sea-ORM to
    /// skip this field; the macro auto-detects `InvitationStatus` as a
    /// non-primitive type and generates `From<String>` conversion in `FromRow`.
    #[sea_orm(ignore)]
    pub status: InvitationStatus,
    pub inviter_id: String,
    #[sea_orm(indexed)]
    pub expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,

    // Relations
    #[sea_orm(belongs_to, from = "organization_id", to = "id")]
    pub organization: HasOne<super::organization::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
