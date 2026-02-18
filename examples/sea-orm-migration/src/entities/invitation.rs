use better_auth_core::{AuthInvitation, InvitationStatus};
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, AuthInvitation)]
#[sea_orm(table_name = "invitation")]
#[auth(from_row)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "organizationId")]
    #[auth(column = "organizationId")]
    pub organization_id: String,
    pub email: String,
    pub role: String,
    /// Stored as TEXT in the database. `#[sea_orm(ignore)]` tells Sea-ORM to
    /// skip this field; the macro auto-detects `InvitationStatus` as a
    /// non-primitive type and generates `From<String>` conversion in `FromRow`.
    #[sea_orm(ignore)]
    pub status: InvitationStatus,
    #[sea_orm(column_name = "inviterId")]
    #[auth(column = "inviterId")]
    pub inviter_id: String,
    #[sea_orm(column_name = "expiresAt")]
    #[auth(column = "expiresAt")]
    pub expires_at: DateTimeUtc,
    #[sea_orm(column_name = "createdAt")]
    #[auth(column = "createdAt")]
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
