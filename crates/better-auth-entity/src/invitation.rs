use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use sea_orm::prelude::async_trait::async_trait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Invitation status values
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

impl From<String> for InvitationStatus {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            "canceled" => Self::Canceled,
            _ => Self::Pending,
        }
    }
}

impl From<InvitationStatus> for String {
    fn from(status: InvitationStatus) -> Self {
        match status {
            InvitationStatus::Pending => "pending".to_string(),
            InvitationStatus::Accepted => "accepted".to_string(),
            InvitationStatus::Rejected => "rejected".to_string(),
            InvitationStatus::Canceled => "canceled".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "invitation")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    #[sea_orm(default_value = "member")]
    pub role: String,
    /// Status: pending, accepted, rejected, canceled
    #[sea_orm(default_value = "pending")]
    pub status: String,
    pub inviter_id: Uuid,
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: DateTimeWithTimeZone,
    #[sea_orm(default_value = "now()")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: DateTimeWithTimeZone,
}

impl Model {
    /// Get the status as an enum
    pub fn status_enum(&self) -> InvitationStatus {
        InvitationStatus::from(self.status.clone())
    }

    /// Check if the invitation is still pending
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// Check if the invitation has expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < chrono::Utc::now().fixed_offset()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organization::Entity",
        from = "Column::OrganizationId",
        to = "super::organization::Column::Id"
    )]
    Organization,
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::InviterId",
        to = "super::user::Column::Id"
    )]
    Inviter,
}

impl Related<super::organization::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organization.def()
    }
}

#[async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert && self.id.is_not_set() {
            let uuid = Uuid::new_v4();
            self.id = Set(uuid);
        }
        Ok(self)
    }
}
