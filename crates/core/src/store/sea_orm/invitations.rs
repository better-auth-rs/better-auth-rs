use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::types_org::{CreateInvitation, Invitation, InvitationStatus};

use super::entities::invitation::{ActiveModel, Column, Entity};
use super::{AuthStore, map_db_err};

impl AuthStore {
    pub async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(invitation.organization_id),
            email: Set(invitation.email),
            role: Set(invitation.role),
            status: Set(InvitationStatus::Pending.to_string()),
            inviter_id: Set(invitation.inviter_id),
            expires_at: Set(invitation.expires_at),
            created_at: Set(Utc::now()),
        }
        .insert(self.connection())
        .await
        .map(Invitation::from)
        .map_err(map_db_err)
    }

    pub async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(Invitation::from))
            .map_err(map_db_err)
    }

    pub async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::Email.eq(email.to_lowercase()))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .one(self.connection())
            .await
            .map(|model| model.map(Invitation::from))
            .map_err(map_db_err)
    }

    pub async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Invitation not found"));
        };

        let mut active = model.into_active_model();
        active.status = Set(status.to_string());
        active
            .update(self.connection())
            .await
            .map(Invitation::from)
            .map_err(map_db_err)
    }

    pub async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }

    pub async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::Email.eq(email.to_lowercase()))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }
}
