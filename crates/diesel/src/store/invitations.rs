use async_trait::async_trait;
use better_auth_core::store::InvitationStore;
use better_auth_core::{CreateInvitation, Invitation, InvitationStatus};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::models::InvitationRow;
use crate::schema::invitation;
use crate::sql_types::UtcTimestampValue;

use super::{DieselStore, new_id};

#[async_trait]
impl InvitationStore for DieselStore {
    async fn create_invitation(&self, input: CreateInvitation) -> AuthResult<Invitation> {
        let row = InvitationRow {
            id: new_id(),
            organization_id: input.organization_id,
            email: input.email,
            role: input.role,
            status: InvitationStatus::Pending.to_string(),
            inviter_id: input.inviter_id,
            expires_at: input.expires_at,
            created_at: Utc::now(),
        };

        run_query!(self, |c| {
            diesel::insert_into(invitation::table)
                .values(row)
                .returning(InvitationRow::as_returning())
                .get_result(c)
                .await
        })
        .map(Invitation::from)
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        run_query!(self, |c| {
            invitation::table
                .find(id)
                .select(InvitationRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Invitation::from))
    }

    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let email = email.to_lowercase();
        let pending = InvitationStatus::Pending.to_string();
        run_query!(self, |c| {
            invitation::table
                .filter(invitation::organization_id.eq(organization_id))
                .filter(invitation::email.eq(&email))
                .filter(invitation::status.eq(&pending))
                .filter(invitation::expires_at.gt(UtcTimestampValue(Utc::now())))
                .select(InvitationRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Invitation::from))
    }

    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let status = status.to_string();
        run_query!(self, |c| {
            diesel::update(invitation::table.find(id))
                .set(invitation::status.eq(&status))
                .returning(InvitationRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(Invitation::from)
        .ok_or_else(|| AuthError::not_found("Invitation not found"))
    }

    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        run_query!(self, |c| {
            invitation::table
                .filter(invitation::organization_id.eq(organization_id))
                .order(invitation::created_at.desc())
                .select(InvitationRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(Invitation::from).collect())
    }

    async fn count_pending_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<i64> {
        let pending = InvitationStatus::Pending.to_string();
        run_query!(self, |c| {
            invitation::table
                .filter(invitation::organization_id.eq(organization_id))
                .filter(invitation::status.eq(&pending))
                .filter(invitation::expires_at.gt(UtcTimestampValue(Utc::now())))
                .count()
                .get_result(c)
                .await
        })
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        let email = email.to_lowercase();
        let pending = InvitationStatus::Pending.to_string();
        run_query!(self, |c| {
            invitation::table
                .filter(invitation::email.eq(&email))
                .filter(invitation::status.eq(&pending))
                .filter(invitation::expires_at.gt(UtcTimestampValue(Utc::now())))
                .order(invitation::created_at.desc())
                .select(InvitationRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(Invitation::from).collect())
    }
}
