use super::*;
use async_trait::async_trait;
use chrono::Utc;

use crate::entity::{
    AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation, AuthInvitationMeta,
    AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta, AuthPasskey,
    AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor, AuthTwoFactorMeta, AuthUser,
    AuthUserMeta, AuthVerification, AuthVerificationMeta,
};
use crate::error::AuthResult;
use crate::types::{CreateInvitation, InvitationStatus};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- InvitationOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> InvitationOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
where
    U: AuthUser + AuthUserMeta + SqlxEntity,
    S: AuthSession + AuthSessionMeta + SqlxEntity,
    A: AuthAccount + AuthAccountMeta + SqlxEntity,
    O: AuthOrganization + AuthOrganizationMeta + SqlxEntity,
    M: AuthMember + AuthMemberMeta + SqlxEntity,
    I: AuthInvitation + AuthInvitationMeta + SqlxEntity,
    V: AuthVerification + AuthVerificationMeta + SqlxEntity,
    TF: AuthTwoFactor + AuthTwoFactorMeta + SqlxEntity,
    AK: AuthApiKey + AuthApiKeyMeta + SqlxEntity,
    PK: AuthPasskey + AuthPasskeyMeta + SqlxEntity,
{
    type Invitation = I;

    async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<I> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7) RETURNING *",
            qi(I::table()),
            qi(I::col_id()),
            qi(I::col_organization_id()),
            qi(I::col_email()),
            qi(I::col_role()),
            qi(I::col_status()),
            qi(I::col_inviter_id()),
            qi(I::col_expires_at()),
            qi(I::col_created_at()),
        );
        let invitation = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_inv.organization_id)
            .bind(&create_inv.email)
            .bind(&create_inv.role)
            .bind(&create_inv.inviter_id)
            .bind(create_inv.expires_at)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(invitation)
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<I>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(I::table()),
            qi(I::col_id())
        );
        let invitation = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(invitation)
    }

    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<I>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1 AND LOWER({}) = LOWER($2) AND {} = 'pending'",
            qi(I::table()),
            qi(I::col_organization_id()),
            qi(I::col_email()),
            qi(I::col_status())
        );
        let invitation = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(organization_id)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(invitation)
    }

    async fn update_invitation_status(&self, id: &str, status: InvitationStatus) -> AuthResult<I> {
        let sql = format!(
            "UPDATE {} SET {} = $1 WHERE {} = $2 RETURNING *",
            qi(I::table()),
            qi(I::col_status()),
            qi(I::col_id())
        );
        let invitation = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(status.to_string())
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(invitation)
    }

    async fn list_organization_invitations(&self, organization_id: &str) -> AuthResult<Vec<I>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1 ORDER BY {} DESC",
            qi(I::table()),
            qi(I::col_organization_id()),
            qi(I::col_created_at())
        );
        let invitations = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(invitations)
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<I>> {
        let sql = format!(
            "SELECT * FROM {} WHERE LOWER({}) = LOWER($1) AND {} = 'pending' AND {} > NOW() ORDER BY {} DESC",
            qi(I::table()),
            qi(I::col_email()),
            qi(I::col_status()),
            qi(I::col_expires_at()),
            qi(I::col_created_at())
        );
        let invitations = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(email)
            .fetch_all(&self.pool)
            .await?;
        Ok(invitations)
    }
}
