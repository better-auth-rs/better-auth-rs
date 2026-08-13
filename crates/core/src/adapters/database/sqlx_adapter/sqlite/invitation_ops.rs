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
impl<U, S, A, O, M, I, V, TF, AK, PK> InvitationOps for SqliteAdapter<U, S, A, O, M, I, V, TF, AK, PK>
where
    U: AuthUser + AuthUserMeta + SqliteEntity,
    S: AuthSession + AuthSessionMeta + SqliteEntity,
    A: AuthAccount + AuthAccountMeta + SqliteEntity,
    O: AuthOrganization + AuthOrganizationMeta + SqliteEntity,
    M: AuthMember + AuthMemberMeta + SqliteEntity,
    I: AuthInvitation + AuthInvitationMeta + SqliteEntity,
    V: AuthVerification + AuthVerificationMeta + SqliteEntity,
    TF: AuthTwoFactor + AuthTwoFactorMeta + SqliteEntity,
    AK: AuthApiKey + AuthApiKeyMeta + SqliteEntity,
    PK: AuthPasskey + AuthPasskeyMeta + SqliteEntity,
{
    type Invitation = I;

    async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<I> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES (?, ?, ?, ?, 'pending', ?, ?, ?) RETURNING *",
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
            "SELECT * FROM {} WHERE {} = ?",
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
            "SELECT * FROM {} WHERE {} = ? AND LOWER({}) = LOWER(?) AND {} = 'pending'",
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
            "UPDATE {} SET {} = ? WHERE {} = ? RETURNING *",
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
            "SELECT * FROM {} WHERE {} = ? ORDER BY {} DESC",
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
        // Use a bind-parameter with an RFC 3339 timestamp instead of
        // CURRENT_TIMESTAMP so the comparison is straightforward.
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT * FROM {} WHERE LOWER({}) = LOWER(?) AND {} = 'pending' AND {} > ? ORDER BY {} DESC",
            qi(I::table()),
            qi(I::col_email()),
            qi(I::col_status()),
            qi(I::col_expires_at()),
            qi(I::col_created_at())
        );
        let invitations = sqlx::query_as::<_, I>(AssertSqlSafe(sql))
            .bind(email)
            .bind(&now)
            .fetch_all(&self.pool)
            .await?;
        Ok(invitations)
    }
}



