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
use crate::types::CreateMember;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- MemberOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> MemberOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Member = M;

    async fn create_member(&self, create_member: CreateMember) -> AuthResult<M> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            qi(M::table()),
            qi(M::col_id()),
            qi(M::col_organization_id()),
            qi(M::col_user_id()),
            qi(M::col_role()),
            qi(M::col_created_at()),
        );
        let member = sqlx::query_as::<_, M>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_member.organization_id)
            .bind(&create_member.user_id)
            .bind(&create_member.role)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(member)
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<M>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1 AND {} = $2",
            qi(M::table()),
            qi(M::col_organization_id()),
            qi(M::col_user_id())
        );
        let member = sqlx::query_as::<_, M>(AssertSqlSafe(sql))
            .bind(organization_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(member)
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<M>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(M::table()),
            qi(M::col_id())
        );
        let member = sqlx::query_as::<_, M>(AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(member)
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<M> {
        let sql = format!(
            "UPDATE {} SET {} = $1 WHERE {} = $2 RETURNING *",
            qi(M::table()),
            qi(M::col_role()),
            qi(M::col_id())
        );
        let member = sqlx::query_as::<_, M>(AssertSqlSafe(sql))
            .bind(role)
            .bind(member_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(member)
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = $1",
            qi(M::table()),
            qi(M::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(member_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<M>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1 ORDER BY {} ASC",
            qi(M::table()),
            qi(M::col_organization_id()),
            qi(M::col_created_at())
        );
        let members = sqlx::query_as::<_, M>(AssertSqlSafe(sql))
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(members)
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE {} = $1",
            qi(M::table()),
            qi(M::col_organization_id())
        );
        let count: (i64,) = sqlx::query_as(AssertSqlSafe(sql))
            .bind(organization_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0 as usize)
    }

    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE {} = $1 AND {} = 'owner'",
            qi(M::table()),
            qi(M::col_organization_id()),
            qi(M::col_role())
        );
        let count: (i64,) = sqlx::query_as(AssertSqlSafe(sql))
            .bind(organization_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0 as usize)
    }
}
