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
impl<U, S, A, O, M, I, V, TF, AK, PK> MemberOps for SqliteAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Member = M;

    async fn create_member(&self, create_member: CreateMember) -> AuthResult<M> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}) VALUES (?, ?, ?, ?, ?) RETURNING *",
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
            "SELECT * FROM {} WHERE {} = ? AND {} = ?",
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
            "SELECT * FROM {} WHERE {} = ?",
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
            "UPDATE {} SET {} = ? WHERE {} = ? RETURNING *",
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
            "DELETE FROM {} WHERE {} = ?",
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
            "SELECT * FROM {} WHERE {} = ? ORDER BY {} ASC",
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
            "SELECT COUNT(*) FROM {} WHERE {} = ?",
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
            "SELECT COUNT(*) FROM {} WHERE {} = ? AND {} = 'owner'",
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



