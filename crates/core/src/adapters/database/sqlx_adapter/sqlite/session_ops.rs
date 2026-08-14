use super::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation, AuthInvitationMeta,
    AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta, AuthPasskey,
    AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor, AuthTwoFactorMeta, AuthUser,
    AuthUserMeta, AuthVerification, AuthVerificationMeta,
};
use crate::error::AuthResult;
use crate::types::CreateSession;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- SessionOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> SessionOps for SqliteAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Session = S;

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S> {
        let id = Uuid::new_v4().to_string();
        let token = format!("session_{}", Uuid::new_v4());
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
            qi(S::table()),
            qi(S::col_id()),
            qi(S::col_user_id()),
            qi(S::col_token()),
            qi(S::col_expires_at()),
            qi(S::col_created_at()),
            qi(S::col_ip_address()),
            qi(S::col_user_agent()),
            qi(S::col_impersonated_by()),
            qi(S::col_active_organization_id()),
            qi(S::col_active()),
        );
        let session = sqlx::query_as::<_, S>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_session.user_id)
            .bind(&token)
            .bind(create_session.expires_at)
            .bind(now)
            .bind(&create_session.ip_address)
            .bind(&create_session.user_agent)
            .bind(&create_session.impersonated_by)
            .bind(&create_session.active_organization_id)
            .bind(true)
            .fetch_one(&self.pool)
            .await?;

        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<S>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? AND {} = true",
            qi(S::table()),
            qi(S::col_token()),
            qi(S::col_active())
        );
        let session = sqlx::query_as::<_, S>(AssertSqlSafe(sql))
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        Ok(session)
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? AND {} = true ORDER BY {} DESC",
            qi(S::table()),
            qi(S::col_user_id()),
            qi(S::col_active()),
            qi(S::col_created_at())
        );
        let sessions = sqlx::query_as::<_, S>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(sessions)
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let sql = format!(
            "UPDATE {} SET {} = ?, {} = ? WHERE {} = ? AND {} = true",
            qi(S::table()),
            qi(S::col_expires_at()),
            qi(S::col_updated_at()),
            qi(S::col_token()),
            qi(S::col_active())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(expires_at)
            .bind(Utc::now())
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = ?",
            qi(S::table()),
            qi(S::col_token())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = ?",
            qi(S::table()),
            qi(S::col_user_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        // Use a bind-parameter with an RFC 3339 timestamp instead of
        // CURRENT_TIMESTAMP so the comparison is straightforward.
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "DELETE FROM {} WHERE {} < ? OR {} = false",
            qi(S::table()),
            qi(S::col_expires_at()),
            qi(S::col_active())
        );
        let result = sqlx::query(AssertSqlSafe(sql))
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S> {
        // Use a bind-parameter with an RFC 3339 timestamp instead of
        // CURRENT_TIMESTAMP so the comparison is straightforward.
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "UPDATE {} SET {} = ?, {} = ? WHERE {} = ? AND {} = true RETURNING *",
            qi(S::table()),
            qi(S::col_active_organization_id()),
            qi(S::col_updated_at()),
            qi(S::col_token()),
            qi(S::col_active())
        );
        let session = sqlx::query_as::<_, S>(AssertSqlSafe(sql))
            .bind(organization_id)
            .bind(&now)
            .bind(token)
            .fetch_one(&self.pool)
            .await?;
        Ok(session)
    }
}
