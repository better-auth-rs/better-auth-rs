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
use crate::types::CreateVerification;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- VerificationOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> VerificationOps
    for SqliteAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Verification = V;

    async fn create_verification(&self, create_verification: CreateVerification) -> AuthResult<V> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}) VALUES (?, ?, ?, ?, ?, ?) RETURNING *",
            qi(V::table()),
            qi(V::col_id()),
            qi(V::col_identifier()),
            qi(V::col_value()),
            qi(V::col_expires_at()),
            qi(V::col_created_at()),
            qi(V::col_updated_at()),
        );
        let verification = sqlx::query_as::<_, V>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_verification.identifier)
            .bind(&create_verification.value)
            .bind(create_verification.expires_at)
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(verification)
    }

    async fn get_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<V>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? AND {} = ? AND {} > CURRENT_TIMESTAMP",
            qi(V::table()),
            qi(V::col_identifier()),
            qi(V::col_value()),
            qi(V::col_expires_at())
        );
        let verification = sqlx::query_as::<_, V>(AssertSqlSafe(sql))
            .bind(identifier)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        Ok(verification)
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<V>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? AND {} > CURRENT_TIMESTAMP",
            qi(V::table()),
            qi(V::col_value()),
            qi(V::col_expires_at())
        );
        let verification = sqlx::query_as::<_, V>(AssertSqlSafe(sql))
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        Ok(verification)
    }

    async fn get_verification_by_identifier(&self, identifier: &str) -> AuthResult<Option<V>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? AND {} > CURRENT_TIMESTAMP",
            qi(V::table()),
            qi(V::col_identifier()),
            qi(V::col_expires_at())
        );
        let verification = sqlx::query_as::<_, V>(AssertSqlSafe(sql))
            .bind(identifier)
            .fetch_optional(&self.pool)
            .await?;
        Ok(verification)
    }

    async fn consume_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<V>> {
        let sql = format!(
            "DELETE FROM {tbl} WHERE {id} IN (\
                    SELECT {id} FROM {tbl} \
                    WHERE {ident} = ? AND {val} = ? AND {exp} > CURRENT_TIMESTAMP \
                    ORDER BY {ca} DESC \
                    LIMIT 1\
                ) RETURNING *",
            tbl = qi(V::table()),
            id = qi(V::col_id()),
            ident = qi(V::col_identifier()),
            val = qi(V::col_value()),
            exp = qi(V::col_expires_at()),
            ca = qi(V::col_created_at()),
        );
        let verification = sqlx::query_as::<_, V>(AssertSqlSafe(sql))
            .bind(identifier)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        Ok(verification)
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = ?",
            qi(V::table()),
            qi(V::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let sql = format!(
            "DELETE FROM {} WHERE {} < CURRENT_TIMESTAMP",
            qi(V::table()),
            qi(V::col_expires_at())
        );
        let result = sqlx::query(AssertSqlSafe(sql)).execute(&self.pool).await?;
        Ok(result.rows_affected() as usize)
    }
}



