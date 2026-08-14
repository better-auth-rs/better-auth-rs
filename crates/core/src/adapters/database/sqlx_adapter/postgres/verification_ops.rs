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
    for PostgresAdapter<U, S, A, O, M, I, V, TF, AK, PK>
where
    U: AuthUser + AuthUserMeta + PostgresEntity,
    S: AuthSession + AuthSessionMeta + PostgresEntity,
    A: AuthAccount + AuthAccountMeta + PostgresEntity,
    O: AuthOrganization + AuthOrganizationMeta + PostgresEntity,
    M: AuthMember + AuthMemberMeta + PostgresEntity,
    I: AuthInvitation + AuthInvitationMeta + PostgresEntity,
    V: AuthVerification + AuthVerificationMeta + PostgresEntity,
    TF: AuthTwoFactor + AuthTwoFactorMeta + PostgresEntity,
    AK: AuthApiKey + AuthApiKeyMeta + PostgresEntity,
    PK: AuthPasskey + AuthPasskeyMeta + PostgresEntity,
{
    type Verification = V;

    async fn create_verification(&self, create_verification: CreateVerification) -> AuthResult<V> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
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
            "SELECT * FROM {} WHERE {} = $1 AND {} = $2 AND {} > NOW()",
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
            "SELECT * FROM {} WHERE {} = $1 AND {} > NOW()",
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
            "SELECT * FROM {} WHERE {} = $1 AND {} > NOW()",
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
                    WHERE {ident} = $1 AND {val} = $2 AND {exp} > NOW() \
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
            "DELETE FROM {} WHERE {} = $1",
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
            "DELETE FROM {} WHERE {} < NOW()",
            qi(V::table()),
            qi(V::col_expires_at())
        );
        let result = sqlx::query(AssertSqlSafe(sql)).execute(&self.pool).await?;
        Ok(result.rows_affected() as usize)
    }
}

