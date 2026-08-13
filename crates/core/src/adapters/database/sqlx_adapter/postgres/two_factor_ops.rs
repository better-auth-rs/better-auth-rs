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
use crate::types::CreateTwoFactor;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- TwoFactorOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> TwoFactorOps for PostgresAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type TwoFactor = TF;

    async fn create_two_factor(&self, create: CreateTwoFactor) -> AuthResult<TF> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            qi(TF::table()),
            qi(TF::col_id()),
            qi(TF::col_secret()),
            qi(TF::col_backup_codes()),
            qi(TF::col_user_id()),
            qi(TF::col_created_at()),
            qi(TF::col_updated_at()),
        );
        let two_factor = sqlx::query_as::<_, TF>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create.secret)
            .bind(&create.backup_codes)
            .bind(&create.user_id)
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(two_factor)
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TF>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(TF::table()),
            qi(TF::col_user_id())
        );
        let two_factor = sqlx::query_as::<_, TF>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(two_factor)
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TF> {
        let sql = format!(
            "UPDATE {} SET {} = $1, {} = NOW() WHERE {} = $2 RETURNING *",
            qi(TF::table()),
            qi(TF::col_backup_codes()),
            qi(TF::col_updated_at()),
            qi(TF::col_user_id())
        );
        let two_factor = sqlx::query_as::<_, TF>(AssertSqlSafe(sql))
            .bind(backup_codes)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(two_factor)
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = $1",
            qi(TF::table()),
            qi(TF::col_user_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

