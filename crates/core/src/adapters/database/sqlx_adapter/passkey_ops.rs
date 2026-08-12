use super::*;
use async_trait::async_trait;
use chrono::Utc;

use crate::entity::{
    AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation, AuthInvitationMeta,
    AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta, AuthPasskey,
    AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor, AuthTwoFactorMeta, AuthUser,
    AuthUserMeta, AuthVerification, AuthVerificationMeta,
};
use crate::error::{AuthError, AuthResult};
use crate::types::CreatePasskey;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- PasskeyOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> PasskeyOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Passkey = PK;

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<PK> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let counter = i64::try_from(input.counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
            qi(PK::table()),
            qi(PK::col_id()),
            qi(PK::col_name()),
            qi(PK::col_public_key()),
            qi(PK::col_user_id()),
            qi(PK::col_credential_id()),
            qi(PK::col_counter()),
            qi(PK::col_device_type()),
            qi(PK::col_backed_up()),
            qi(PK::col_transports()),
            qi(PK::col_created_at()),
        );
        let passkey = sqlx::query_as::<_, PK>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&input.name)
            .bind(&input.public_key)
            .bind(&input.user_id)
            .bind(&input.credential_id)
            .bind(counter)
            .bind(&input.device_type)
            .bind(input.backed_up)
            .bind(&input.transports)
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                    AuthError::conflict("A passkey with this credential ID already exists")
                }
                other => AuthError::from(other),
            })?;

        Ok(passkey)
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<PK>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(PK::table()),
            qi(PK::col_id())
        );
        let passkey = sqlx::query_as::<_, PK>(AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(passkey)
    }

    async fn get_passkey_by_credential_id(&self, credential_id: &str) -> AuthResult<Option<PK>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(PK::table()),
            qi(PK::col_credential_id())
        );
        let passkey = sqlx::query_as::<_, PK>(AssertSqlSafe(sql))
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(passkey)
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<PK>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1 ORDER BY {} DESC",
            qi(PK::table()),
            qi(PK::col_user_id()),
            qi(PK::col_created_at())
        );
        let passkeys = sqlx::query_as::<_, PK>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(passkeys)
    }

    async fn update_passkey_counter(&self, id: &str, counter: u64) -> AuthResult<PK> {
        let counter = i64::try_from(counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
        let sql = format!(
            "UPDATE {} SET {} = $2 WHERE {} = $1 RETURNING *",
            qi(PK::table()),
            qi(PK::col_counter()),
            qi(PK::col_id())
        );
        let passkey = sqlx::query_as::<_, PK>(AssertSqlSafe(sql))
            .bind(id)
            .bind(counter)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => AuthError::not_found("Passkey not found"),
                other => AuthError::from(other),
            })?;
        Ok(passkey)
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<PK> {
        let sql = format!(
            "UPDATE {} SET {} = $2 WHERE {} = $1 RETURNING *",
            qi(PK::table()),
            qi(PK::col_name()),
            qi(PK::col_id())
        );
        let passkey = sqlx::query_as::<_, PK>(AssertSqlSafe(sql))
            .bind(id)
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => AuthError::not_found("Passkey not found"),
                other => AuthError::from(other),
            })?;
        Ok(passkey)
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = $1",
            qi(PK::table()),
            qi(PK::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
