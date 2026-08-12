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
use crate::types::{CreateApiKey, UpdateApiKey};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- ApiKeyOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> ApiKeyOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type ApiKey = AK;

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<AK> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::timestamptz, $15, $16, $17, $18) RETURNING *",
            qi(AK::table()),
            qi(AK::col_id()),
            qi(AK::col_name()),
            qi(AK::col_start()),
            qi(AK::col_prefix()),
            qi(AK::col_key_hash()),
            qi(AK::col_user_id()),
            qi(AK::col_refill_interval()),
            qi(AK::col_refill_amount()),
            qi(AK::col_enabled()),
            qi(AK::col_rate_limit_enabled()),
            qi(AK::col_rate_limit_time_window()),
            qi(AK::col_rate_limit_max()),
            qi(AK::col_remaining()),
            qi(AK::col_expires_at()),
            qi(AK::col_created_at()),
            qi(AK::col_updated_at()),
            qi(AK::col_permissions()),
            qi(AK::col_metadata()),
        );
        let api_key = sqlx::query_as::<_, AK>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&input.name)
            .bind(&input.start)
            .bind(&input.prefix)
            .bind(&input.key_hash)
            .bind(&input.user_id)
            .bind(input.refill_interval)
            .bind(input.refill_amount)
            .bind(input.enabled)
            .bind(input.rate_limit_enabled)
            .bind(input.rate_limit_time_window)
            .bind(input.rate_limit_max)
            .bind(input.remaining)
            .bind(&input.expires_at)
            .bind(now)
            .bind(now)
            .bind(&input.permissions)
            .bind(&input.metadata)
            .fetch_one(&self.pool)
            .await?;

        Ok(api_key)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<AK>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(AK::table()),
            qi(AK::col_id())
        );
        let api_key = sqlx::query_as::<_, AK>(AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(api_key)
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<AK>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(AK::table()),
            qi(AK::col_key_hash())
        );
        let api_key = sqlx::query_as::<_, AK>(AssertSqlSafe(sql))
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?;
        Ok(api_key)
    }

    async fn list_api_keys_by_user(&self, user_id: &str) -> AuthResult<Vec<AK>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1 ORDER BY {} DESC",
            qi(AK::table()),
            qi(AK::col_user_id()),
            qi(AK::col_created_at())
        );
        let keys = sqlx::query_as::<_, AK>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(keys)
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<AK> {
        let mut query = sqlx::QueryBuilder::new(format!(
            "UPDATE {} SET {} = NOW()",
            qi(AK::table()),
            qi(AK::col_updated_at())
        ));

        if let Some(name) = &update.name {
            query.push(format!(", {} = ", qi(AK::col_name())));
            query.push_bind(name);
        }
        if let Some(enabled) = update.enabled {
            query.push(format!(", {} = ", qi(AK::col_enabled())));
            query.push_bind(enabled);
        }
        if let Some(remaining) = update.remaining {
            query.push(format!(", {} = ", qi(AK::col_remaining())));
            query.push_bind(remaining);
        }
        if let Some(rate_limit_enabled) = update.rate_limit_enabled {
            query.push(format!(", {} = ", qi(AK::col_rate_limit_enabled())));
            query.push_bind(rate_limit_enabled);
        }
        if let Some(rate_limit_time_window) = update.rate_limit_time_window {
            query.push(format!(", {} = ", qi(AK::col_rate_limit_time_window())));
            query.push_bind(rate_limit_time_window);
        }
        if let Some(rate_limit_max) = update.rate_limit_max {
            query.push(format!(", {} = ", qi(AK::col_rate_limit_max())));
            query.push_bind(rate_limit_max);
        }
        if let Some(refill_interval) = update.refill_interval {
            query.push(format!(", {} = ", qi(AK::col_refill_interval())));
            query.push_bind(refill_interval);
        }
        if let Some(refill_amount) = update.refill_amount {
            query.push(format!(", {} = ", qi(AK::col_refill_amount())));
            query.push_bind(refill_amount);
        }
        if let Some(permissions) = &update.permissions {
            query.push(format!(", {} = ", qi(AK::col_permissions())));
            query.push_bind(permissions);
        }
        if let Some(metadata) = &update.metadata {
            query.push(format!(", {} = ", qi(AK::col_metadata())));
            query.push_bind(metadata);
        }
        if let Some(expires_at) = &update.expires_at {
            query.push(format!(", {} = ", qi(AK::col_expires_at())));
            query.push_bind(expires_at.as_deref().map(|s| s.to_string()));
        }
        if let Some(last_request) = &update.last_request {
            query.push(format!(", {} = ", qi(AK::col_last_request())));
            query.push_bind(last_request.as_deref().map(|s| s.to_string()));
        }
        if let Some(request_count) = update.request_count {
            query.push(format!(", {} = ", qi(AK::col_request_count())));
            query.push_bind(request_count);
        }
        if let Some(last_refill_at) = &update.last_refill_at {
            query.push(format!(", {} = ", qi(AK::col_last_refill_at())));
            query.push_bind(last_refill_at.as_deref().map(|s| s.to_string()));
        }

        query.push(format!(" WHERE {} = ", qi(AK::col_id())));
        query.push_bind(id);
        query.push(" RETURNING *");

        let api_key = query
            .build_query_as::<AK>()
            .fetch_one(&self.pool)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => AuthError::not_found("API key not found"),
                other => AuthError::from(other),
            })?;
        Ok(api_key)
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = $1",
            qi(AK::table()),
            qi(AK::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        // Use a bind-parameter with an RFC 3339 timestamp instead of
        // NOW() / ::timestamptz so the comparison is straightforward.
        // (This adapter is PostgreSQL-only; $1 placeholders are correct.)
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "DELETE FROM {} WHERE {} IS NOT NULL AND {} < $1",
            qi(AK::table()),
            qi(AK::col_expires_at()),
            qi(AK::col_expires_at()),
        );
        let result = sqlx::query(AssertSqlSafe(sql))
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}
