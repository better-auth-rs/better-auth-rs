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
use crate::types::{CreateAccount, UpdateAccount};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- AccountOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> AccountOps for SqliteAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Account = A;

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<A> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
            qi(A::table()),
            qi(A::col_id()),
            qi(A::col_account_id()),
            qi(A::col_provider_id()),
            qi(A::col_user_id()),
            qi(A::col_access_token()),
            qi(A::col_refresh_token()),
            qi(A::col_id_token()),
            qi(A::col_access_token_expires_at()),
            qi(A::col_refresh_token_expires_at()),
            qi(A::col_scope()),
            qi(A::col_password()),
            qi(A::col_created_at()),
            qi(A::col_updated_at()),
        );
        let account = sqlx::query_as::<_, A>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_account.account_id)
            .bind(&create_account.provider_id)
            .bind(&create_account.user_id)
            .bind(&create_account.access_token)
            .bind(&create_account.refresh_token)
            .bind(&create_account.id_token)
            .bind(create_account.access_token_expires_at)
            .bind(create_account.refresh_token_expires_at)
            .bind(&create_account.scope)
            .bind(&create_account.password)
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(account)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<A>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? AND {} = ?",
            qi(A::table()),
            qi(A::col_provider_id()),
            qi(A::col_account_id())
        );
        let account = sqlx::query_as::<_, A>(AssertSqlSafe(sql))
            .bind(provider)
            .bind(provider_account_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(account)
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<A>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = ? ORDER BY {} DESC",
            qi(A::table()),
            qi(A::col_user_id()),
            qi(A::col_created_at())
        );
        let accounts = sqlx::query_as::<_, A>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(accounts)
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<A> {
        let mut query = sqlx::QueryBuilder::new(format!(
            "UPDATE {} SET {} = CURRENT_TIMESTAMP",
            qi(A::table()),
            qi(A::col_updated_at())
        ));

        if let Some(access_token) = &update.access_token {
            query.push(format!(", {} = ", qi(A::col_access_token())));
            query.push_bind(access_token);
        }
        if let Some(refresh_token) = &update.refresh_token {
            query.push(format!(", {} = ", qi(A::col_refresh_token())));
            query.push_bind(refresh_token);
        }
        if let Some(id_token) = &update.id_token {
            query.push(format!(", {} = ", qi(A::col_id_token())));
            query.push_bind(id_token);
        }
        if let Some(access_token_expires_at) = &update.access_token_expires_at {
            query.push(format!(", {} = ", qi(A::col_access_token_expires_at())));
            query.push_bind(access_token_expires_at);
        }
        if let Some(refresh_token_expires_at) = &update.refresh_token_expires_at {
            query.push(format!(", {} = ", qi(A::col_refresh_token_expires_at())));
            query.push_bind(refresh_token_expires_at);
        }
        if let Some(scope) = &update.scope {
            query.push(format!(", {} = ", qi(A::col_scope())));
            query.push_bind(scope);
        }
        if let Some(password) = &update.password {
            query.push(format!(", {} = ", qi(A::col_password())));
            query.push_bind(password);
        }

        query.push(format!(" WHERE {} = ", qi(A::col_id())));
        query.push_bind(id);
        query.push(" RETURNING *");

        let account = query.build_query_as::<A>().fetch_one(&self.pool).await?;
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = ?",
            qi(A::table()),
            qi(A::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}



