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
use crate::types::{CreateOrganization, UpdateOrganization};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

// -- OrganizationOps --

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> OrganizationOps
    for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type Organization = O;

    async fn create_organization(&self, create_org: CreateOrganization) -> AuthResult<O> {
        let id = create_org.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
            qi(O::table()),
            qi(O::col_id()),
            qi(O::col_name()),
            qi(O::col_slug()),
            qi(O::col_logo()),
            qi(O::col_metadata()),
            qi(O::col_created_at()),
            qi(O::col_updated_at()),
        );
        let organization = sqlx::query_as::<_, O>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_org.name)
            .bind(&create_org.slug)
            .bind(&create_org.logo)
            .bind(sqlx::types::Json(
                create_org.metadata.unwrap_or(serde_json::json!({})),
            ))
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        Ok(organization)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<O>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(O::table()),
            qi(O::col_id())
        );
        let organization = sqlx::query_as::<_, O>(AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(organization)
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<O>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(O::table()),
            qi(O::col_slug())
        );
        let organization = sqlx::query_as::<_, O>(AssertSqlSafe(sql))
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;
        Ok(organization)
    }

    async fn update_organization(&self, id: &str, update: UpdateOrganization) -> AuthResult<O> {
        let mut query = sqlx::QueryBuilder::new(format!(
            "UPDATE {} SET {} = NOW()",
            qi(O::table()),
            qi(O::col_updated_at())
        ));

        if let Some(name) = &update.name {
            query.push(format!(", {} = ", qi(O::col_name())));
            query.push_bind(name);
        }
        if let Some(slug) = &update.slug {
            query.push(format!(", {} = ", qi(O::col_slug())));
            query.push_bind(slug);
        }
        if let Some(logo) = &update.logo {
            query.push(format!(", {} = ", qi(O::col_logo())));
            query.push_bind(logo);
        }
        if let Some(metadata) = &update.metadata {
            query.push(format!(", {} = ", qi(O::col_metadata())));
            query.push_bind(sqlx::types::Json(metadata.clone()));
        }

        query.push(format!(" WHERE {} = ", qi(O::col_id())));
        query.push_bind(id);
        query.push(" RETURNING *");

        let organization = query.build_query_as::<O>().fetch_one(&self.pool).await?;
        Ok(organization)
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = $1",
            qi(O::table()),
            qi(O::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<O>> {
        let sql = format!(
            "SELECT o.* FROM {} o INNER JOIN {} m ON o.{} = m.{} WHERE m.{} = $1 ORDER BY o.{} DESC",
            qi(O::table()),
            qi(M::table()),
            qi(O::col_id()),
            qi(M::col_organization_id()),
            qi(M::col_user_id()),
            qi(O::col_created_at()),
        );
        let organizations = sqlx::query_as::<_, O>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(organizations)
    }
}
