// PostgreSQL UserOps implementation

use super::*;
use async_trait::async_trait;
use chrono::Utc;

use crate::UserOps;
use crate::entity::{
    AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation, AuthInvitationMeta,
    AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta, AuthPasskey,
    AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor, AuthTwoFactorMeta, AuthUser,
    AuthUserMeta, AuthVerification, AuthVerificationMeta,
};
use crate::error::{AuthError, AuthResult};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

#[async_trait]
impl<U, S, A, O, M, I, V, TF, AK, PK> UserOps for PostgresAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
    type User = U;

    async fn create_user(&self, create_user: CreateUser) -> AuthResult<U> {
        let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now();

        let sql = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *",
            qi(U::table()),
            qi(U::col_id()),
            qi(U::col_email()),
            qi(U::col_name()),
            qi(U::col_image()),
            qi(U::col_email_verified()),
            qi(U::col_username()),
            qi(U::col_display_username()),
            qi(U::col_role()),
            qi(U::col_created_at()),
            qi(U::col_updated_at()),
            qi(U::col_metadata()),
        );
        let user = sqlx::query_as::<_, U>(AssertSqlSafe(sql))
            .bind(&id)
            .bind(&create_user.email)
            .bind(&create_user.name)
            .bind(&create_user.image)
            .bind(create_user.email_verified.unwrap_or(false))
            .bind(&create_user.username)
            .bind(&create_user.display_username)
            .bind(&create_user.role)
            .bind(now)
            .bind(now)
            .bind(sqlx::types::Json(
                create_user.metadata.unwrap_or(serde_json::json!({})),
            ))
            .fetch_one(&self.pool)
            .await?;

        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<U>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(U::table()),
            qi(U::col_id())
        );
        let user = sqlx::query_as::<_, U>(AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<U>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(U::table()),
            qi(U::col_email())
        );
        let user = sqlx::query_as::<_, U>(AssertSqlSafe(sql))
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<U>> {
        let sql = format!(
            "SELECT * FROM {} WHERE {} = $1",
            qi(U::table()),
            qi(U::col_username())
        );
        let user = sqlx::query_as::<_, U>(AssertSqlSafe(sql))
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<U> {
        let mut query = sqlx::QueryBuilder::new(format!(
            "UPDATE {} SET {} = NOW()",
            qi(U::table()),
            qi(U::col_updated_at())
        ));
        let mut has_updates = false;

        if let Some(email) = &update.email {
            query.push(format!(", {} = ", qi(U::col_email())));
            query.push_bind(email);
            has_updates = true;
        }
        if let Some(name) = &update.name {
            query.push(format!(", {} = ", qi(U::col_name())));
            query.push_bind(name);
            has_updates = true;
        }
        if let Some(image) = &update.image {
            query.push(format!(", {} = ", qi(U::col_image())));
            query.push_bind(image);
            has_updates = true;
        }
        if let Some(email_verified) = update.email_verified {
            query.push(format!(", {} = ", qi(U::col_email_verified())));
            query.push_bind(email_verified);
            has_updates = true;
        }
        if let Some(username) = &update.username {
            query.push(format!(", {} = ", qi(U::col_username())));
            query.push_bind(username);
            has_updates = true;
        }
        if let Some(display_username) = &update.display_username {
            query.push(format!(", {} = ", qi(U::col_display_username())));
            query.push_bind(display_username);
            has_updates = true;
        }
        if let Some(role) = &update.role {
            query.push(format!(", {} = ", qi(U::col_role())));
            query.push_bind(role);
            has_updates = true;
        }
        if let Some(banned) = update.banned {
            query.push(format!(", {} = ", qi(U::col_banned())));
            query.push_bind(banned);
            has_updates = true;
            // When explicitly unbanning, clear ban_reason and ban_expires
            if !banned {
                query.push(format!(
                    ", {} = NULL, {} = NULL",
                    qi(U::col_ban_reason()),
                    qi(U::col_ban_expires())
                ));
            }
        }
        // Only process ban_reason and ban_expires when we are NOT
        // explicitly unbanning
        if update.banned != Some(false) {
            if let Some(ban_reason) = &update.ban_reason {
                query.push(format!(", {} = ", qi(U::col_ban_reason())));
                query.push_bind(ban_reason);
                has_updates = true;
            }
            if let Some(ban_expires) = update.ban_expires {
                query.push(format!(", {} = ", qi(U::col_ban_expires())));
                query.push_bind(ban_expires);
                has_updates = true;
            }
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            query.push(format!(", {} = ", qi(U::col_two_factor_enabled())));
            query.push_bind(two_factor_enabled);
            has_updates = true;
        }
        if let Some(metadata) = &update.metadata {
            query.push(format!(", {} = ", qi(U::col_metadata())));
            query.push_bind(sqlx::types::Json(metadata.clone()));
            has_updates = true;
        }

        if !has_updates {
            return self
                .get_user_by_id(id)
                .await?
                .ok_or(AuthError::UserNotFound);
        }

        query.push(format!(" WHERE {} = ", qi(U::col_id())));
        query.push_bind(id);
        query.push(" RETURNING *");

        let user = query.build_query_as::<U>().fetch_one(&self.pool).await?;
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = $1",
            qi(U::table()),
            qi(U::col_id())
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<U>, usize)> {
        let limit = params.limit.unwrap_or(100) as i64;
        let offset = params.offset.unwrap_or(0) as i64;

        // Build WHERE clause
        let mut conditions: Vec<String> = Vec::new();
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(search_value) = &params.search_value {
            let field = params.search_field.as_deref().unwrap_or("email");
            let col = qi(match field {
                "name" => U::col_name(),
                _ => U::col_email(),
            });
            let op = params.search_operator.as_deref().unwrap_or("contains");
            let escaped = search_value.replace('%', "\\%").replace('_', "\\_");
            let pattern = match op {
                "starts_with" => format!("{}%", escaped),
                "ends_with" => format!("%{}", escaped),
                _ => format!("%{}%", escaped),
            };
            let idx = bind_values.len() + 1;
            conditions.push(format!("{} ILIKE ${}", col, idx));
            bind_values.push(pattern);
        }

        if let Some(filter_value) = &params.filter_value {
            let field = params.filter_field.as_deref().unwrap_or("email");
            let col = qi(match field {
                "name" => U::col_name(),
                "role" => U::col_role(),
                _ => U::col_email(),
            });
            let op = params.filter_operator.as_deref().unwrap_or("eq");
            let idx = bind_values.len() + 1;
            match op {
                "contains" => {
                    let escaped = filter_value.replace('%', "\\%").replace('_', "\\_");
                    conditions.push(format!("{} ILIKE ${}", col, idx));
                    bind_values.push(format!("%{}%", escaped));
                }
                "ne" => {
                    conditions.push(format!("{} != ${}", col, idx));
                    bind_values.push(filter_value.clone());
                }
                _ => {
                    conditions.push(format!("{} = ${}", col, idx));
                    bind_values.push(filter_value.clone());
                }
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        // Sort
        let order_clause = if let Some(sort_by) = &params.sort_by {
            let col = qi(match sort_by.as_str() {
                "name" => U::col_name(),
                "createdAt" | "created_at" => U::col_created_at(),
                _ => U::col_email(),
            });
            let dir = if params.sort_direction.as_deref() == Some("desc") {
                "DESC"
            } else {
                "ASC"
            };
            format!(" ORDER BY {} {}", col, dir)
        } else {
            format!(" ORDER BY {} DESC", qi(U::col_created_at()))
        };

        // Count query
        let count_sql = format!(
            "SELECT COUNT(*) as count FROM {}{}",
            qi(U::table()),
            where_clause
        );
        let mut count_query = sqlx::query_scalar::<_, i64>(AssertSqlSafe(count_sql));
        for v in &bind_values {
            count_query = count_query.bind(v);
        }
        let total = count_query.fetch_one(&self.pool).await? as usize;

        // Data query
        let limit_idx = bind_values.len() + 1;
        let offset_idx = bind_values.len() + 2;
        let data_sql = format!(
            "SELECT * FROM {}{}{} LIMIT ${} OFFSET ${}",
            qi(U::table()),
            where_clause,
            order_clause,
            limit_idx,
            offset_idx
        );
        let mut data_query = sqlx::query_as::<_, U>(AssertSqlSafe(data_sql));
        for v in &bind_values {
            data_query = data_query.bind(v);
        }
        data_query = data_query.bind(limit).bind(offset);
        let users = data_query.fetch_all(&self.pool).await?;

        Ok((users, total))
    }
}
