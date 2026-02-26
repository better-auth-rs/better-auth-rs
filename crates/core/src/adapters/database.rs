pub use super::traits::{
    AccountOps, ApiKeyOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};

/// Database adapter trait for persistence.
///
/// Combines all entity-specific operation traits. Any type that implements
/// all sub-traits (`UserOps`, `SessionOps`, etc.) automatically implements
/// `DatabaseAdapter` via the blanket impl.
///
/// Use the sub-traits directly when you only need a subset of operations
/// (e.g., a plugin that only accesses users and sessions).
pub trait DatabaseAdapter:
    UserOps
    + SessionOps
    + AccountOps
    + VerificationOps
    + OrganizationOps
    + MemberOps
    + InvitationOps
    + TwoFactorOps
    + ApiKeyOps
    + PasskeyOps
{
}

impl<T> DatabaseAdapter for T where
    T: UserOps
        + SessionOps
        + AccountOps
        + VerificationOps
        + OrganizationOps
        + MemberOps
        + InvitationOps
        + TwoFactorOps
        + ApiKeyOps
        + PasskeyOps
{
}

#[cfg(feature = "sqlx-postgres")]
pub mod sqlx_adapter {
    use super::*;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};

    use crate::entity::{
        AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation,
        AuthInvitationMeta, AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta,
        AuthPasskey, AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor,
        AuthTwoFactorMeta, AuthUser, AuthUserMeta, AuthVerification, AuthVerificationMeta,
    };
    use crate::error::{AuthError, AuthResult};
    use crate::types::{
        Account, ApiKey, CreateAccount, CreateApiKey, CreateInvitation, CreateMember,
        CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
        CreateVerification, Invitation, InvitationStatus, ListUsersParams, Member, Organization,
        Passkey, Session, TwoFactor, UpdateAccount, UpdateApiKey, UpdateOrganization, UpdateUser,
        User, Verification,
    };
    use sqlx::PgPool;
    use sqlx::postgres::PgRow;
    use std::marker::PhantomData;
    use uuid::Uuid;

    /// Quote a SQL identifier with double quotes for PostgreSQL.
    ///
    /// This prevents issues with reserved words (e.g. `user`, `key`, `order`)
    /// and ensures correct identifier handling regardless of the names returned
    /// by `Auth*Meta` traits.
    #[inline]
    fn qi(ident: &str) -> String {
        format!("\"{}\"", ident.replace('"', "\"\""))
    }

    /// Blanket trait combining all bounds needed for SQLx-based entity types.
    ///
    /// Any type that implements `sqlx::FromRow` plus the standard marker traits
    /// automatically satisfies this bound. Custom entity types just need
    /// `#[derive(sqlx::FromRow)]` (or a manual `FromRow` impl) alongside
    /// their `Auth*` derive.
    pub trait SqlxEntity:
        for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Clone + 'static
    {
    }

    impl<T> SqlxEntity for T where
        T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Clone + 'static
    {
    }

    type SqlxAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK> = (U, S, A, O, M, I, V, TF, AK, PK);

    /// PostgreSQL database adapter via SQLx.
    ///
    /// Generic over entity types — use default type parameters for the built-in
    /// types, or supply your own custom structs that implement `Auth*` + `sqlx::FromRow`.
    pub struct SqlxAdapter<
        U = User,
        S = Session,
        A = Account,
        O = Organization,
        M = Member,
        I = Invitation,
        V = Verification,
        TF = TwoFactor,
        AK = ApiKey,
        PK = Passkey,
    > {
        pool: PgPool,
        #[allow(clippy::type_complexity)]
        _phantom: PhantomData<SqlxAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK>>,
    }

    /// Constructors for the default (built-in) entity types.
    impl SqlxAdapter {
        pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
            let pool = PgPool::connect(database_url).await?;
            Ok(Self {
                pool,
                _phantom: PhantomData,
            })
        }

        pub async fn with_config(
            database_url: &str,
            config: PoolConfig,
        ) -> Result<Self, sqlx::Error> {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.max_connections)
                .min_connections(config.min_connections)
                .acquire_timeout(config.acquire_timeout)
                .idle_timeout(config.idle_timeout)
                .max_lifetime(config.max_lifetime)
                .connect(database_url)
                .await?;
            Ok(Self {
                pool,
                _phantom: PhantomData,
            })
        }
    }

    /// Methods available for all type parameterizations.
    impl<U, S, A, O, M, I, V, TF, AK, PK> SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK> {
        pub fn from_pool(pool: PgPool) -> Self {
            Self {
                pool,
                _phantom: PhantomData,
            }
        }

        pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        }

        pub fn pool_stats(&self) -> PoolStats {
            PoolStats {
                size: self.pool.size(),
                idle: self.pool.num_idle(),
            }
        }

        pub async fn close(&self) {
            self.pool.close().await;
        }
    }

    #[derive(Debug, Clone)]
    pub struct PoolConfig {
        pub max_connections: u32,
        pub min_connections: u32,
        pub acquire_timeout: std::time::Duration,
        pub idle_timeout: Option<std::time::Duration>,
        pub max_lifetime: Option<std::time::Duration>,
    }

    impl Default for PoolConfig {
        fn default() -> Self {
            Self {
                max_connections: 10,
                min_connections: 0,
                acquire_timeout: std::time::Duration::from_secs(30),
                idle_timeout: Some(std::time::Duration::from_secs(600)),
                max_lifetime: Some(std::time::Duration::from_secs(1800)),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct PoolStats {
        pub size: u32,
        pub idle: usize,
    }

    // -- UserOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> UserOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
            let user = sqlx::query_as::<_, U>(&sql)
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
            let user = sqlx::query_as::<_, U>(&sql)
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
            let user = sqlx::query_as::<_, U>(&sql)
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
            let user = sqlx::query_as::<_, U>(&sql)
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
            // explicitly unbanning.  When banned == Some(false) the block
            // above already emits `ban_reason = NULL, ban_expires = NULL`,
            // so applying these fields again would overwrite the NULLs.
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
            sqlx::query(&sql).bind(id).execute(&self.pool).await?;
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
            let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
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
            let mut data_query = sqlx::query_as::<_, U>(&data_sql);
            for v in &bind_values {
                data_query = data_query.bind(v);
            }
            data_query = data_query.bind(limit).bind(offset);
            let users = data_query.fetch_all(&self.pool).await?;

            Ok((users, total))
        }
    }

    // -- SessionOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> SessionOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
        type Session = S;

        async fn create_session(&self, create_session: CreateSession) -> AuthResult<S> {
            let id = Uuid::new_v4().to_string();
            let token = format!("session_{}", Uuid::new_v4());
            let now = Utc::now();

            let sql = format!(
                "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
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
            let session = sqlx::query_as::<_, S>(&sql)
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
                "SELECT * FROM {} WHERE {} = $1 AND {} = true",
                qi(S::table()),
                qi(S::col_token()),
                qi(S::col_active())
            );
            let session = sqlx::query_as::<_, S>(&sql)
                .bind(token)
                .fetch_optional(&self.pool)
                .await?;
            Ok(session)
        }

        async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1 AND {} = true ORDER BY {} DESC",
                qi(S::table()),
                qi(S::col_user_id()),
                qi(S::col_active()),
                qi(S::col_created_at())
            );
            let sessions = sqlx::query_as::<_, S>(&sql)
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
                "UPDATE {} SET {} = $1 WHERE {} = $2 AND {} = true",
                qi(S::table()),
                qi(S::col_expires_at()),
                qi(S::col_token()),
                qi(S::col_active())
            );
            sqlx::query(&sql)
                .bind(expires_at)
                .bind(token)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn delete_session(&self, token: &str) -> AuthResult<()> {
            let sql = format!(
                "DELETE FROM {} WHERE {} = $1",
                qi(S::table()),
                qi(S::col_token())
            );
            sqlx::query(&sql).bind(token).execute(&self.pool).await?;
            Ok(())
        }

        async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
            let sql = format!(
                "DELETE FROM {} WHERE {} = $1",
                qi(S::table()),
                qi(S::col_user_id())
            );
            sqlx::query(&sql).bind(user_id).execute(&self.pool).await?;
            Ok(())
        }

        async fn delete_expired_sessions(&self) -> AuthResult<usize> {
            let sql = format!(
                "DELETE FROM {} WHERE {} < NOW() OR {} = false",
                qi(S::table()),
                qi(S::col_expires_at()),
                qi(S::col_active())
            );
            let result = sqlx::query(&sql).execute(&self.pool).await?;
            Ok(result.rows_affected() as usize)
        }

        async fn update_session_active_organization(
            &self,
            token: &str,
            organization_id: Option<&str>,
        ) -> AuthResult<S> {
            let sql = format!(
                "UPDATE {} SET {} = $1, {} = NOW() WHERE {} = $2 AND {} = true RETURNING *",
                qi(S::table()),
                qi(S::col_active_organization_id()),
                qi(S::col_updated_at()),
                qi(S::col_token()),
                qi(S::col_active())
            );
            let session = sqlx::query_as::<_, S>(&sql)
                .bind(organization_id)
                .bind(token)
                .fetch_one(&self.pool)
                .await?;
            Ok(session)
        }
    }

    // -- AccountOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> AccountOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
        type Account = A;

        async fn create_account(&self, create_account: CreateAccount) -> AuthResult<A> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let sql = format!(
                "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *",
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
            let account = sqlx::query_as::<_, A>(&sql)
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
                "SELECT * FROM {} WHERE {} = $1 AND {} = $2",
                qi(A::table()),
                qi(A::col_provider_id()),
                qi(A::col_account_id())
            );
            let account = sqlx::query_as::<_, A>(&sql)
                .bind(provider)
                .bind(provider_account_id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(account)
        }

        async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<A>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1 ORDER BY {} DESC",
                qi(A::table()),
                qi(A::col_user_id()),
                qi(A::col_created_at())
            );
            let accounts = sqlx::query_as::<_, A>(&sql)
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?;
            Ok(accounts)
        }

        async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<A> {
            let mut query = sqlx::QueryBuilder::new(format!(
                "UPDATE {} SET {} = NOW()",
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
                "DELETE FROM {} WHERE {} = $1",
                qi(A::table()),
                qi(A::col_id())
            );
            sqlx::query(&sql).bind(id).execute(&self.pool).await?;
            Ok(())
        }
    }

    // -- VerificationOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> VerificationOps
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
        type Verification = V;

        async fn create_verification(
            &self,
            create_verification: CreateVerification,
        ) -> AuthResult<V> {
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
            let verification = sqlx::query_as::<_, V>(&sql)
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
            let verification = sqlx::query_as::<_, V>(&sql)
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
            let verification = sqlx::query_as::<_, V>(&sql)
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
            let verification = sqlx::query_as::<_, V>(&sql)
                .bind(identifier)
                .fetch_optional(&self.pool)
                .await?;
            Ok(verification)
        }

        async fn consume_verification(
            &self,
            identifier: &str,
            value: &str,
        ) -> AuthResult<Option<V>> {
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
            let verification = sqlx::query_as::<_, V>(&sql)
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
            sqlx::query(&sql).bind(id).execute(&self.pool).await?;
            Ok(())
        }

        async fn delete_expired_verifications(&self) -> AuthResult<usize> {
            let sql = format!(
                "DELETE FROM {} WHERE {} < NOW()",
                qi(V::table()),
                qi(V::col_expires_at())
            );
            let result = sqlx::query(&sql).execute(&self.pool).await?;
            Ok(result.rows_affected() as usize)
        }
    }

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
            let organization = sqlx::query_as::<_, O>(&sql)
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
            let organization = sqlx::query_as::<_, O>(&sql)
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
            let organization = sqlx::query_as::<_, O>(&sql)
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
            sqlx::query(&sql).bind(id).execute(&self.pool).await?;
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
            let organizations = sqlx::query_as::<_, O>(&sql)
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?;
            Ok(organizations)
        }
    }

    // -- MemberOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> MemberOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
        type Member = M;

        async fn create_member(&self, create_member: CreateMember) -> AuthResult<M> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let sql = format!(
                "INSERT INTO {} ({}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5) RETURNING *",
                qi(M::table()),
                qi(M::col_id()),
                qi(M::col_organization_id()),
                qi(M::col_user_id()),
                qi(M::col_role()),
                qi(M::col_created_at()),
            );
            let member = sqlx::query_as::<_, M>(&sql)
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
                "SELECT * FROM {} WHERE {} = $1 AND {} = $2",
                qi(M::table()),
                qi(M::col_organization_id()),
                qi(M::col_user_id())
            );
            let member = sqlx::query_as::<_, M>(&sql)
                .bind(organization_id)
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(member)
        }

        async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<M>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1",
                qi(M::table()),
                qi(M::col_id())
            );
            let member = sqlx::query_as::<_, M>(&sql)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(member)
        }

        async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<M> {
            let sql = format!(
                "UPDATE {} SET {} = $1 WHERE {} = $2 RETURNING *",
                qi(M::table()),
                qi(M::col_role()),
                qi(M::col_id())
            );
            let member = sqlx::query_as::<_, M>(&sql)
                .bind(role)
                .bind(member_id)
                .fetch_one(&self.pool)
                .await?;
            Ok(member)
        }

        async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
            let sql = format!(
                "DELETE FROM {} WHERE {} = $1",
                qi(M::table()),
                qi(M::col_id())
            );
            sqlx::query(&sql)
                .bind(member_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<M>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1 ORDER BY {} ASC",
                qi(M::table()),
                qi(M::col_organization_id()),
                qi(M::col_created_at())
            );
            let members = sqlx::query_as::<_, M>(&sql)
                .bind(organization_id)
                .fetch_all(&self.pool)
                .await?;
            Ok(members)
        }

        async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
            let sql = format!(
                "SELECT COUNT(*) FROM {} WHERE {} = $1",
                qi(M::table()),
                qi(M::col_organization_id())
            );
            let count: (i64,) = sqlx::query_as(&sql)
                .bind(organization_id)
                .fetch_one(&self.pool)
                .await?;
            Ok(count.0 as usize)
        }

        async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
            let sql = format!(
                "SELECT COUNT(*) FROM {} WHERE {} = $1 AND {} = 'owner'",
                qi(M::table()),
                qi(M::col_organization_id()),
                qi(M::col_role())
            );
            let count: (i64,) = sqlx::query_as(&sql)
                .bind(organization_id)
                .fetch_one(&self.pool)
                .await?;
            Ok(count.0 as usize)
        }
    }

    // -- InvitationOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> InvitationOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
        type Invitation = I;

        async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<I> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let sql = format!(
                "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}) \
                 VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7) RETURNING *",
                qi(I::table()),
                qi(I::col_id()),
                qi(I::col_organization_id()),
                qi(I::col_email()),
                qi(I::col_role()),
                qi(I::col_status()),
                qi(I::col_inviter_id()),
                qi(I::col_expires_at()),
                qi(I::col_created_at()),
            );
            let invitation = sqlx::query_as::<_, I>(&sql)
                .bind(&id)
                .bind(&create_inv.organization_id)
                .bind(&create_inv.email)
                .bind(&create_inv.role)
                .bind(&create_inv.inviter_id)
                .bind(create_inv.expires_at)
                .bind(now)
                .fetch_one(&self.pool)
                .await?;

            Ok(invitation)
        }

        async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<I>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1",
                qi(I::table()),
                qi(I::col_id())
            );
            let invitation = sqlx::query_as::<_, I>(&sql)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(invitation)
        }

        async fn get_pending_invitation(
            &self,
            organization_id: &str,
            email: &str,
        ) -> AuthResult<Option<I>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1 AND LOWER({}) = LOWER($2) AND {} = 'pending'",
                qi(I::table()),
                qi(I::col_organization_id()),
                qi(I::col_email()),
                qi(I::col_status())
            );
            let invitation = sqlx::query_as::<_, I>(&sql)
                .bind(organization_id)
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;
            Ok(invitation)
        }

        async fn update_invitation_status(
            &self,
            id: &str,
            status: InvitationStatus,
        ) -> AuthResult<I> {
            let sql = format!(
                "UPDATE {} SET {} = $1 WHERE {} = $2 RETURNING *",
                qi(I::table()),
                qi(I::col_status()),
                qi(I::col_id())
            );
            let invitation = sqlx::query_as::<_, I>(&sql)
                .bind(status.to_string())
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
            Ok(invitation)
        }

        async fn list_organization_invitations(&self, organization_id: &str) -> AuthResult<Vec<I>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1 ORDER BY {} DESC",
                qi(I::table()),
                qi(I::col_organization_id()),
                qi(I::col_created_at())
            );
            let invitations = sqlx::query_as::<_, I>(&sql)
                .bind(organization_id)
                .fetch_all(&self.pool)
                .await?;
            Ok(invitations)
        }

        async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<I>> {
            let sql = format!(
                "SELECT * FROM {} WHERE LOWER({}) = LOWER($1) AND {} = 'pending' AND {} > NOW() ORDER BY {} DESC",
                qi(I::table()),
                qi(I::col_email()),
                qi(I::col_status()),
                qi(I::col_expires_at()),
                qi(I::col_created_at())
            );
            let invitations = sqlx::query_as::<_, I>(&sql)
                .bind(email)
                .fetch_all(&self.pool)
                .await?;
            Ok(invitations)
        }
    }

    // -- TwoFactorOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> TwoFactorOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
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
            let two_factor = sqlx::query_as::<_, TF>(&sql)
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
            let two_factor = sqlx::query_as::<_, TF>(&sql)
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
            let two_factor = sqlx::query_as::<_, TF>(&sql)
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
            sqlx::query(&sql).bind(user_id).execute(&self.pool).await?;
            Ok(())
        }
    }

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
            let api_key = sqlx::query_as::<_, AK>(&sql)
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
            let api_key = sqlx::query_as::<_, AK>(&sql)
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
            let api_key = sqlx::query_as::<_, AK>(&sql)
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
            let keys = sqlx::query_as::<_, AK>(&sql)
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
            sqlx::query(&sql).bind(id).execute(&self.pool).await?;
            Ok(())
        }

        async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
            let sql = format!(
                "DELETE FROM {} WHERE {} IS NOT NULL AND {}::timestamptz < NOW()",
                qi(AK::table()),
                qi(AK::col_expires_at()),
                qi(AK::col_expires_at()),
            );
            let result = sqlx::query(&sql).execute(&self.pool).await?;
            Ok(result.rows_affected() as usize)
        }
    }

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
            let passkey = sqlx::query_as::<_, PK>(&sql)
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
            let passkey = sqlx::query_as::<_, PK>(&sql)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(passkey)
        }

        async fn get_passkey_by_credential_id(
            &self,
            credential_id: &str,
        ) -> AuthResult<Option<PK>> {
            let sql = format!(
                "SELECT * FROM {} WHERE {} = $1",
                qi(PK::table()),
                qi(PK::col_credential_id())
            );
            let passkey = sqlx::query_as::<_, PK>(&sql)
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
            let passkeys = sqlx::query_as::<_, PK>(&sql)
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
            let passkey = sqlx::query_as::<_, PK>(&sql)
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
            let passkey = sqlx::query_as::<_, PK>(&sql)
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
            sqlx::query(&sql).bind(id).execute(&self.pool).await?;
            Ok(())
        }
    }
}

#[cfg(feature = "sqlx-postgres")]
pub use sqlx_adapter::{SqlxAdapter, SqlxEntity};
