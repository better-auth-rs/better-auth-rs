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
        AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
        AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
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
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type User = U;

        async fn create_user(&self, create_user: CreateUser) -> AuthResult<U> {
            let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let now = Utc::now();

            let user = sqlx::query_as::<_, U>(
                r#"
                INSERT INTO users (id, email, name, image, email_verified, created_at, updated_at, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
                "#,
            )
            .bind(&id)
            .bind(&create_user.email)
            .bind(&create_user.name)
            .bind(&create_user.image)
            .bind(false)
            .bind(now)
            .bind(now)
            .bind(sqlx::types::Json(create_user.metadata.unwrap_or(serde_json::json!({}))))
            .fetch_one(&self.pool)
            .await?;

            Ok(user)
        }

        async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<U>> {
            let user = sqlx::query_as::<_, U>("SELECT * FROM users WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(user)
        }

        async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<U>> {
            let user = sqlx::query_as::<_, U>("SELECT * FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;
            Ok(user)
        }

        async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<U>> {
            let user = sqlx::query_as::<_, U>("SELECT * FROM users WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
            Ok(user)
        }

        async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<U> {
            let mut query = sqlx::QueryBuilder::new("UPDATE users SET updated_at = NOW()");
            let mut has_updates = false;

            if let Some(email) = &update.email {
                query.push(", email = ");
                query.push_bind(email);
                has_updates = true;
            }
            if let Some(name) = &update.name {
                query.push(", name = ");
                query.push_bind(name);
                has_updates = true;
            }
            if let Some(image) = &update.image {
                query.push(", image = ");
                query.push_bind(image);
                has_updates = true;
            }
            if let Some(email_verified) = update.email_verified {
                query.push(", email_verified = ");
                query.push_bind(email_verified);
                has_updates = true;
            }
            if let Some(metadata) = &update.metadata {
                query.push(", metadata = ");
                query.push_bind(sqlx::types::Json(metadata.clone()));
                has_updates = true;
            }

            if !has_updates {
                return self
                    .get_user_by_id(id)
                    .await?
                    .ok_or(AuthError::UserNotFound);
            }

            query.push(" WHERE id = ");
            query.push_bind(id);
            query.push(" RETURNING *");

            let user = query.build_query_as::<U>().fetch_one(&self.pool).await?;
            Ok(user)
        }

        async fn delete_user(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM users WHERE id = $1")
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
                let col = match field {
                    "name" => "name",
                    _ => "email",
                };
                let op = params.search_operator.as_deref().unwrap_or("contains");
                let pattern = match op {
                    "starts_with" => format!("{}%", search_value),
                    "ends_with" => format!("%{}", search_value),
                    _ => format!("%{}%", search_value),
                };
                let idx = bind_values.len() + 1;
                conditions.push(format!("{} ILIKE ${}", col, idx));
                bind_values.push(pattern);
            }

            if let Some(filter_value) = &params.filter_value {
                let field = params.filter_field.as_deref().unwrap_or("email");
                let col = match field {
                    "name" => "name",
                    "role" => "role",
                    _ => "email",
                };
                let op = params.filter_operator.as_deref().unwrap_or("eq");
                let idx = bind_values.len() + 1;
                match op {
                    "contains" => {
                        conditions.push(format!("{} ILIKE ${}", col, idx));
                        bind_values.push(format!("%{}%", filter_value));
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
                let col = match sort_by.as_str() {
                    "name" => "name",
                    "createdAt" | "created_at" => "created_at",
                    _ => "email",
                };
                let dir = if params.sort_direction.as_deref() == Some("desc") {
                    "DESC"
                } else {
                    "ASC"
                };
                format!(" ORDER BY {} {}", col, dir)
            } else {
                " ORDER BY created_at DESC".to_string()
            };

            // Count query
            let count_idx = bind_values.len() + 1;
            let _count_idx = count_idx; // suppress unused warning
            let count_sql = format!("SELECT COUNT(*) as count FROM users{}", where_clause);
            let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
            for v in &bind_values {
                count_query = count_query.bind(v);
            }
            let total = count_query.fetch_one(&self.pool).await? as usize;

            // Data query
            let limit_idx = bind_values.len() + 1;
            let offset_idx = bind_values.len() + 2;
            let data_sql = format!(
                "SELECT * FROM users{}{} LIMIT ${} OFFSET ${}",
                where_clause, order_clause, limit_idx, offset_idx
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
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Session = S;

        async fn create_session(&self, create_session: CreateSession) -> AuthResult<S> {
            let id = Uuid::new_v4().to_string();
            let token = format!("session_{}", Uuid::new_v4());
            let now = Utc::now();

            let session = sqlx::query_as::<_, S>(
                r#"
                INSERT INTO sessions (id, user_id, token, expires_at, created_at, ip_address, user_agent, active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
                "#,
            )
            .bind(&id)
            .bind(&create_session.user_id)
            .bind(&token)
            .bind(create_session.expires_at)
            .bind(now)
            .bind(&create_session.ip_address)
            .bind(&create_session.user_agent)
            .bind(true)
            .fetch_one(&self.pool)
            .await?;

            Ok(session)
        }

        async fn get_session(&self, token: &str) -> AuthResult<Option<S>> {
            let session =
                sqlx::query_as::<_, S>("SELECT * FROM sessions WHERE token = $1 AND active = true")
                    .bind(token)
                    .fetch_optional(&self.pool)
                    .await?;
            Ok(session)
        }

        async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S>> {
            let sessions = sqlx::query_as::<_, S>(
                "SELECT * FROM sessions WHERE user_id = $1 AND active = true ORDER BY created_at DESC",
            )
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
            sqlx::query("UPDATE sessions SET expires_at = $1 WHERE token = $2 AND active = true")
                .bind(expires_at)
                .bind(token)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn delete_session(&self, token: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM sessions WHERE token = $1")
                .bind(token)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn delete_expired_sessions(&self) -> AuthResult<usize> {
            let result =
                sqlx::query("DELETE FROM sessions WHERE expires_at < NOW() OR active = false")
                    .execute(&self.pool)
                    .await?;
            Ok(result.rows_affected() as usize)
        }

        async fn update_session_active_organization(
            &self,
            token: &str,
            organization_id: Option<&str>,
        ) -> AuthResult<S> {
            let session = sqlx::query_as::<_, S>(
                "UPDATE sessions SET active_organization_id = $1, updated_at = NOW() WHERE token = $2 AND active = true RETURNING *",
            )
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
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Account = A;

        async fn create_account(&self, create_account: CreateAccount) -> AuthResult<A> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let account = sqlx::query_as::<_, A>(
                r#"
                INSERT INTO accounts (id, account_id, provider_id, user_id, access_token, refresh_token, id_token, access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING *
                "#,
            )
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
            let account = sqlx::query_as::<_, A>(
                "SELECT * FROM accounts WHERE provider_id = $1 AND account_id = $2",
            )
            .bind(provider)
            .bind(provider_account_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(account)
        }

        async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<A>> {
            let accounts = sqlx::query_as::<_, A>(
                "SELECT * FROM accounts WHERE user_id = $1 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(accounts)
        }

        async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<A> {
            let mut query = sqlx::QueryBuilder::new("UPDATE accounts SET updated_at = NOW()");

            if let Some(access_token) = &update.access_token {
                query.push(", access_token = ");
                query.push_bind(access_token);
            }
            if let Some(refresh_token) = &update.refresh_token {
                query.push(", refresh_token = ");
                query.push_bind(refresh_token);
            }
            if let Some(id_token) = &update.id_token {
                query.push(", id_token = ");
                query.push_bind(id_token);
            }
            if let Some(access_token_expires_at) = &update.access_token_expires_at {
                query.push(", access_token_expires_at = ");
                query.push_bind(access_token_expires_at);
            }
            if let Some(refresh_token_expires_at) = &update.refresh_token_expires_at {
                query.push(", refresh_token_expires_at = ");
                query.push_bind(refresh_token_expires_at);
            }
            if let Some(scope) = &update.scope {
                query.push(", scope = ");
                query.push_bind(scope);
            }

            query.push(" WHERE id = ");
            query.push_bind(id);
            query.push(" RETURNING *");

            let account = query.build_query_as::<A>().fetch_one(&self.pool).await?;
            Ok(account)
        }

        async fn delete_account(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    // -- VerificationOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> VerificationOps
        for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
    where
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Verification = V;

        async fn create_verification(
            &self,
            create_verification: CreateVerification,
        ) -> AuthResult<V> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let verification = sqlx::query_as::<_, V>(
                r#"
                INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
                "#,
            )
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
            let verification = sqlx::query_as::<_, V>(
                "SELECT * FROM verifications WHERE identifier = $1 AND value = $2 AND expires_at > NOW()",
            )
            .bind(identifier)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
            Ok(verification)
        }

        async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<V>> {
            let verification = sqlx::query_as::<_, V>(
                "SELECT * FROM verifications WHERE value = $1 AND expires_at > NOW()",
            )
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
            Ok(verification)
        }

        async fn get_verification_by_identifier(&self, identifier: &str) -> AuthResult<Option<V>> {
            let verification = sqlx::query_as::<_, V>(
                "SELECT * FROM verifications WHERE identifier = $1 AND expires_at > NOW()",
            )
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
            let verification = sqlx::query_as::<_, V>(
                "DELETE FROM verifications WHERE id IN (
                    SELECT id FROM verifications
                    WHERE identifier = $1 AND value = $2 AND expires_at > NOW()
                    ORDER BY created_at DESC
                    LIMIT 1
                ) RETURNING *",
            )
            .bind(identifier)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
            Ok(verification)
        }

        async fn delete_verification(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM verifications WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn delete_expired_verifications(&self) -> AuthResult<usize> {
            let result = sqlx::query("DELETE FROM verifications WHERE expires_at < NOW()")
                .execute(&self.pool)
                .await?;
            Ok(result.rows_affected() as usize)
        }
    }

    // -- OrganizationOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> OrganizationOps
        for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
    where
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Organization = O;

        async fn create_organization(&self, create_org: CreateOrganization) -> AuthResult<O> {
            let id = create_org.id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let now = Utc::now();

            let organization = sqlx::query_as::<_, O>(
                r#"
                INSERT INTO organization (id, name, slug, logo, metadata, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING *
                "#,
            )
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
            let organization = sqlx::query_as::<_, O>("SELECT * FROM organization WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(organization)
        }

        async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<O>> {
            let organization = sqlx::query_as::<_, O>("SELECT * FROM organization WHERE slug = $1")
                .bind(slug)
                .fetch_optional(&self.pool)
                .await?;
            Ok(organization)
        }

        async fn update_organization(&self, id: &str, update: UpdateOrganization) -> AuthResult<O> {
            let mut query = sqlx::QueryBuilder::new("UPDATE organization SET updated_at = NOW()");

            if let Some(name) = &update.name {
                query.push(", name = ");
                query.push_bind(name);
            }
            if let Some(slug) = &update.slug {
                query.push(", slug = ");
                query.push_bind(slug);
            }
            if let Some(logo) = &update.logo {
                query.push(", logo = ");
                query.push_bind(logo);
            }
            if let Some(metadata) = &update.metadata {
                query.push(", metadata = ");
                query.push_bind(sqlx::types::Json(metadata.clone()));
            }

            query.push(" WHERE id = ");
            query.push_bind(id);
            query.push(" RETURNING *");

            let organization = query.build_query_as::<O>().fetch_one(&self.pool).await?;
            Ok(organization)
        }

        async fn delete_organization(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM organization WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<O>> {
            let organizations = sqlx::query_as::<_, O>(
                r#"
                SELECT o.*
                FROM organization o
                INNER JOIN member m ON o.id = m.organization_id
                WHERE m.user_id = $1
                ORDER BY o.created_at DESC
                "#,
            )
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
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Member = M;

        async fn create_member(&self, create_member: CreateMember) -> AuthResult<M> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let member = sqlx::query_as::<_, M>(
                r#"
                INSERT INTO member (id, organization_id, user_id, role, created_at)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
                "#,
            )
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
            let member = sqlx::query_as::<_, M>(
                "SELECT * FROM member WHERE organization_id = $1 AND user_id = $2",
            )
            .bind(organization_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(member)
        }

        async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<M>> {
            let member = sqlx::query_as::<_, M>("SELECT * FROM member WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(member)
        }

        async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<M> {
            let member =
                sqlx::query_as::<_, M>("UPDATE member SET role = $1 WHERE id = $2 RETURNING *")
                    .bind(role)
                    .bind(member_id)
                    .fetch_one(&self.pool)
                    .await?;
            Ok(member)
        }

        async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM member WHERE id = $1")
                .bind(member_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<M>> {
            let members = sqlx::query_as::<_, M>(
                "SELECT * FROM member WHERE organization_id = $1 ORDER BY created_at ASC",
            )
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(members)
        }

        async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
            let count: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM member WHERE organization_id = $1")
                    .bind(organization_id)
                    .fetch_one(&self.pool)
                    .await?;
            Ok(count.0 as usize)
        }

        async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
            let count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM member WHERE organization_id = $1 AND role = 'owner'",
            )
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
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Invitation = I;

        async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<I> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let invitation = sqlx::query_as::<_, I>(
                r#"
                INSERT INTO invitation (id, organization_id, email, role, status, inviter_id, expires_at, created_at)
                VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
                RETURNING *
                "#,
            )
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
            let invitation = sqlx::query_as::<_, I>("SELECT * FROM invitation WHERE id = $1")
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
            let invitation = sqlx::query_as::<_, I>(
                "SELECT * FROM invitation WHERE organization_id = $1 AND LOWER(email) = LOWER($2) AND status = 'pending'",
            )
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
            let invitation = sqlx::query_as::<_, I>(
                "UPDATE invitation SET status = $1 WHERE id = $2 RETURNING *",
            )
            .bind(status.to_string())
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
            Ok(invitation)
        }

        async fn list_organization_invitations(&self, organization_id: &str) -> AuthResult<Vec<I>> {
            let invitations = sqlx::query_as::<_, I>(
                "SELECT * FROM invitation WHERE organization_id = $1 ORDER BY created_at DESC",
            )
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(invitations)
        }

        async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<I>> {
            let invitations = sqlx::query_as::<_, I>(
                "SELECT * FROM invitation WHERE LOWER(email) = LOWER($1) AND status = 'pending' AND expires_at > NOW() ORDER BY created_at DESC",
            )
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
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type TwoFactor = TF;

        async fn create_two_factor(&self, create: CreateTwoFactor) -> AuthResult<TF> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let two_factor = sqlx::query_as::<_, TF>(
                r#"
                INSERT INTO two_factor (id, secret, backup_codes, user_id, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
                "#,
            )
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
            let two_factor = sqlx::query_as::<_, TF>("SELECT * FROM two_factor WHERE user_id = $1")
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
            let two_factor = sqlx::query_as::<_, TF>(
                "UPDATE two_factor SET backup_codes = $1, updated_at = NOW() WHERE user_id = $2 RETURNING *",
            )
            .bind(backup_codes)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;
            Ok(two_factor)
        }

        async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM two_factor WHERE user_id = $1")
                .bind(user_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    // -- ApiKeyOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> ApiKeyOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
    where
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type ApiKey = AK;

        async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<AK> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let api_key = sqlx::query_as::<_, AK>(
                r#"
                INSERT INTO api_keys (id, name, start, prefix, key, user_id, refill_interval, refill_amount,
                    enabled, rate_limit_enabled, rate_limit_time_window, rate_limit_max, remaining,
                    expires_at, created_at, updated_at, permissions, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                    $14::timestamptz, $15, $16, $17, $18)
                RETURNING *
                "#,
            )
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
            let api_key = sqlx::query_as::<_, AK>("SELECT * FROM api_keys WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(api_key)
        }

        async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<AK>> {
            let api_key = sqlx::query_as::<_, AK>("SELECT * FROM api_keys WHERE key = $1")
                .bind(hash)
                .fetch_optional(&self.pool)
                .await?;
            Ok(api_key)
        }

        async fn list_api_keys_by_user(&self, user_id: &str) -> AuthResult<Vec<AK>> {
            let keys = sqlx::query_as::<_, AK>(
                "SELECT * FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(keys)
        }

        async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<AK> {
            let mut query = sqlx::QueryBuilder::new("UPDATE api_keys SET updated_at = NOW()");

            if let Some(name) = &update.name {
                query.push(", name = ");
                query.push_bind(name);
            }
            if let Some(enabled) = update.enabled {
                query.push(", enabled = ");
                query.push_bind(enabled);
            }
            if let Some(remaining) = update.remaining {
                query.push(", remaining = ");
                query.push_bind(remaining);
            }
            if let Some(rate_limit_enabled) = update.rate_limit_enabled {
                query.push(", rate_limit_enabled = ");
                query.push_bind(rate_limit_enabled);
            }
            if let Some(rate_limit_time_window) = update.rate_limit_time_window {
                query.push(", rate_limit_time_window = ");
                query.push_bind(rate_limit_time_window);
            }
            if let Some(rate_limit_max) = update.rate_limit_max {
                query.push(", rate_limit_max = ");
                query.push_bind(rate_limit_max);
            }
            if let Some(refill_interval) = update.refill_interval {
                query.push(", refill_interval = ");
                query.push_bind(refill_interval);
            }
            if let Some(refill_amount) = update.refill_amount {
                query.push(", refill_amount = ");
                query.push_bind(refill_amount);
            }
            if let Some(permissions) = &update.permissions {
                query.push(", permissions = ");
                query.push_bind(permissions);
            }
            if let Some(metadata) = &update.metadata {
                query.push(", metadata = ");
                query.push_bind(metadata);
            }

            query.push(" WHERE id = ");
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
            sqlx::query("DELETE FROM api_keys WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    // -- PasskeyOps --

    #[async_trait]
    impl<U, S, A, O, M, I, V, TF, AK, PK> PasskeyOps for SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK>
    where
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
        TF: AuthTwoFactor + SqlxEntity,
        AK: AuthApiKey + SqlxEntity,
        PK: AuthPasskey + SqlxEntity,
    {
        type Passkey = PK;

        async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<PK> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();
            let counter = i64::try_from(input.counter)
                .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

            let passkey = sqlx::query_as::<_, PK>(
                r#"
                INSERT INTO passkeys (id, name, public_key, user_id, credential_id, counter, device_type, backed_up, transports, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING *
                "#,
            )
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
            let passkey = sqlx::query_as::<_, PK>("SELECT * FROM passkeys WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(passkey)
        }

        async fn get_passkey_by_credential_id(
            &self,
            credential_id: &str,
        ) -> AuthResult<Option<PK>> {
            let passkey =
                sqlx::query_as::<_, PK>("SELECT * FROM passkeys WHERE credential_id = $1")
                    .bind(credential_id)
                    .fetch_optional(&self.pool)
                    .await?;
            Ok(passkey)
        }

        async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<PK>> {
            let passkeys = sqlx::query_as::<_, PK>(
                "SELECT * FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(passkeys)
        }

        async fn update_passkey_counter(&self, id: &str, counter: u64) -> AuthResult<PK> {
            let counter = i64::try_from(counter)
                .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
            let passkey = sqlx::query_as::<_, PK>(
                "UPDATE passkeys SET counter = $2 WHERE id = $1 RETURNING *",
            )
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
            let passkey =
                sqlx::query_as::<_, PK>("UPDATE passkeys SET name = $2 WHERE id = $1 RETURNING *")
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
            sqlx::query("DELETE FROM passkeys WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }
}

#[cfg(feature = "sqlx-postgres")]
pub use sqlx_adapter::{SqlxAdapter, SqlxEntity};
