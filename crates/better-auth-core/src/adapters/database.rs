use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
    AuthVerification,
};
use crate::error::AuthResult;
use crate::types::{
    CreateAccount, CreateInvitation, CreateMember, CreateOrganization, CreateSession, CreateUser,
    CreateVerification, InvitationStatus, UpdateOrganization, UpdateUser,
};

/// Database adapter trait for persistence.
///
/// Associated types allow users to define their own entity structs.
/// Use the default types (`User`, `Session`, etc.) or implement entity traits
/// on custom structs via `#[derive(AuthUser)]` etc.
#[async_trait]
pub trait DatabaseAdapter: Send + Sync + 'static {
    type User: AuthUser;
    type Session: AuthSession;
    type Account: AuthAccount;
    type Organization: AuthOrganization;
    type Member: AuthMember;
    type Invitation: AuthInvitation;
    type Verification: AuthVerification;

    // User operations
    async fn create_user(&self, user: CreateUser) -> AuthResult<Self::User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<Self::User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<Self::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<Self::User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<Self::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;

    // Session operations
    async fn create_session(&self, session: CreateSession) -> AuthResult<Self::Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<Self::Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Self::Session>>;
    async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>)
    -> AuthResult<()>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;

    // Account operations (for OAuth)
    async fn create_account(&self, account: CreateAccount) -> AuthResult<Self::Account>;
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Self::Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Self::Account>>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;

    // Verification token operations
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<Self::Verification>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>>;
    async fn get_verification_by_value(
        &self,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;

    // Organization operations
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Self::Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Self::Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Self::Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Self::Organization>;
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Self::Organization>>;

    // Member operations
    async fn create_member(&self, member: CreateMember) -> AuthResult<Self::Member>;
    async fn get_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<Self::Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Self::Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Self::Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Self::Member>>;
    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize>;
    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize>;

    // Invitation operations
    async fn create_invitation(&self, invitation: CreateInvitation)
    -> AuthResult<Self::Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Self::Invitation>>;
    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Self::Invitation>>;
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Self::Invitation>;
    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Self::Invitation>>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Self::Invitation>>;

    // Session organization support
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Self::Session>;
}

#[cfg(feature = "sqlx-postgres")]
pub mod sqlx_adapter {
    use super::*;
    use crate::error::AuthError;
    use crate::types::{Account, Invitation, Member, Organization, Session, User, Verification};
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

    /// PostgreSQL database adapter via SQLx.
    ///
    /// Generic over entity types — use default type parameters for the built-in
    /// types, or supply your own custom structs that implement `Auth*` + `sqlx::FromRow`.
    ///
    /// ```rust,ignore
    /// // Using built-in types (no turbofish needed):
    /// let adapter = SqlxAdapter::new("postgresql://...").await?;
    ///
    /// // Using custom types via type alias:
    /// type AppDb = SqlxAdapter<AppUser, AppSession, AppAccount,
    ///     AppOrg, AppMember, AppInvitation, AppVerification>;
    /// let adapter = AppDb::from_pool(pool);
    /// ```
    pub struct SqlxAdapter<
        U = User,
        S = Session,
        A = Account,
        O = Organization,
        M = Member,
        I = Invitation,
        V = Verification,
    > {
        pool: PgPool,
        _phantom: PhantomData<(U, S, A, O, M, I, V)>,
    }

    /// Constructors for the default (built-in) entity types.
    /// Use `from_pool()` with a type alias for custom type parameterizations.
    impl SqlxAdapter {
        pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
            let pool = PgPool::connect(database_url).await?;
            Ok(Self {
                pool,
                _phantom: PhantomData,
            })
        }

        /// Create adapter with custom pool configuration
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

    /// Methods available for all type parameterizations (including custom types).
    impl<U, S, A, O, M, I, V> SqlxAdapter<U, S, A, O, M, I, V> {
        pub fn from_pool(pool: PgPool) -> Self {
            Self {
                pool,
                _phantom: PhantomData,
            }
        }

        /// Test database connection
        pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        }

        /// Get connection pool statistics
        pub fn pool_stats(&self) -> PoolStats {
            PoolStats {
                size: self.pool.size(),
                idle: self.pool.num_idle(),
            }
        }

        /// Close the connection pool
        pub async fn close(&self) {
            self.pool.close().await;
        }
    }

    /// Database connection pool configuration
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
                idle_timeout: Some(std::time::Duration::from_secs(600)), // 10 minutes
                max_lifetime: Some(std::time::Duration::from_secs(1800)), // 30 minutes
            }
        }
    }

    /// Connection pool statistics
    #[derive(Debug, Clone)]
    pub struct PoolStats {
        pub size: u32,
        pub idle: usize,
    }

    #[async_trait]
    impl<U, S, A, O, M, I, V> DatabaseAdapter for SqlxAdapter<U, S, A, O, M, I, V>
    where
        U: AuthUser + SqlxEntity,
        S: AuthSession + SqlxEntity,
        A: AuthAccount + SqlxEntity,
        O: AuthOrganization + SqlxEntity,
        M: AuthMember + SqlxEntity,
        I: AuthInvitation + SqlxEntity,
        V: AuthVerification + SqlxEntity,
    {
        type User = U;
        type Session = S;
        type Account = A;
        type Organization = O;
        type Member = M;
        type Invitation = I;
        type Verification = V;

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
            .bind(&now)
            .bind(&now)
            .bind(sqlx::types::Json(create_user.metadata.unwrap_or_default()))
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
            .bind(&create_session.expires_at)
            .bind(&now)
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
                r#"
                SELECT * FROM sessions
                WHERE user_id = $1 AND active = true
                ORDER BY created_at DESC
                "#,
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
                .bind(&expires_at)
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
            .bind(&create_account.access_token_expires_at)
            .bind(&create_account.refresh_token_expires_at)
            .bind(&create_account.scope)
            .bind(&create_account.password)
            .bind(&now)
            .bind(&now)
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

        async fn delete_account(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

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
            .bind(&create_verification.expires_at)
            .bind(&now)
            .bind(&now)
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

        // Organization operations
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
            .bind(&now)
            .bind(&now)
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

        // Member operations
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
            .bind(&now)
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

        // Invitation operations
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
            .bind(&create_inv.expires_at)
            .bind(&now)
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

        // Session organization support
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
}

#[cfg(feature = "sqlx-postgres")]
pub use sqlx_adapter::{SqlxAdapter, SqlxEntity};
