use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::types::{User, Session, Account, Verification, CreateUser, UpdateUser, CreateSession, CreateAccount, CreateVerification};
use crate::error::{AuthResult, AuthError};

/// Database adapter trait for persistence
#[async_trait]
pub trait DatabaseAdapter: Send + Sync {
    // User operations
    async fn create_user(&self, user: CreateUser) -> AuthResult<User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    
    // Session operations
    async fn create_session(&self, session: CreateSession) -> AuthResult<Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>>;
    async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>) -> AuthResult<()>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;
    
    // Account operations (for OAuth)
    async fn create_account(&self, account: CreateAccount) -> AuthResult<Account>;
    async fn get_account(&self, provider: &str, provider_account_id: &str) -> AuthResult<Option<Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
    
    // Verification token operations
    async fn create_verification(&self, verification: CreateVerification) -> AuthResult<Verification>;
    async fn get_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<Verification>>;
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

/// In-memory database adapter for testing and development
pub struct MemoryDatabaseAdapter {
    users: Arc<Mutex<HashMap<String, User>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    verifications: Arc<Mutex<HashMap<String, Verification>>>,
    email_index: Arc<Mutex<HashMap<String, String>>>, // email -> user_id
}

impl MemoryDatabaseAdapter {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            verifications: Arc::new(Mutex::new(HashMap::new())),
            email_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryDatabaseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DatabaseAdapter for MemoryDatabaseAdapter {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        
        let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        
        // Check if email already exists
        if let Some(email) = &create_user.email {
            if email_index.contains_key(email) {
                return Err(AuthError::config("Email already exists"));
            }
        }
        
        let now = Utc::now();
        let user = User {
            id: id.clone(),
            name: create_user.name,
            email: create_user.email.clone(),
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: now,
            updated_at: now,
            username: create_user.username,
            display_username: create_user.display_username,
            two_factor_enabled: false,
            role: create_user.role,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: create_user.metadata.unwrap_or_default(),
        };
        
        users.insert(id.clone(), user.clone());
        
        if let Some(email) = &create_user.email {
            email_index.insert(email.clone(), id);
        }
        
        Ok(user)
    }
    
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }
    
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        let email_index = self.email_index.lock().unwrap();
        let users = self.users.lock().unwrap();
        
        if let Some(user_id) = email_index.get(email) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }
    
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        
        let user = users.get_mut(id).ok_or(AuthError::UserNotFound)?;
        
        // Update email index if email changed
        if let Some(new_email) = &update.email {
            if let Some(old_email) = &user.email {
                email_index.remove(old_email);
            }
            email_index.insert(new_email.clone(), id.to_string());
            user.email = Some(new_email.clone());
        }
        
        if let Some(name) = update.name {
            user.name = Some(name);
        }
        
        if let Some(image) = update.image {
            user.image = Some(image);
        }
        
        if let Some(email_verified) = update.email_verified {
            user.email_verified = email_verified;
        }
        
        if let Some(username) = update.username {
            user.username = Some(username);
        }
        
        if let Some(display_username) = update.display_username {
            user.display_username = Some(display_username);
        }
        
        if let Some(role) = update.role {
            user.role = Some(role);
        }
        
        if let Some(banned) = update.banned {
            user.banned = banned;
        }
        
        if let Some(ban_reason) = update.ban_reason {
            user.ban_reason = Some(ban_reason);
        }
        
        if let Some(ban_expires) = update.ban_expires {
            user.ban_expires = Some(ban_expires);
        }
        
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            user.two_factor_enabled = two_factor_enabled;
        }
        
        if let Some(metadata) = update.metadata {
            user.metadata = metadata;
        }
        
        user.updated_at = Utc::now();
        
        Ok(user.clone())
    }
    
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        
        if let Some(user) = users.remove(id) {
            if let Some(email) = &user.email {
                email_index.remove(email);
            }
        }
        
        Ok(())
    }
    
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        
        let token = format!("session_{}", Uuid::new_v4());
        let now = Utc::now();
        let session = Session {
            id: Uuid::new_v4().to_string(),
            expires_at: create_session.expires_at,
            token: token.clone(),
            created_at: now,
            updated_at: now,
            ip_address: create_session.ip_address,
            user_agent: create_session.user_agent,
            user_id: create_session.user_id,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active: true,
        };
        
        sessions.insert(token, session.clone());
        Ok(session)
    }
    
    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(token).cloned())
    }
    
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.values()
            .filter(|session| session.user_id == user_id && session.active)
            .cloned()
            .collect())
    }
    
    async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(token) {
            session.expires_at = expires_at;
        }
        Ok(())
    }
    
    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(token);
        Ok(())
    }
    
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| session.user_id != user_id);
        Ok(())
    }
    
    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Utc::now();
        let initial_count = sessions.len();
        
        sessions.retain(|_, session| session.expires_at > now && session.active);
        
        Ok(initial_count - sessions.len())
    }
    
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
        let mut accounts = self.accounts.lock().unwrap();
        
        let now = Utc::now();
        let account = Account {
            id: Uuid::new_v4().to_string(),
            account_id: create_account.account_id,
            provider_id: create_account.provider_id,
            user_id: create_account.user_id,
            access_token: create_account.access_token,
            refresh_token: create_account.refresh_token,
            id_token: create_account.id_token,
            access_token_expires_at: create_account.access_token_expires_at,
            refresh_token_expires_at: create_account.refresh_token_expires_at,
            scope: create_account.scope,
            password: create_account.password,
            created_at: now,
            updated_at: now,
        };
        
        accounts.insert(account.id.clone(), account.clone());
        Ok(account)
    }
    
    async fn get_account(&self, provider: &str, provider_account_id: &str) -> AuthResult<Option<Account>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts.values()
            .find(|acc| acc.provider_id == provider && acc.account_id == provider_account_id)
            .cloned())
    }
    
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts.values()
            .filter(|acc| acc.user_id == user_id)
            .cloned()
            .collect())
    }
    
    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        accounts.remove(id);
        Ok(())
    }
    
    async fn create_verification(&self, create_verification: CreateVerification) -> AuthResult<Verification> {
        let mut verifications = self.verifications.lock().unwrap();
        
        let now = Utc::now();
        let verification = Verification {
            id: Uuid::new_v4().to_string(),
            identifier: create_verification.identifier,
            value: create_verification.value.clone(),
            expires_at: create_verification.expires_at,
            created_at: now,
            updated_at: now,
        };
        
        verifications.insert(verification.id.clone(), verification.clone());
        Ok(verification)
    }
    
    async fn get_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<Verification>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        
        Ok(verifications.values()
            .find(|v| v.identifier == identifier && v.value == value && v.expires_at > now)
            .cloned())
    }
    
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        
        Ok(verifications.values()
            .find(|v| v.value == value && v.expires_at > now)
            .cloned())
    }
    
    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let mut verifications = self.verifications.lock().unwrap();
        verifications.remove(id);
        Ok(())
    }
    
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let mut verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        let initial_count = verifications.len();
        
        verifications.retain(|_, verification| verification.expires_at > now);
        
        Ok(initial_count - verifications.len())
    }
}


#[cfg(feature = "sqlx-postgres")]
pub mod sqlx_adapter {
    use super::*;
    use sqlx::PgPool;
    
    pub struct SqlxAdapter {
        pool: PgPool,
    }
    
    impl SqlxAdapter {
        pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
            let pool = PgPool::connect(database_url).await?;
            Ok(Self { pool })
        }
        
        /// Create adapter with custom pool configuration
        pub async fn with_config(database_url: &str, config: PoolConfig) -> Result<Self, sqlx::Error> {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.max_connections)
                .min_connections(config.min_connections)
                .acquire_timeout(config.acquire_timeout)
                .idle_timeout(config.idle_timeout)
                .max_lifetime(config.max_lifetime)
                .connect(database_url)
                .await?;
            Ok(Self { pool })
        }
        
        pub fn from_pool(pool: PgPool) -> Self {
            Self { pool }
        }
        
        /// Test database connection
        pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
            sqlx::query("SELECT 1")
                .execute(&self.pool)
                .await?;
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
    impl DatabaseAdapter for SqlxAdapter {
        async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
            let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let now = Utc::now();
            
            let user = sqlx::query_as::<_, User>(
                r#"
                INSERT INTO users (id, email, name, image, email_verified, created_at, updated_at, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, email, name, image, email_verified, created_at, updated_at, metadata
                "#
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
        
        async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, email, name, image, email_verified, created_at, updated_at, metadata
                FROM users WHERE id = $1
                "#
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            
            Ok(user)
        }
        
        async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, email, name, image, email_verified, created_at, updated_at, metadata
                FROM users WHERE email = $1
                "#
            )
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
            
            Ok(user)
        }
        
        async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User> {
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
                // If no updates, just return the current user
                return self.get_user_by_id(id).await?.ok_or(AuthError::UserNotFound);
            }
            
            query.push(" WHERE id = ");
            query.push_bind(id);
            query.push(" RETURNING id, email, name, image, email_verified, created_at, updated_at, metadata");
            
            let user = query
                .build_query_as::<User>()
                .fetch_one(&self.pool)
                .await?;
                
            Ok(user)
        }
        
        async fn delete_user(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            
            Ok(())
        }
        
        async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
            let id = Uuid::new_v4().to_string();
            let token = format!("session_{}", Uuid::new_v4());
            let now = Utc::now();
            
            let session = sqlx::query_as::<_, Session>(
                r#"
                INSERT INTO sessions (id, user_id, token, expires_at, created_at, ip_address, user_agent, active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, user_id, token, expires_at, created_at, ip_address, user_agent, active
                "#
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
        
        async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
            let session = sqlx::query_as::<_, Session>(
                r#"
                SELECT id, user_id, token, expires_at, created_at, updated_at, ip_address, user_agent, active, impersonated_by, active_organization_id
                FROM sessions 
                WHERE token = $1 AND active = true
                "#
            )
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
            
            Ok(session)
        }
        
        async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
            let sessions = sqlx::query_as::<_, Session>(
                r#"
                SELECT id, user_id, token, expires_at, created_at, updated_at, ip_address, user_agent, active, impersonated_by, active_organization_id
                FROM sessions 
                WHERE user_id = $1 AND active = true
                ORDER BY created_at DESC
                "#
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
            
            Ok(sessions)
        }
        
        async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>) -> AuthResult<()> {
            sqlx::query(
                r#"
                UPDATE sessions 
                SET expires_at = $1 
                WHERE token = $2 AND active = true
                "#
            )
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
            let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW() OR active = false")
                .execute(&self.pool)
                .await?;
            
            Ok(result.rows_affected() as usize)
        }
        
        async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();
            
            let account = sqlx::query_as::<_, Account>(
                r#"
                INSERT INTO accounts (id, account_id, provider_id, user_id, access_token, refresh_token, id_token, access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING *
                "#
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
        
        async fn get_account(&self, provider: &str, provider_account_id: &str) -> AuthResult<Option<Account>> {
            let account = sqlx::query_as::<_, Account>(
                r#"
                SELECT *
                FROM accounts 
                WHERE provider_id = $1 AND account_id = $2
                "#
            )
            .bind(provider)
            .bind(provider_account_id)
            .fetch_optional(&self.pool)
            .await?;
            
            Ok(account)
        }
        
        async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
            let accounts = sqlx::query_as::<_, Account>(
                r#"
                SELECT id, user_id, provider, provider_account_id, access_token, refresh_token, expires_at, token_type, scope, created_at
                FROM accounts 
                WHERE user_id = $1
                ORDER BY created_at DESC
                "#
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
        
        async fn create_verification(&self, create_verification: CreateVerification) -> AuthResult<Verification> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();
            
            let verification = sqlx::query_as::<_, Verification>(
                r#"
                INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
                "#
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
        
        async fn get_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<Verification>> {
            let verification = sqlx::query_as::<_, Verification>(
                r#"
                SELECT *
                FROM verifications 
                WHERE identifier = $1 AND value = $2 AND expires_at > NOW()
                "#
            )
            .bind(identifier)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
            
            Ok(verification)
        }
        
        async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
            let verification = sqlx::query_as::<_, Verification>(
                r#"
                SELECT *
                FROM verifications 
                WHERE value = $1 AND expires_at > NOW()
                "#
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
    }
}

#[cfg(feature = "sqlx-postgres")]
pub use sqlx_adapter::SqlxAdapter; 