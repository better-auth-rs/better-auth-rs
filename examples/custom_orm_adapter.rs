//! Example of creating a custom database adapter for your ORM
//!
//! This example shows how to integrate better-auth with any ORM or database
//! library by implementing the DatabaseAdapter trait.

use async_trait::async_trait;
use better_auth::adapters::DatabaseAdapter;
use better_auth::error::{AuthError, AuthResult};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::types::*;
use better_auth::{AuthConfig, BetterAuth};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Example custom adapter that could wrap any ORM
///
/// This example uses an in-memory store for simplicity, but you would
/// replace this with calls to your actual ORM (Diesel, SeaORM, etc.)
pub struct CustomORMAdapter {
    // In a real implementation, this would be your ORM's connection/client
    // For example:
    // - diesel: Pool<ConnectionManager<PgConnection>>
    // - sea_orm: DatabaseConnection
    // - mongodb: mongodb::Client
    users: Arc<Mutex<HashMap<String, User>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    credentials: Arc<Mutex<HashMap<String, String>>>, // user_id -> password_hash
    email_index: Arc<Mutex<HashMap<String, String>>>, // email -> user_id
}

impl CustomORMAdapter {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            credentials: Arc::new(Mutex::new(HashMap::new())),
            email_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Helper method to simulate ORM operations
    // In real implementation, these would be actual ORM calls
    async fn orm_create_user(&self, user: User) -> Result<User, String> {
        // Example with Diesel:
        // tokio::task::spawn_blocking(move || {
        //     let mut conn = pool.get()?;
        //     diesel::insert_into(users::table)
        //         .values(&user)
        //         .get_result(&mut conn)
        // }).await?

        // Example with SeaORM:
        // let user_model = user::ActiveModel {
        //     id: Set(user.id),
        //     email: Set(user.email),
        //     ...
        // };
        // user_model.insert(&db).await?

        // For this example, we use in-memory storage
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();

        if let Some(ref email) = user.email {
            if email_index.contains_key(email) {
                return Err("Email already exists".to_string());
            }
            email_index.insert(email.clone(), user.id.clone());
        }

        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn orm_find_user_by_email(&self, email: &str) -> Result<Option<User>, String> {
        // Example with Diesel:
        // tokio::task::spawn_blocking(move || {
        //     let mut conn = pool.get()?;
        //     users::table
        //         .filter(users::email.eq(email))
        //         .first(&mut conn)
        //         .optional()
        // }).await?

        // Example with SeaORM:
        // User::find()
        //     .filter(user::Column::Email.eq(email))
        //     .one(&db)
        //     .await?

        let email_index = self.email_index.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(user_id) = email_index.get(email) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn orm_create_session(&self, session: Session) -> Result<Session, String> {
        // Your ORM's create session logic
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session.token.clone(), session.clone());
        Ok(session)
    }

    async fn orm_find_session(&self, token: &str) -> Result<Option<Session>, String> {
        // Your ORM's find session logic
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(token).cloned())
    }
}

#[async_trait]
impl DatabaseAdapter for CustomORMAdapter {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
        let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now();

        let user = User {
            id: id.clone(),
            email: create_user.email.clone(),
            name: create_user.name,
            image: create_user.image,
            email_verified: create_user.email_verified.unwrap_or(false),
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

        self.orm_create_user(user)
            .await
            .map_err(|e| AuthError::database(e))
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        self.orm_find_user_by_email(email)
            .await
            .map_err(|e| AuthError::database(e))
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User> {
        let mut users = self.users.lock().unwrap();

        let user = users
            .get_mut(id)
            .ok_or_else(|| AuthError::database("User not found"))?;

        // Update fields if provided
        if let Some(email) = update.email {
            user.email = Some(email);
        }
        if let Some(name) = update.name {
            user.name = name;
        }
        if let Some(image) = update.image {
            user.image = image;
        }
        if let Some(email_verified) = update.email_verified {
            user.email_verified = email_verified;
        }

        user.updated_at = Utc::now();

        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();

        if let Some(user) = users.remove(id) {
            if let Some(email) = user.email {
                email_index.remove(&email);
            }
        }

        Ok(())
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = Session {
            id: id.clone(),
            token: create_session.token,
            user_id: create_session.user_id,
            expires_at: create_session.expires_at,
            ip_address: create_session.ip_address,
            user_agent: create_session.user_agent,
            created_at: now,
            updated_at: now,
        };

        self.orm_create_session(session)
            .await
            .map_err(|e| AuthError::database(e))
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        self.orm_find_session(token)
            .await
            .map_err(|e| AuthError::database(e))
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        let sessions = self.sessions.lock().unwrap();
        let user_sessions: Vec<Session> = sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect();
        Ok(user_sessions)
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get_mut(token) {
            session.expires_at = expires_at;
            session.updated_at = Utc::now();
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
        sessions.retain(|_, session| session.expires_at > now);
        Ok(initial_count - sessions.len())
    }

    // Account operations (for OAuth)
    async fn create_account(&self, _account: CreateAccount) -> AuthResult<Account> {
        // Implement based on your OAuth needs
        unimplemented!("OAuth accounts not implemented in this example")
    }

    async fn get_account(
        &self,
        _provider: &str,
        _provider_account_id: &str,
    ) -> AuthResult<Option<Account>> {
        Ok(None)
    }

    async fn get_user_accounts(&self, _user_id: &str) -> AuthResult<Vec<Account>> {
        Ok(vec![])
    }

    async fn delete_account(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }

    // Verification token operations
    async fn create_verification(
        &self,
        _verification: CreateVerification,
    ) -> AuthResult<Verification> {
        unimplemented!("Verifications not implemented in this example")
    }

    async fn get_verification(&self, _id: &str) -> AuthResult<Option<Verification>> {
        Ok(None)
    }

    async fn get_verification_by_value(&self, _value: &str) -> AuthResult<Option<Verification>> {
        Ok(None)
    }

    async fn delete_verification(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        Ok(0)
    }

    // Credential operations
    async fn create_credential(&self, user_id: String, password_hash: String) -> AuthResult<()> {
        let mut credentials = self.credentials.lock().unwrap();
        credentials.insert(user_id, password_hash);
        Ok(())
    }

    async fn get_credential(&self, user_id: &str) -> AuthResult<Option<String>> {
        let credentials = self.credentials.lock().unwrap();
        Ok(credentials.get(user_id).cloned())
    }

    async fn update_credential(&self, user_id: &str, password_hash: String) -> AuthResult<()> {
        let mut credentials = self.credentials.lock().unwrap();
        credentials.insert(user_id.to_string(), password_hash);
        Ok(())
    }

    async fn delete_credential(&self, user_id: &str) -> AuthResult<()> {
        let mut credentials = self.credentials.lock().unwrap();
        credentials.remove(user_id);
        Ok(())
    }
}

/// Example: Real-world Diesel adapter skeleton
#[cfg(feature = "diesel-example")]
mod diesel_adapter {
    use super::*;
    use diesel::PgConnection;
    use diesel::prelude::*;
    use diesel::r2d2::{ConnectionManager, Pool};

    pub struct DieselAdapter {
        pool: Pool<ConnectionManager<PgConnection>>,
    }

    impl DieselAdapter {
        pub fn new(database_url: &str) -> Result<Self, diesel::r2d2::Error> {
            let manager = ConnectionManager::<PgConnection>::new(database_url);
            let pool = Pool::builder().max_size(10).build(manager)?;
            Ok(Self { pool })
        }
    }

    #[async_trait]
    impl DatabaseAdapter for DieselAdapter {
        async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
            let pool = self.pool.clone();

            // Run blocking Diesel operation in separate thread
            tokio::task::spawn_blocking(move || {
                let mut conn = pool.get().map_err(|e| AuthError::database(e.to_string()))?;

                // Your Diesel query here
                // diesel::insert_into(users::table)
                //     .values(&new_user)
                //     .get_result(&mut conn)
                //     .map_err(|e| AuthError::database(e.to_string()))

                todo!("Implement actual Diesel query")
            })
            .await
            .map_err(|e| AuthError::database(e.to_string()))?
        }

        // Implement other methods similarly...
        async fn get_user_by_email(&self, _email: &str) -> AuthResult<Option<User>> {
            todo!()
        }

        // ... rest of the trait methods
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Custom ORM Adapter Example");
    println!("{}", "=".repeat(50));

    // Create your custom adapter
    let custom_adapter = CustomORMAdapter::new();

    println!("✅ Custom adapter created");

    // Create better-auth configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    // Build better-auth with your custom adapter
    let auth = BetterAuth::new(config)
        .database(custom_adapter)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;

    println!("🔐 Better-auth initialized with custom adapter");
    println!("📝 Registered plugins: {:?}", auth.plugin_names());

    // Test the custom adapter
    println!("\n🧪 Testing custom adapter...");

    // Test user registration
    let signup_body = serde_json::json!({
        "email": "custom_adapter_user@example.com",
        "password": "test_password_123",
        "name": "Custom Adapter User"
    });

    let mut signup_req = AuthRequest::new(HttpMethod::Post, "/sign-up");
    signup_req.body = Some(signup_body.to_string().into_bytes());
    signup_req
        .headers
        .insert("content-type".to_string(), "application/json".to_string());

    match auth.handle_request(signup_req).await {
        Ok(response) => {
            println!("✅ Registration successful with custom adapter");

            let body_str = String::from_utf8(response.body)?;
            let parsed: serde_json::Value = serde_json::from_str(&body_str)?;

            println!("👤 User: {}", parsed["user"]["email"]);
            println!("🆔 ID: {}", parsed["user"]["id"]);
        }
        Err(e) => {
            println!("❌ Registration failed: {}", e);
        }
    }

    // Test sign in
    println!("\n🧪 Testing sign in...");

    let signin_body = serde_json::json!({
        "email": "custom_adapter_user@example.com",
        "password": "test_password_123"
    });

    let mut signin_req = AuthRequest::new(HttpMethod::Post, "/sign-in");
    signin_req.body = Some(signin_body.to_string().into_bytes());
    signin_req
        .headers
        .insert("content-type".to_string(), "application/json".to_string());

    match auth.handle_request(signin_req).await {
        Ok(response) => {
            println!("✅ Sign in successful with custom adapter");

            let body_str = String::from_utf8(response.body)?;
            let parsed: serde_json::Value = serde_json::from_str(&body_str)?;

            if let Some(token) = parsed["session_token"].as_str() {
                println!("🎫 Session token: {}...", &token[..20.min(token.len())]);
            }
        }
        Err(e) => {
            println!("❌ Sign in failed: {}", e);
        }
    }

    println!("\n🎉 Custom adapter example completed!");
    println!("{}", "=".repeat(50));

    println!("\n💡 Key points for implementing custom adapters:");
    println!("   1. Implement the DatabaseAdapter trait");
    println!("   2. Map your ORM types to better-auth types");
    println!("   3. Handle blocking operations with tokio::task::spawn_blocking");
    println!("   4. Convert ORM errors to AuthError");
    println!("   5. Implement all required methods (users, sessions, credentials)");
    println!("   6. OAuth and verification methods can return unimplemented if not needed");

    println!("\n📚 Adapter implementation tips:");
    println!("   • Diesel: Use spawn_blocking for all queries");
    println!("   • SeaORM: Direct async/await support");
    println!("   • MongoDB: Use the async driver");
    println!("   • Redis: Can be used for session storage");
    println!("   • Custom REST API: Use reqwest for HTTP calls");

    Ok(())
}
