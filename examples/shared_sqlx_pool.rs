//! Example showing how to share an existing SQLx connection pool with better-auth
//! 
//! This demonstrates a real-world scenario where your application already has
//! a database connection pool that you want to share with better-auth.

use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::adapters::SqlxAdapter;
use better_auth::types::{AuthRequest, HttpMethod};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};

/// Your application's custom user profile table
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
struct UserProfile {
    user_id: String,
    bio: Option<String>,
    website: Option<String>,
    location: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Your application's custom posts table
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
struct Post {
    id: String,
    user_id: String,
    title: String,
    content: String,
    published: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Application state that shares the database pool
#[derive(Clone)]
struct AppState {
    /// Shared database pool used by both better-auth and your application
    pool: PgPool,
    /// Better-auth instance
    auth: Arc<BetterAuth>,
}

impl AppState {
    async fn new(database_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        println!("🔧 Creating shared database pool...");
        
        // Create your application's database pool with custom configuration
        let pool = PgPoolOptions::new()
            .max_connections(25)
            .min_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .idle_timeout(std::time::Duration::from_secs(600))
            .test_before_acquire(true)
            .connect(database_url)
            .await?;
        
        println!("✅ Database pool created");
        
        // Run your application's migrations
        Self::run_migrations(&pool).await?;
        
        // Create better-auth configuration
        let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
            .base_url("http://localhost:3000")
            .password_min_length(8);
        
        // Create better-auth instance using YOUR existing pool
        let auth = Arc::new(
            BetterAuth::new(config)
                .database(SqlxAdapter::from_pool(pool.clone())) // Share the pool!
                .plugin(EmailPasswordPlugin::new().enable_signup(true))
                .plugin(SessionManagementPlugin::new())
                .build()
                .await?
        );
        
        println!("🔐 Better-auth initialized with shared pool");
        
        Ok(Self { pool, auth })
    }
    
    /// Run application-specific migrations
    async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
        println!("📝 Running migrations...");
        
        // Create better-auth tables (if not using sqlx migrate)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(255) PRIMARY KEY,
                email VARCHAR(255) UNIQUE,
                name VARCHAR(255),
                image TEXT,
                email_verified BOOLEAN DEFAULT false,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                username VARCHAR(255) UNIQUE,
                display_username VARCHAR(255),
                two_factor_enabled BOOLEAN DEFAULT false,
                role VARCHAR(50),
                banned BOOLEAN DEFAULT false,
                ban_reason TEXT,
                ban_expires TIMESTAMPTZ,
                metadata JSONB DEFAULT '{}'::jsonb
            );
            "#
        )
        .execute(pool)
        .await?;
        
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(255) PRIMARY KEY,
                token VARCHAR(255) UNIQUE NOT NULL,
                user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TIMESTAMPTZ NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#
        )
        .execute(pool)
        .await?;
        
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#
        )
        .execute(pool)
        .await?;
        
        // Create your application-specific tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id VARCHAR(255) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                bio TEXT,
                website VARCHAR(255),
                location VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#
        )
        .execute(pool)
        .await?;
        
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS posts (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title VARCHAR(500) NOT NULL,
                content TEXT NOT NULL,
                published BOOLEAN DEFAULT false,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#
        )
        .execute(pool)
        .await?;
        
        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);").execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);").execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);").execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);").execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_published ON posts(published);").execute(pool).await?;
        
        println!("✅ Migrations completed");
        Ok(())
    }
    
    /// Create or update user profile using the shared pool
    async fn upsert_user_profile(&self, user_id: &str, bio: Option<String>, website: Option<String>, location: Option<String>) -> Result<UserProfile, sqlx::Error> {
        let profile = sqlx::query_as::<_, UserProfile>(
            r#"
            INSERT INTO user_profiles (user_id, bio, website, location)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id) DO UPDATE
            SET bio = EXCLUDED.bio,
                website = EXCLUDED.website,
                location = EXCLUDED.location,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(user_id)
        .bind(bio)
        .bind(website)
        .bind(location)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(profile)
    }
    
    /// Create a post using the shared pool
    async fn create_post(&self, user_id: &str, title: String, content: String) -> Result<Post, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        
        let post = sqlx::query_as::<_, Post>(
            r#"
            INSERT INTO posts (id, user_id, title, content)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#
        )
        .bind(&id)
        .bind(user_id)
        .bind(title)
        .bind(content)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(post)
    }
    
    /// Get user's posts using the shared pool
    async fn get_user_posts(&self, user_id: &str) -> Result<Vec<Post>, sqlx::Error> {
        let posts = sqlx::query_as::<_, Post>(
            "SELECT * FROM posts WHERE user_id = $1 ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(posts)
    }
    
    /// Get user with profile (JOIN query using shared pool)
    async fn get_user_with_profile(&self, user_id: &str) -> Result<serde_json::Value, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT 
                u.id, u.email, u.name, u.created_at as user_created_at,
                p.bio, p.website, p.location
            FROM users u
            LEFT JOIN user_profiles p ON u.id = p.user_id
            WHERE u.id = $1
            "#,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(serde_json::json!({
            "id": row.id,
            "email": row.email,
            "name": row.name,
            "created_at": row.user_created_at,
            "profile": {
                "bio": row.bio,
                "website": row.website,
                "location": row.location
            }
        }))
    }
    
    /// Get database statistics
    async fn get_stats(&self) -> Result<serde_json::Value, sqlx::Error> {
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        
        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool)
            .await?;
        
        let post_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM posts")
            .fetch_one(&self.pool)
            .await?;
        
        Ok(serde_json::json!({
            "users": user_count,
            "sessions": session_count,
            "posts": post_count,
            "pool": {
                "size": self.pool.size(),
                "idle": self.pool.num_idle(),
            }
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Shared SQLx Pool Example");
    println!("{}", "=".repeat(50));
    
    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://better_auth:password@localhost:5432/better_auth".to_string());
    
    // Create application state with shared pool
    let app = AppState::new(&database_url).await?;
    
    println!("\n📊 Initial database stats:");
    let stats = app.get_stats().await?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    
    // Test 1: Register a user through better-auth
    println!("\n🧪 Test 1: Register user through better-auth");
    println!("{}", "-".repeat(40));
    
    let signup_body = serde_json::json!({
        "email": "shared_pool_user@example.com",
        "password": "secure_password_123",
        "name": "Shared Pool User"
    });
    
    let mut signup_req = AuthRequest::new(HttpMethod::Post, "/sign-up");
    signup_req.body = Some(signup_body.to_string().into_bytes());
    signup_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    let user_id = match app.auth.handle_request(signup_req).await {
        Ok(response) => {
            println!("✅ User registered successfully");
            
            let body_str = String::from_utf8(response.body)?;
            let parsed: serde_json::Value = serde_json::from_str(&body_str)?;
            
            let user_id = parsed["user"]["id"].as_str().unwrap().to_string();
            println!("👤 User ID: {}", user_id);
            println!("📧 Email: {}", parsed["user"]["email"]);
            
            user_id
        }
        Err(e) => {
            println!("❌ Registration failed: {}", e);
            return Err(e.into());
        }
    };
    
    // Test 2: Create user profile using the shared pool
    println!("\n🧪 Test 2: Create user profile with shared pool");
    println!("{}", "-".repeat(40));
    
    let profile = app.upsert_user_profile(
        &user_id,
        Some("I love using better-auth with my existing database!".to_string()),
        Some("https://example.com".to_string()),
        Some("San Francisco, CA".to_string())
    ).await?;
    
    println!("✅ Profile created:");
    println!("   Bio: {:?}", profile.bio);
    println!("   Website: {:?}", profile.website);
    println!("   Location: {:?}", profile.location);
    
    // Test 3: Create posts using the shared pool
    println!("\n🧪 Test 3: Create posts with shared pool");
    println!("{}", "-".repeat(40));
    
    let post1 = app.create_post(
        &user_id,
        "My First Post".to_string(),
        "This is my first post using the shared database pool!".to_string()
    ).await?;
    println!("✅ Created post: {}", post1.title);
    
    let post2 = app.create_post(
        &user_id,
        "Better-Auth Integration".to_string(),
        "Sharing a database pool between better-auth and my app is amazing!".to_string()
    ).await?;
    println!("✅ Created post: {}", post2.title);
    
    // Test 4: Query user data with JOIN
    println!("\n🧪 Test 4: Query user with profile (JOIN)");
    println!("{}", "-".repeat(40));
    
    let user_data = app.get_user_with_profile(&user_id).await?;
    println!("✅ User data with profile:");
    println!("{}", serde_json::to_string_pretty(&user_data)?);
    
    // Test 5: Get all user posts
    println!("\n🧪 Test 5: Get user posts");
    println!("{}", "-".repeat(40));
    
    let posts = app.get_user_posts(&user_id).await?;
    println!("✅ Found {} posts:", posts.len());
    for post in &posts {
        println!("   📝 {}: {}", post.title, &post.content[..50.min(post.content.len())]);
    }
    
    // Test 6: Sign in through better-auth
    println!("\n🧪 Test 6: Sign in through better-auth");
    println!("{}", "-".repeat(40));
    
    let signin_body = serde_json::json!({
        "email": "shared_pool_user@example.com",
        "password": "secure_password_123"
    });
    
    let mut signin_req = AuthRequest::new(HttpMethod::Post, "/sign-in");
    signin_req.body = Some(signin_body.to_string().into_bytes());
    signin_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match app.auth.handle_request(signin_req).await {
        Ok(response) => {
            println!("✅ Sign in successful");
            let body_str = String::from_utf8(response.body)?;
            let parsed: serde_json::Value = serde_json::from_str(&body_str)?;
            
            if let Some(token) = parsed["session_token"].as_str() {
                println!("🎫 Session token: {}...", &token[..20.min(token.len())]);
            }
        }
        Err(e) => println!("❌ Sign in failed: {}", e),
    }
    
    // Final stats
    println!("\n📊 Final database stats:");
    let final_stats = app.get_stats().await?;
    println!("{}", serde_json::to_string_pretty(&final_stats)?);
    
    println!("\n🎉 Example completed successfully!");
    println!("{}", "=".repeat(50));
    println!("\n💡 Key takeaways:");
    println!("   1. Single database pool shared between better-auth and your app");
    println!("   2. Better-auth manages auth tables (users, sessions, credentials)");
    println!("   3. Your app manages its own tables (user_profiles, posts)");
    println!("   4. You can JOIN across tables and run complex queries");
    println!("   5. Connection pool is efficiently shared, reducing overhead");
    
    Ok(())
}


