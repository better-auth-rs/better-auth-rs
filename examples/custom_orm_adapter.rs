//! Example of creating a custom database adapter for your ORM
//!
//! This example shows how to integrate better-auth with any ORM or database
//! library by implementing the required operation traits. The DatabaseAdapter
//! trait is automatically implemented when all operation traits are present.

use async_trait::async_trait;
use better_auth::adapters::{
    AccountOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps, UserOps,
    VerificationOps,
};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::types::*;
use better_auth::{AuthConfig, BetterAuth};
use better_auth::{AuthError, AuthResult};
use better_auth_core::types::{Member, Organization};
use better_auth_core::{
    ApiKey, ApiKeyOps, CreateApiKey, CreateTwoFactor, ListUsersParams, TwoFactorOps, UpdateAccount,
    UpdateApiKey,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Example custom adapter that could wrap any ORM
///
/// This example uses an in-memory store for simplicity, but you would
/// replace this with calls to your actual ORM (Diesel, SeaORM, etc.)
#[derive(Default)]
pub struct CustomORMAdapter {
    // In a real implementation, this would be your ORM's connection/client
    // For example:
    // - diesel: Pool<ConnectionManager<PgConnection>>
    // - sea_orm: DatabaseConnection
    // - mongodb: mongodb::Client
    users: Arc<Mutex<HashMap<String, User>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    email_index: Arc<Mutex<HashMap<String, String>>>, // email -> user_id
}

impl CustomORMAdapter {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
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

// ============================================================================
// User Operations
// ============================================================================

#[async_trait]
impl UserOps for CustomORMAdapter {
    type User = User;

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
            .map_err(AuthError::internal)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        self.orm_find_user_by_email(email)
            .await
            .map_err(AuthError::internal)
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        // Stub implementation - would need username index in real implementation
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.username.as_deref() == Some(username))
            .cloned())
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User> {
        let mut users = self.users.lock().unwrap();

        let user = users
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("User not found"))?;

        // Update fields if provided
        if let Some(email) = update.email {
            user.email = Some(email);
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

        if let Some(user) = users.remove(id)
            && let Some(email) = user.email
        {
            email_index.remove(&email);
        }

        Ok(())
    }

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<User>, usize)> {
        // Simple stub implementation - real implementation would handle filtering/sorting
        let users = self.users.lock().unwrap();
        let all_users: Vec<User> = users.values().cloned().collect();
        let total = all_users.len();

        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);

        let paginated: Vec<User> = all_users.into_iter().skip(offset).take(limit).collect();

        Ok((paginated, total))
    }
}

// ============================================================================
// Session Operations
// ============================================================================

#[async_trait]
impl SessionOps for CustomORMAdapter {
    type Session = Session;

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        let id = Uuid::new_v4().to_string();
        let token = format!("session_{}", Uuid::new_v4());
        let now = Utc::now();

        let session = Session {
            id: id.clone(),
            token: token.clone(),
            user_id: create_session.user_id,
            expires_at: create_session.expires_at,
            ip_address: create_session.ip_address,
            user_agent: create_session.user_agent,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active: true,
            created_at: now,
            updated_at: now,
        };

        self.orm_create_session(session)
            .await
            .map_err(AuthError::internal)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        self.orm_find_session(token)
            .await
            .map_err(AuthError::internal)
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

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Session> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(token).ok_or(AuthError::SessionNotFound)?;

        session.active_organization_id = organization_id.map(String::from);
        session.updated_at = Utc::now();

        Ok(session.clone())
    }
}

// ============================================================================
// Account Operations (OAuth)
// ============================================================================

#[async_trait]
impl AccountOps for CustomORMAdapter {
    type Account = Account;

    async fn create_account(&self, _account: CreateAccount) -> AuthResult<Account> {
        // Implement based on your OAuth needs
        Err(AuthError::not_implemented(
            "OAuth accounts not implemented in this example",
        ))
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

    async fn update_account(&self, _id: &str, _update: UpdateAccount) -> AuthResult<Account> {
        Err(AuthError::not_implemented(
            "OAuth accounts not implemented in this example",
        ))
    }

    async fn delete_account(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }
}

// ============================================================================
// Verification Operations
// ============================================================================

#[async_trait]
impl VerificationOps for CustomORMAdapter {
    type Verification = Verification;

    async fn create_verification(
        &self,
        _verification: CreateVerification,
    ) -> AuthResult<Verification> {
        Err(AuthError::not_implemented(
            "Verifications not implemented in this example",
        ))
    }

    async fn get_verification(
        &self,
        _identifier: &str,
        _value: &str,
    ) -> AuthResult<Option<Verification>> {
        Ok(None)
    }

    async fn get_verification_by_value(&self, _value: &str) -> AuthResult<Option<Verification>> {
        Ok(None)
    }

    async fn consume_verification(
        &self,
        _identifier: &str,
        _value: &str,
    ) -> AuthResult<Option<Verification>> {
        Ok(None)
    }

    async fn delete_verification(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        Ok(0)
    }
}

// ============================================================================
// Organization Operations (Stubs)
// ============================================================================

#[async_trait]
impl OrganizationOps for CustomORMAdapter {
    type Organization = Organization;

    async fn create_organization(&self, _org: CreateOrganization) -> AuthResult<Organization> {
        Err(AuthError::not_implemented(
            "Organizations not implemented in this example",
        ))
    }

    async fn get_organization_by_id(&self, _id: &str) -> AuthResult<Option<Organization>> {
        Ok(None)
    }

    async fn get_organization_by_slug(&self, _slug: &str) -> AuthResult<Option<Organization>> {
        Ok(None)
    }

    async fn update_organization(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        Err(AuthError::not_implemented(
            "Organizations not implemented in this example",
        ))
    }

    async fn delete_organization(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }

    async fn list_user_organizations(&self, _user_id: &str) -> AuthResult<Vec<Organization>> {
        Ok(vec![])
    }
}

// ============================================================================
// Member Operations (Stubs)
// ============================================================================

#[async_trait]
impl MemberOps for CustomORMAdapter {
    type Member = Member;

    async fn create_member(&self, _member: CreateMember) -> AuthResult<Member> {
        Err(AuthError::not_implemented(
            "Organization members not implemented in this example",
        ))
    }

    async fn get_member(
        &self,
        _organization_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<Member>> {
        Ok(None)
    }

    async fn get_member_by_id(&self, _id: &str) -> AuthResult<Option<Member>> {
        Ok(None)
    }

    async fn update_member_role(&self, _member_id: &str, _role: &str) -> AuthResult<Member> {
        Err(AuthError::not_implemented(
            "Organization members not implemented in this example",
        ))
    }

    async fn delete_member(&self, _member_id: &str) -> AuthResult<()> {
        Ok(())
    }

    async fn list_organization_members(&self, _organization_id: &str) -> AuthResult<Vec<Member>> {
        Ok(vec![])
    }

    async fn count_organization_members(&self, _organization_id: &str) -> AuthResult<usize> {
        Ok(0)
    }

    async fn count_organization_owners(&self, _organization_id: &str) -> AuthResult<usize> {
        Ok(0)
    }
}

// ============================================================================
// Invitation Operations (Stubs)
// ============================================================================

#[async_trait]
impl InvitationOps for CustomORMAdapter {
    type Invitation = Invitation;

    async fn create_invitation(&self, _invitation: CreateInvitation) -> AuthResult<Invitation> {
        Err(AuthError::not_implemented(
            "Invitations not implemented in this example",
        ))
    }

    async fn get_invitation_by_id(&self, _id: &str) -> AuthResult<Option<Invitation>> {
        Ok(None)
    }

    async fn get_pending_invitation(
        &self,
        _organization_id: &str,
        _email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Ok(None)
    }

    async fn update_invitation_status(
        &self,
        _id: &str,
        _status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        Err(AuthError::not_implemented(
            "Invitations not implemented in this example",
        ))
    }

    async fn list_organization_invitations(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        Ok(vec![])
    }

    async fn list_user_invitations(&self, _email: &str) -> AuthResult<Vec<Invitation>> {
        Ok(vec![])
    }
}

// ============================================================================
// Two-Factor Operations (Stubs)
// ============================================================================

#[async_trait]
impl TwoFactorOps for CustomORMAdapter {
    type TwoFactor = TwoFactor;

    async fn create_two_factor(&self, _two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        Err(AuthError::not_implemented(
            "Two-factor authentication not implemented in this example",
        ))
    }

    async fn get_two_factor_by_user_id(&self, _user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(None)
    }

    async fn update_two_factor_backup_codes(
        &self,
        _user_id: &str,
        _backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        Err(AuthError::not_implemented(
            "Two-factor authentication not implemented in this example",
        ))
    }

    async fn delete_two_factor(&self, _user_id: &str) -> AuthResult<()> {
        Ok(())
    }
}

// ============================================================================
// API Key Operations (Stubs)
// ============================================================================

#[async_trait]
impl ApiKeyOps for CustomORMAdapter {
    type ApiKey = ApiKey;

    async fn create_api_key(&self, _input: CreateApiKey) -> AuthResult<ApiKey> {
        Err(AuthError::not_implemented(
            "API keys not implemented in this example",
        ))
    }

    async fn get_api_key_by_id(&self, _id: &str) -> AuthResult<Option<ApiKey>> {
        Ok(None)
    }

    async fn get_api_key_by_hash(&self, _hash: &str) -> AuthResult<Option<ApiKey>> {
        Ok(None)
    }

    async fn list_api_keys_by_user(&self, _user_id: &str) -> AuthResult<Vec<ApiKey>> {
        Ok(vec![])
    }

    async fn update_api_key(&self, _id: &str, _update: UpdateApiKey) -> AuthResult<ApiKey> {
        Err(AuthError::not_implemented(
            "API keys not implemented in this example",
        ))
    }

    async fn delete_api_key(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        Ok(0)
    }
}

// ============================================================================
// Passkey Operations (Stubs)
// ============================================================================

#[async_trait]
impl PasskeyOps for CustomORMAdapter {
    type Passkey = Passkey;

    async fn create_passkey(&self, _input: CreatePasskey) -> AuthResult<Passkey> {
        Err(AuthError::not_implemented(
            "Passkeys not implemented in this example",
        ))
    }

    async fn get_passkey_by_id(&self, _id: &str) -> AuthResult<Option<Passkey>> {
        Ok(None)
    }

    async fn get_passkey_by_credential_id(
        &self,
        _credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        Ok(None)
    }

    async fn list_passkeys_by_user(&self, _user_id: &str) -> AuthResult<Vec<Passkey>> {
        Ok(vec![])
    }

    async fn update_passkey_counter(&self, _id: &str, _counter: u64) -> AuthResult<Passkey> {
        Err(AuthError::not_implemented(
            "Passkeys not implemented in this example",
        ))
    }

    async fn update_passkey_name(&self, _id: &str, _name: &str) -> AuthResult<Passkey> {
        Err(AuthError::not_implemented(
            "Passkeys not implemented in this example",
        ))
    }

    async fn delete_passkey(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }
}

// ============================================================================
// Example Usage
// ============================================================================

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
    let auth: BetterAuth<CustomORMAdapter> = BetterAuth::<CustomORMAdapter>::new(config)
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
    println!("   1. Implement the operation traits (UserOps, SessionOps, etc.)");
    println!("   2. DatabaseAdapter is automatically implemented via blanket impl");
    println!("   3. Map your ORM types to better-auth types");
    println!("   4. Handle blocking operations with tokio::task::spawn_blocking");
    println!("   5. Convert ORM errors to AuthError using AuthError::internal()");
    println!("   6. Implement required traits fully (User, Session)");
    println!("   7. Stub optional traits (Organization, TwoFactor, etc.) if not needed");

    println!("\n📚 Adapter implementation tips:");
    println!("   • Diesel: Use spawn_blocking for all queries");
    println!("   • SeaORM: Direct async/await support");
    println!("   • MongoDB: Use the async driver");
    println!("   • Redis: Can be used for session storage");
    println!("   • Custom REST API: Use reqwest for HTTP calls");

    println!("\n🔍 Trait structure:");
    println!("   • UserOps - User CRUD operations");
    println!("   • SessionOps - Session management");
    println!("   • AccountOps - OAuth account linking");
    println!("   • VerificationOps - Email/phone verification");
    println!("   • OrganizationOps - Organization management");
    println!("   • MemberOps - Organization membership");
    println!("   • InvitationOps - Organization invitations");
    println!("   • TwoFactorOps - 2FA management");
    println!("   • ApiKeyOps - API key management");
    println!("   • PasskeyOps - WebAuthn passkey management");

    Ok(())
}
