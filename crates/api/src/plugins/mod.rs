pub mod account_management;
pub mod admin;
pub mod api_key;
pub mod email_password;
pub mod email_verification;
pub mod helpers;
pub mod oauth;
pub mod organization;
pub mod passkey;
pub mod password_management;
pub mod session_management;
pub mod two_factor;
pub mod user_management;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusResponse {
    status: bool,
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
    use better_auth_core::config::AuthConfig;
    use better_auth_core::{
        AuthContext, AuthRequest, CreateSession, CreateUser, HttpMethod, Session, User,
    };
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    pub fn create_test_config() -> AuthConfig {
        AuthConfig::new("test-secret-key-at-least-32-chars-long")
    }

    pub fn create_test_context() -> AuthContext<MemoryDatabaseAdapter> {
        create_test_context_with_config(create_test_config())
    }

    pub fn create_test_context_with_config(
        config: AuthConfig,
    ) -> AuthContext<MemoryDatabaseAdapter> {
        let config = Arc::new(config);
        let database = Arc::new(MemoryDatabaseAdapter::new());
        AuthContext::new(config, database)
    }

    pub async fn create_user(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        create_user: CreateUser,
    ) -> User {
        ctx.database.create_user(create_user).await.unwrap()
    }

    pub async fn create_session(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        user_id: String,
        expires_in: Duration,
    ) -> Session {
        let create_session = CreateSession {
            user_id,
            expires_at: Utc::now() + expires_in,
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(create_session).await.unwrap()
    }

    pub async fn create_user_and_session(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        user_data: CreateUser,
        session_expires_in: Duration,
    ) -> (User, Session) {
        let user = create_user(ctx, user_data).await;
        let session = create_session(ctx, user.id.clone(), session_expires_in).await;
        (user, session)
    }

    pub async fn create_test_context_with_user(
        create_user: CreateUser,
        session_expires_in: Duration,
    ) -> (AuthContext<MemoryDatabaseAdapter>, User, Session) {
        let ctx = create_test_context();
        let (user, session) = create_user_and_session(&ctx, create_user, session_expires_in).await;
        (ctx, user, session)
    }

    pub fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }

        AuthRequest::from_parts(method, path.to_string(), headers, body, query)
    }

    pub fn create_auth_request_no_query(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> AuthRequest {
        create_auth_request(method, path, token, body, HashMap::new())
    }

    pub fn create_auth_json_request_no_query(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        create_auth_json_request(method, path, token, body, HashMap::new())
    }

    pub fn create_auth_json_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut req = create_auth_request(
            method,
            path,
            token,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
            query,
        );
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        req
    }
}

pub use account_management::AccountManagementPlugin;
pub use admin::{AdminConfig, AdminPlugin};
pub use api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use better_auth_core::PasswordHasher;
pub use email_password::{EmailPasswordConfig, EmailPasswordPlugin};
pub use email_verification::{
    EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin, SendVerificationEmail,
};
pub use organization::{OrganizationConfig, OrganizationPlugin};
pub use passkey::{PasskeyConfig, PasskeyPlugin};
pub use password_management::{
    PasswordManagementConfig, PasswordManagementPlugin, SendResetPassword,
};
pub use session_management::SessionManagementPlugin;
pub use two_factor::{TwoFactorConfig, TwoFactorPlugin};
pub use user_management::{
    ChangeEmailConfig, DeleteUserConfig, UserManagementConfig, UserManagementPlugin,
};
