pub mod account_management;
pub mod admin;
pub mod anonymous;
pub mod api_key;
pub mod captcha;
pub mod custom_session;
pub mod device_authorization;
pub mod email_otp;
pub mod email_password;
pub mod email_verification;
pub mod endpoint_context;
pub mod have_i_been_pwned;
pub mod helpers;
mod json_body;
pub mod jwt;
pub mod last_login_method;
pub mod magic_link;
pub mod multi_session;
pub mod oauth;
pub mod one_tap;
pub mod one_time_token;
pub mod open_api;
pub mod organization;
pub mod passkey;
pub mod password_management;
pub mod phone_number;
mod query_input;
pub mod session_management;
mod session_update;
pub mod siwe;
mod symmetric;
pub mod two_factor;
pub mod user_management;
pub mod username;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusResponse {
    status: bool,
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::HashMap;
    use std::sync::Arc;

    use better_auth_core::config::AuthConfig;
    use better_auth_core::wire::{SessionView, UserView};
    use better_auth_core::{AuthContext, AuthRequest, CreateSession, CreateUser, HttpMethod};
    use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    use better_auth_seaorm::{Database, SeaOrmStore};
    use chrono::{Duration, Utc};

    pub type TestDatabase = dyn better_auth_core::store::AuthStore<BundledSchema>;

    /// Apply the dispatch response boundary after invoking an internal handler directly.
    pub fn finalize_response(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        req: &AuthRequest,
        mut response: better_auth_core::AuthResponse,
    ) -> better_auth_core::AuthResponse {
        ctx.session_manager()
            .finish_response(req, &mut response)
            .expect("endpoint response should finalize");
        response
    }

    pub fn create_test_config() -> AuthConfig {
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long")
            .base_url("http://localhost:3000");
        config.session.bearer = Some(better_auth_core::config::BearerConfig::default());
        config
    }

    pub async fn create_test_database() -> Arc<TestDatabase> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        Arc::new(SeaOrmStore::<BundledSchema>::new(
            Arc::new(create_test_config()),
            database,
        ))
    }

    pub async fn create_test_context() -> AuthContext<BundledSchema> {
        create_test_context_with_config(create_test_config()).await
    }

    pub fn create_test_context_blocking() -> AuthContext<BundledSchema> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should build")
            .block_on(create_test_context())
    }

    pub async fn create_test_context_with_config(config: AuthConfig) -> AuthContext<BundledSchema> {
        let config = Arc::new(config);
        let database = create_test_database().await;
        AuthContext::new(config, database)
            .initialize_request_context()
            .await
            .expect("test request context should initialize")
            .as_ref()
            .clone()
    }

    pub async fn create_user(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        create_user: CreateUser,
    ) -> UserView {
        let user = ctx.database.create_user(create_user).await.unwrap();
        UserView::from(&user)
    }

    pub async fn create_session(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        user_id: String,
        expires_in: Duration,
    ) -> SessionView {
        let create_session = CreateSession {
            user_id,
            expires_at: Utc::now() + expires_in,
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session = ctx.database.create_session(create_session).await.unwrap();
        SessionView::from(&session)
    }

    pub async fn create_user_and_session(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        user_data: CreateUser,
        session_expires_in: Duration,
    ) -> (UserView, SessionView) {
        let user = create_user(ctx, user_data).await;
        let session = create_session(ctx, user.id.clone(), session_expires_in).await;
        (user, session)
    }

    pub async fn create_test_context_with_user(
        create_user: CreateUser,
        session_expires_in: Duration,
    ) -> (AuthContext<BundledSchema>, UserView, SessionView) {
        let ctx = create_test_context().await;
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

        AuthRequest::from_parts(
            method,
            path.to_string(),
            headers,
            body,
            Some(serde_json::json!(query)),
        )
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
pub use admin::{AdminConfig, AdminPlugin, RolePermissions};
pub use api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use better_auth_core::PasswordHasher;
pub use custom_session::{CustomSessionCallback, CustomSessionInput, CustomSessionPlugin};
pub use device_authorization::DeviceAuthorizationPlugin;
pub use email_otp::{
    EmailOtpApi, EmailOtpCodec, EmailOtpConfig, EmailOtpGenerator, EmailOtpMessage, EmailOtpPlugin,
    EmailOtpStorage, EmailOtpType, SendEmailOtp,
};
pub use email_password::{EmailPasswordConfig, EmailPasswordPlugin};
pub use email_verification::{
    EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin, SendVerificationEmail,
};
pub use jwt::{
    JwtAdapterFuture, JwtAlgorithm, JwtApi, JwtAudience, JwtCallOverrides, JwtCallbackFuture,
    JwtCallbacks, JwtCustomSign, JwtDefinePayload, JwtExpiration, JwtGetSubject, JwtKeyOptions,
    JwtKeyPairConfig, JwtPlugin, JwtPluginConfig, JwtSigningOptions, JwtTokenOptions,
};
pub use magic_link::{MagicLinkConfig, MagicLinkMessage, MagicLinkPlugin, SendMagicLink};
pub use multi_session::{MultiSessionConfig, MultiSessionPlugin};
pub use oauth::{OAuthPopupPlugin, OAuthProxyConfig, OAuthProxyPlugin};
pub use one_tap::{OneTapConfig, OneTapPlugin};
pub use one_time_token::{OneTimeTokenConfig, OneTimeTokenPlugin, TokenStorage};
pub use open_api::{OpenApiConfig, OpenApiPlugin};
pub use organization::{OrganizationConfig, OrganizationPlugin};
pub use passkey::{PasskeyConfig, PasskeyPlugin};
pub use password_management::{
    PasswordManagementConfig, PasswordManagementPlugin, SendResetPassword,
};
pub use session_management::SessionManagementPlugin;
pub use two_factor::{SendTwoFactorOtp, TwoFactorConfig, TwoFactorPlugin};
pub use user_management::{
    ChangeEmailConfig, DeleteUserConfig, UserManagementConfig, UserManagementPlugin,
};

pub mod user_admission;

pub use last_login_method::{
    BeforeStoreLastLoginCookie, LastLoginMethodConfig, LastLoginMethodPlugin,
    LastLoginMethodResolver,
};
