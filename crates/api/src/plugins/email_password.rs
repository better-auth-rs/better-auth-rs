use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateUser, CreateVerification, HttpMethod};

use better_auth_core::utils::password::{self as password_utils, PasswordHasher};

/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
}

#[derive(Clone)]
pub struct EmailPasswordConfig {
    pub enable_signup: bool,
    pub require_email_verification: bool,
    pub password_min_length: usize,
    /// Maximum password length (default: 128).
    pub password_max_length: usize,
    /// Whether to automatically sign in the user after sign-up (default: true).
    /// When false, sign-up returns the user but doesn't create a session.
    pub auto_sign_in: bool,
    /// Custom password hasher. When `None`, the default Argon2 hasher is used.
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
}

impl std::fmt::Debug for EmailPasswordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordConfig")
            .field("enable_signup", &self.enable_signup)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field("password_min_length", &self.password_min_length)
            .field("password_max_length", &self.password_max_length)
            .field("auto_sign_in", &self.auto_sign_in)
            .field(
                "password_hasher",
                &self.password_hasher.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

#[derive(Debug, Deserialize, Validate)]
#[allow(dead_code)]
struct SignUpRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    name: String,
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    username: Option<String>,
    #[serde(rename = "displayUsername")]
    display_username: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
#[allow(dead_code)]
struct SignInRequest {
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
#[allow(dead_code)]
struct SignInUsernameRequest {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SignUpResponse<U: Serialize> {
    token: Option<String>,
    user: U,
}

#[derive(Debug, Serialize)]
struct SignInResponse<U: Serialize> {
    redirect: bool,
    token: String,
    url: Option<String>,
    user: U,
}

impl EmailPasswordPlugin {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
        }
    }

    pub fn with_config(config: EmailPasswordConfig) -> Self {
        Self { config }
    }

    pub fn enable_signup(mut self, enable: bool) -> Self {
        self.config.enable_signup = enable;
        self
    }

    pub fn require_email_verification(mut self, require: bool) -> Self {
        self.config.require_email_verification = require;
        self
    }

    pub fn password_min_length(mut self, length: usize) -> Self {
        self.config.password_min_length = length;
        self
    }

    pub fn password_max_length(mut self, length: usize) -> Self {
        self.config.password_max_length = length;
        self
    }

    pub fn auto_sign_in(mut self, auto: bool) -> Self {
        self.config.auto_sign_in = auto;
        self
    }

    pub fn password_hasher(mut self, hasher: Arc<dyn PasswordHasher>) -> Self {
        self.config.password_hasher = Some(hasher);
        self
    }

    async fn handle_sign_up<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enable_signup {
            return Err(AuthError::forbidden("User registration is not enabled"));
        }

        let signup_req: SignUpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validate password
        self.validate_password(&signup_req.password, ctx)?;

        // Check if user already exists
        if ctx
            .database
            .get_user_by_email(&signup_req.email)
            .await?
            .is_some()
        {
            return Err(AuthError::conflict("A user with this email already exists"));
        }

        // Hash password
        let password_hash = self.hash_password(&signup_req.password).await?;

        // Create user with password hash in metadata
        let metadata = serde_json::json!({
            "password_hash": password_hash,
        });

        let mut create_user = CreateUser::new()
            .with_email(&signup_req.email)
            .with_name(&signup_req.name);
        if let Some(username) = signup_req.username {
            create_user = create_user.with_username(username);
        }
        if let Some(display_username) = signup_req.display_username {
            create_user.display_username = Some(display_username);
        }
        create_user.metadata = Some(metadata);

        let user = ctx.database.create_user(create_user).await?;

        if self.config.auto_sign_in {
            // Create session
            let session_manager =
                better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
            let session = session_manager.create_session(&user, None, None).await?;

            let response = SignUpResponse {
                token: Some(session.token().to_string()),
                user,
            };

            // Create session cookie
            let cookie_header =
                better_auth_core::utils::cookie_utils::create_session_cookie(session.token(), ctx);

            Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
        } else {
            let response = SignUpResponse { token: None, user };

            Ok(AuthResponse::json(200, &response)?)
        }
    }

    async fn handle_sign_in<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Get user by email
        let user = ctx
            .database
            .get_user_by_email(&signin_req.email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify password
        let stored_hash = user
            .metadata()
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        self.verify_password(&signin_req.password, stored_hash)
            .await?;

        // Check if 2FA is enabled
        if user.two_factor_enabled() {
            let pending_token = format!("2fa_{}", uuid::Uuid::new_v4());
            ctx.database
                .create_verification(CreateVerification {
                    identifier: format!("2fa_pending:{}", pending_token),
                    value: user.id().to_string(),
                    expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                })
                .await?;
            return Ok(AuthResponse::json(
                200,
                &serde_json::json!({
                    "twoFactorRedirect": true,
                    "token": pending_token,
                }),
            )?);
        }

        // Create session
        let session_manager =
            better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = SignInResponse {
            redirect: false,
            token: session.token().to_string(),
            url: None,
            user,
        };

        // Create session cookie
        let cookie_header =
            better_auth_core::utils::cookie_utils::create_session_cookie(session.token(), ctx);

        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    async fn handle_sign_in_username<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInUsernameRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Get user by username
        let user = ctx
            .database
            .get_user_by_username(&signin_req.username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify password
        let stored_hash = user
            .metadata()
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        self.verify_password(&signin_req.password, stored_hash)
            .await?;

        // Check if 2FA is enabled
        if user.two_factor_enabled() {
            let pending_token = format!("2fa_{}", uuid::Uuid::new_v4());
            ctx.database
                .create_verification(CreateVerification {
                    identifier: format!("2fa_pending:{}", pending_token),
                    value: user.id().to_string(),
                    expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                })
                .await?;
            return Ok(AuthResponse::json(
                200,
                &serde_json::json!({
                    "twoFactorRedirect": true,
                    "token": pending_token,
                }),
            )?);
        }

        // Create session
        let session_manager =
            better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = SignInResponse {
            redirect: false,
            token: session.token().to_string(),
            url: None,
            user,
        };

        // Create session cookie
        let cookie_header =
            better_auth_core::utils::cookie_utils::create_session_cookie(session.token(), ctx);

        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    fn validate_password<DB: DatabaseAdapter>(
        &self,
        password: &str,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<()> {
        password_utils::validate_password(
            password,
            self.config.password_min_length,
            self.config.password_max_length,
            ctx,
        )
    }

    async fn hash_password(&self, password: &str) -> AuthResult<String> {
        password_utils::hash_password(self.config.password_hasher.as_ref(), password).await
    }

    async fn verify_password(&self, password: &str, hash: &str) -> AuthResult<()> {
        password_utils::verify_password(self.config.password_hasher.as_ref(), password, hash).await
    }
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enable_signup: true,
            require_email_verification: false,
            password_min_length: 8,
            password_max_length: 128,
            auto_sign_in: true,
            password_hasher: None,
        }
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            AuthRoute::post("/sign-in/email", "sign_in_email"),
            AuthRoute::post("/sign-in/username", "sign_in_username"),
        ];

        if self.config.enable_signup {
            routes.push(AuthRoute::post("/sign-up/email", "sign_up_email"));
        }

        routes
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up/email") if self.config.enable_signup => {
                Ok(Some(self.handle_sign_up(req, ctx).await?))
            }
            (HttpMethod::Post, "/sign-in/email") => Ok(Some(self.handle_sign_in(req, ctx).await?)),
            (HttpMethod::Post, "/sign-in/username") => {
                Ok(Some(self.handle_sign_in_username(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }

    async fn on_user_created(&self, user: &DB::User, _ctx: &AuthContext<DB>) -> AuthResult<()> {
        if self.config.require_email_verification
            && !user.email_verified()
            && let Some(email) = user.email()
        {
            println!("Email verification required for user: {}", email);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::AuthContext;
    use better_auth_core::adapters::{MemoryDatabaseAdapter, UserOps};
    use better_auth_core::config::AuthConfig;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_context() -> AuthContext<MemoryDatabaseAdapter> {
        let config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        let config = Arc::new(config);
        let database = Arc::new(MemoryDatabaseAdapter::new());
        AuthContext::new(config, database)
    }

    fn create_signup_request(email: &str, password: &str) -> AuthRequest {
        let body = serde_json::json!({
            "name": "Test User",
            "email": email,
            "password": password,
        });
        AuthRequest {
            method: HttpMethod::Post,
            path: "/sign-up/email".to_string(),
            headers: HashMap::new(),
            body: Some(body.to_string().into_bytes()),
            query: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_auto_sign_in_false_returns_no_session() {
        let plugin = EmailPasswordPlugin::new().auto_sign_in(false);
        let ctx = create_test_context();

        let req = create_signup_request("auto@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Response should NOT have a Set-Cookie header
        let has_cookie = response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
        assert!(!has_cookie, "auto_sign_in=false should not set a cookie");

        // Response body token should be null
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["token"].is_null(),
            "auto_sign_in=false should return null token"
        );
        // But the user should still be created
        assert!(body["user"]["id"].is_string());
    }

    #[tokio::test]
    async fn test_auto_sign_in_true_returns_session() {
        let plugin = EmailPasswordPlugin::new(); // default auto_sign_in=true
        let ctx = create_test_context();

        let req = create_signup_request("autotrue@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Response SHOULD have a Set-Cookie header
        let has_cookie = response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
        assert!(has_cookie, "auto_sign_in=true should set a cookie");

        // Response body token should be a string
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["token"].is_string(),
            "auto_sign_in=true should return a session token"
        );
    }

    #[tokio::test]
    async fn test_password_max_length_rejection() {
        let plugin = EmailPasswordPlugin::new().password_max_length(128);
        let ctx = create_test_context();

        // Password of exactly 129 chars should be rejected
        let long_password = format!("A1!{}", "a".repeat(126)); // 129 chars total
        let req = create_signup_request("long@example.com", &long_password);
        let err = plugin.handle_sign_up(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);

        // Password of exactly 128 chars should be accepted
        let ok_password = format!("A1!{}", "a".repeat(125)); // 128 chars total
        let req = create_signup_request("ok@example.com", &ok_password);
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_custom_password_hasher() {
        /// A simple test hasher that prefixes the password with "hashed:"
        struct TestHasher;

        #[async_trait]
        impl PasswordHasher for TestHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("hashed:{}", password))
            }
            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                Ok(hash == format!("hashed:{}", password))
            }
        }

        let hasher: Arc<dyn PasswordHasher> = Arc::new(TestHasher);
        let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
        let ctx = create_test_context();

        // Sign up with custom hasher
        let req = create_signup_request("hasher@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify the stored hash uses our custom hasher
        let user = ctx
            .database
            .get_user_by_email("hasher@example.com")
            .await
            .unwrap()
            .unwrap();
        let stored_hash = user
            .metadata
            .get("password_hash")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(stored_hash, "hashed:Password123!");

        // Sign in should work with the custom hasher
        let signin_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "Password123!",
        });
        let signin_req = AuthRequest {
            method: HttpMethod::Post,
            path: "/sign-in/email".to_string(),
            headers: HashMap::new(),
            body: Some(signin_body.to_string().into_bytes()),
            query: HashMap::new(),
        };
        let response = plugin.handle_sign_in(&signin_req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Sign in with wrong password should fail
        let bad_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "WrongPassword!",
        });
        let bad_req = AuthRequest {
            method: HttpMethod::Post,
            path: "/sign-in/email".to_string(),
            headers: HashMap::new(),
            body: Some(bad_body.to_string().into_bytes()),
            query: HashMap::new(),
        };
        let err = plugin.handle_sign_in(&bad_req, &ctx).await.unwrap_err();
        assert_eq!(err.to_string(), AuthError::InvalidCredentials.to_string());
    }
}
