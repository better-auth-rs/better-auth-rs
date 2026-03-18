use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::{Validate, ValidateEmail};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser, CreateVerification,
    HttpMethod, RequestMeta,
};

use super::email_verification::EmailVerificationPlugin;
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::utils::password::{self as password_utils, PasswordHasher};
use better_auth_core::wire::UserView;
/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
    /// Optional reference to the email-verification plugin so that
    /// `send_on_sign_in` can be triggered during the sign-in flow.
    email_verification: Option<Arc<EmailVerificationPlugin>>,
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
#[expect(dead_code, reason = "fields deserialized from request body")]
pub(crate) struct SignUpRequest {
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
#[expect(dead_code, reason = "fields deserialized from request body")]
pub(crate) struct SignInRequest {
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
#[expect(dead_code, reason = "fields deserialized from request body")]
pub(crate) struct SignInUsernameRequest {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignUpResponse<U: Serialize> {
    token: Option<String>,
    user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignInResponse<U: Serialize> {
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: U,
}

/// 2FA redirect response returned when the user has 2FA enabled.
#[derive(Debug, Serialize)]
pub(crate) struct TwoFactorRedirectResponse {
    #[serde(rename = "twoFactorRedirect")]
    two_factor_redirect: bool,
    token: String,
}

/// Result of sign-in: either a successful session or a 2FA redirect.
pub(crate) enum SignInCoreResult<U: Serialize> {
    Success(SignInResponse<U>, String),
    TwoFactorRedirect(TwoFactorRedirectResponse),
}

impl EmailPasswordPlugin {
    #[expect(
        clippy::new_without_default,
        reason = "plugin construction is intentionally explicit"
    )]
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
            email_verification: None,
        }
    }

    pub fn with_config(config: EmailPasswordConfig) -> Self {
        Self {
            config,
            email_verification: None,
        }
    }

    /// Attach an [`EmailVerificationPlugin`] so that `send_on_sign_in` is
    /// automatically called when a user signs in with an unverified email.
    pub fn with_email_verification(mut self, plugin: Arc<EmailVerificationPlugin>) -> Self {
        self.email_verification = Some(plugin);
        self
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

    async fn handle_sign_up(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signup_req: SignUpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let meta = RequestMeta::from_request(req);
        let (response, session_token) = sign_up_core(&signup_req, &self.config, &meta, ctx).await?;

        if let Some(token) = session_token {
            let cookie_header = create_session_cookie(&token, &ctx.config);
            Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
        } else {
            Ok(AuthResponse::json(200, &response)?)
        }
    }

    async fn handle_sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Ok(raw_body) = req.body_as_json::<serde_json::Value>()
            && let Some(email) = raw_body.get("email").and_then(|value| value.as_str())
            && !email.validate_email()
        {
            return Err(AuthError::bad_request("Invalid email"));
        }

        let signin_req: SignInRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let meta = RequestMeta::from_request(req);
        match sign_in_core(
            &signin_req,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await?
        {
            SignInCoreResult::Success(response, token) => {
                let cookie_header = create_session_cookie(&token, &ctx.config);
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
            }
            SignInCoreResult::TwoFactorRedirect(redirect) => {
                Ok(AuthResponse::json(200, &redirect)?)
            }
        }
    }

    async fn handle_sign_in_username(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInUsernameRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let meta = RequestMeta::from_request(req);
        match sign_in_username_core(
            &signin_req,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await?
        {
            SignInCoreResult::Success(response, token) => {
                let cookie_header = create_session_cookie(&token, &ctx.config);
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
            }
            SignInCoreResult::TwoFactorRedirect(redirect) => {
                Ok(AuthResponse::json(200, &redirect)?)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

/// Core sign-up logic.
///
/// Returns `(response, Option<session_token>)`. The session token is present
/// only when `auto_sign_in` is true.
pub(crate) async fn sign_up_core(
    body: &SignUpRequest,
    config: &EmailPasswordConfig,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SignUpResponse<UserView>, Option<String>)> {
    if !config.enable_signup {
        return Err(AuthError::forbidden("User registration is not enabled"));
    }

    password_utils::validate_password(
        &body.password,
        config.password_min_length,
        config.password_max_length,
        ctx,
    )?;

    // Check if user already exists
    if ctx.database.get_user_by_email(&body.email).await?.is_some() {
        // TS returns 422 UNPROCESSABLE_ENTITY for duplicate email
        return Err(AuthError::UnprocessableEntity(
            "User already exists. Use another email.".to_string(),
        ));
    }

    // Hash password
    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.password).await?;

    let mut create_user = CreateUser::new()
        .with_email(&body.email)
        .with_name(&body.name);
    if let Some(ref username) = body.username {
        create_user = create_user.with_username(username.clone());
    }
    if let Some(ref display_username) = body.display_username {
        create_user.display_username = Some(display_username.clone());
    }
    let auto_sign_in = config.auto_sign_in;
    let expires_in = ctx.config.session.expires_in;
    let ip_address = meta.ip_address.clone();
    let user_agent = meta.user_agent.clone();
    let database = ctx.database.clone();
    let transaction_database = database.clone();

    database
        .transaction(move |tx| {
            let database = transaction_database.clone();
            Box::pin(async move {
                let user = database.create_user_in_tx(tx, create_user).await?;

                let _ = database
                    .create_account_in_tx(
                        tx,
                        CreateAccount {
                            user_id: user.id().to_string(),
                            account_id: user.id().to_string(),
                            provider_id: "credential".to_string(),
                            access_token: None,
                            refresh_token: None,
                            id_token: None,
                            access_token_expires_at: None,
                            refresh_token_expires_at: None,
                            scope: None,
                            password: Some(password_hash.clone()),
                        },
                    )
                    .await?;

                if auto_sign_in {
                    let session = database
                        .create_session_in_tx(
                            tx,
                            CreateSession {
                                user_id: user.id().to_string(),
                                expires_at: chrono::Utc::now() + expires_in,
                                ip_address,
                                user_agent,
                                impersonated_by: None,
                                active_organization_id: None,
                            },
                        )
                        .await?;
                    let token = session.token().to_string();

                    Ok((
                        SignUpResponse {
                            token: Some(token.clone()),
                            user: UserView::from(&user),
                        },
                        Some(token),
                    ))
                } else {
                    Ok((
                        SignUpResponse {
                            token: None,
                            user: UserView::from(&user),
                        },
                        None,
                    ))
                }
            })
        })
        .await
}

/// Shared sign-in logic after user lookup: verify password, check 2FA, create session.
async fn sign_in_with_user_core(
    user: impl AuthUser,
    password: &str,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    callback_url: Option<&str>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    // Verify password
    let stored_hash = ctx
        .database
        .get_user_accounts(user.id())
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential" && account.password().is_some())
        .and_then(|account| account.password().map(str::to_string))
        .ok_or(AuthError::InvalidCredentials)?;

    password_utils::verify_password(config.password_hasher.as_ref(), password, &stored_hash)
        .await?;

    // Check if 2FA is enabled
    if user.two_factor_enabled() {
        let pending_token = format!("2fa_{}", uuid::Uuid::new_v4());
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: format!("2fa_pending:{}", pending_token),
                value: user.id().to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            })
            .await?;
        return Ok(SignInCoreResult::TwoFactorRedirect(
            TwoFactorRedirectResponse {
                two_factor_redirect: true,
                token: pending_token,
            },
        ));
    }

    // Send verification email on sign-in if configured
    if let Some(ev) = email_verification
        && let Err(e) = ev
            .send_verification_on_sign_in(&user, callback_url, ctx)
            .await
    {
        tracing::warn!(
            error = %e,
            "Failed to send verification email on sign-in"
        );
    }

    let session = ctx
        .session_manager()
        .create_session(&user, meta.ip_address.clone(), meta.user_agent.clone())
        .await?;
    let token = session.token().to_string();

    let response = SignInResponse {
        redirect: false,
        token: token.clone(),
        url: None,
        user: UserView::from(&user),
    };
    Ok(SignInCoreResult::Success(response, token))
}

/// Core sign-in by email.
pub(crate) async fn sign_in_core(
    body: &SignInRequest,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let user = ctx
        .database
        .get_user_by_email(&body.email)
        .await?
        .ok_or(AuthError::InvalidCredentials)?;

    sign_in_with_user_core(
        user,
        &body.password,
        config,
        email_verification,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
}

/// Core sign-in by username.
pub(crate) async fn sign_in_username_core(
    body: &SignInUsernameRequest,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let user = ctx
        .database
        .get_user_by_username(&body.username)
        .await?
        .ok_or(AuthError::InvalidCredentials)?;

    sign_in_with_user_core(
        user,
        &body.password,
        config,
        email_verification,
        None,
        meta,
        ctx,
    )
    .await
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
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for EmailPasswordPlugin {
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
        ctx: &AuthContext<S>,
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

    async fn on_user_created(&self, user: &S::User, _ctx: &AuthContext<S>) -> AuthResult<()> {
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
    use better_auth_core::config::AuthConfig;
    use std::collections::HashMap;
    use std::sync::Arc;

    type TestSchema =
        better_auth_core::store::sea_orm::__private_test_support::bundled_schema::BundledSchema;

    async fn create_test_context() -> AuthContext<TestSchema> {
        let config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        let config = Arc::new(config);
        let database = crate::plugins::test_helpers::create_test_database().await;
        AuthContext::new(config, database)
    }

    fn create_signup_request(email: &str, password: &str) -> AuthRequest {
        let body = serde_json::json!({
            "name": "Test User",
            "email": email,
            "password": password,
        });
        AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_string(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        )
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_auto_sign_in_false_returns_no_session() {
        let plugin = EmailPasswordPlugin::new().auto_sign_in(false);
        let ctx = create_test_context().await;

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

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_auto_sign_in_true_returns_session() {
        let plugin = EmailPasswordPlugin::new(); // default auto_sign_in=true
        let ctx = create_test_context().await;

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

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_password_max_length_rejection() {
        let plugin = EmailPasswordPlugin::new().password_max_length(128);
        let ctx = create_test_context().await;

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

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
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
        let ctx = create_test_context().await;

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
        let stored_hash = ctx
            .database
            .get_user_accounts(user.id())
            .await
            .unwrap()
            .into_iter()
            .find(|account| account.provider_id() == "credential")
            .and_then(|account| account.password().map(str::to_string))
            .expect("credential account should store hashed password");
        assert_eq!(stored_hash, "hashed:Password123!");

        // Sign in should work with the custom hasher
        let signin_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_string(),
            HashMap::new(),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin.handle_sign_in(&signin_req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Sign in with wrong password should fail
        let bad_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "WrongPassword!",
        });
        let bad_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_string(),
            HashMap::new(),
            Some(bad_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let err = plugin.handle_sign_in(&bad_req, &ctx).await.unwrap_err();
        assert_eq!(err.to_string(), AuthError::InvalidCredentials.to_string());
    }
}
