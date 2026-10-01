use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::{Validate, ValidateEmail};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod, RequestMeta};

use super::{email_verification::EmailVerificationPlugin, two_factor};
use better_auth_core::utils::password::{self as password_utils, PasswordHasher};
use better_auth_core::wire::UserView;

use crate::plugins::helpers::{SessionIssueError, issue_user_session_with_lifetime};

mod request;
mod signup;
use super::username::request::SignInUsernameRequest;
use signup::sign_up_core;
pub use signup::{CustomSyntheticUser, OnExistingUserSignUp, SyntheticUserInput};

const MESSAGE_EMAIL_NOT_VERIFIED: &str = "Email not verified";

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
    /// Enable the upstream username plugin behavior. Requires both username fields.
    pub username: bool,
    pub require_email_verification: bool,
    pub password_min_length: usize,
    /// Maximum password length (default: 128).
    pub password_max_length: usize,
    /// Whether to automatically sign in the user after sign-up (default: true).
    /// When false, sign-up returns the user but doesn't create a session.
    pub auto_sign_in: bool,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
    /// Notify the application after a protected duplicate signup hashes its password.
    pub on_existing_user_sign_up: Option<Arc<dyn OnExistingUserSignUp>>,
    /// Customize enumeration-safe signup responses without creating an account.
    pub custom_synthetic_user: Option<Arc<CustomSyntheticUser>>,
}

impl std::fmt::Debug for EmailPasswordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordConfig")
            .field("enable_signup", &self.enable_signup)
            .field("username", &self.username)
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
pub(crate) struct SignUpRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    name: String,
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    image: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
    #[serde(flatten)]
    additional_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SignInRequest {
    email: String,
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
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

/// Result of sign-in: either a successful session or a 2FA redirect.
pub(crate) enum SignInCoreResult<U: Serialize> {
    Success {
        response: SignInResponse<U>,
        set_cookie_headers: Vec<String>,
    },
    TwoFactorRedirect {
        response: two_factor::TwoFactorRedirectResponse,
        set_cookie_headers: Vec<String>,
    },
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

    /// Enable username registration, sign-in, availability checks, and updates.
    ///
    /// The user entity must persist `username` and `display_username`.
    pub fn username(mut self, enabled: bool) -> Self {
        self.config.username = enabled;
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

    /// Set the notification for a duplicate signup protected against enumeration.
    pub fn on_existing_user_sign_up(mut self, callback: Arc<dyn OnExistingUserSignUp>) -> Self {
        self.config.on_existing_user_sign_up = Some(callback);
        self
    }

    /// Customize synthetic users returned by enumeration-safe signup.
    pub fn custom_synthetic_user(mut self, callback: Arc<CustomSyntheticUser>) -> Self {
        self.config.custom_synthetic_user = Some(callback);
        self
    }

    async fn handle_sign_up(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let endpoint_body: serde_json::Value = req
            .body_as_json()
            .map_err(|error| AuthError::bad_request(format!("Invalid JSON: {error}")))?;
        let parsed_body = endpoint_body.clone();
        if let Some(value) = parsed_body.get("rememberMe")
            && !value.is_boolean()
        {
            return Err(
                super::json_body::validation_error(&super::json_body::invalid_type(
                    "body.rememberMe",
                    "boolean",
                    Some(value),
                ))
                .into(),
            );
        }
        let mut signup_req_source = req.clone();
        signup_req_source.body = Some(serde_json::to_vec(&parsed_body)?);
        let signup_req: SignUpRequest =
            match better_auth_core::validate_request_body(&signup_req_source) {
                Ok(v) => v,
                Err(resp) => return Ok(resp),
            };
        request::form_csrf(req, ctx).await?;

        let response = sign_up_core(&signup_req, endpoint_body, &self.config, req, ctx).await?;

        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signin_req = request::sign_in(req)?;
        request::form_csrf(req, ctx).await?;
        if !signin_req.email.validate_email() {
            return Err(AuthError::bad_request("Invalid email"));
        }

        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        match sign_in_core(
            req,
            &signin_req,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await?
        {
            SignInCoreResult::Success {
                response,
                set_cookie_headers,
            } => {
                let mut auth_response = AuthResponse::json(200, &response)?;
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(auth_response)
            }
            SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            } => {
                let mut auth_response = AuthResponse::json(200, &response)?;
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(auth_response)
            }
        }
    }

    async fn handle_sign_in_username(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        super::username::UsernamePlugin::default()
            .sign_in_with_verification(req, ctx, self.email_verification.as_deref())
            .await
    }

    async fn handle_is_username_available(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        super::username::UsernamePlugin::default()
            .available(req, ctx)
            .await
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

async fn load_credential_password_hash(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    ctx.database
        .get_user_accounts(&user.id())
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential" && account.password().is_some())
        .and_then(|account| account.password().map(str::to_string))
        .ok_or(AuthError::InvalidCredentials)
}

async fn verify_user_password(
    user: &impl AuthUser,
    password: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    let stored_hash = load_credential_password_hash(user, ctx).await?;
    password_utils::verify_password(ctx.password_policy.hasher.as_ref(), password, &stored_hash)
        .await
}

/// Shared sign-in finalization logic after user lookup and credential verification.
async fn finalize_sign_in_with_user_core(
    req: &AuthRequest,
    user: impl AuthUser,
    remember_me: Option<bool>,
    email_verification: Option<&EmailVerificationPlugin>,
    callback_url: Option<&str>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let mut set_cookie_headers = Vec::new();
    if two_factor::is_enabled(ctx) && user.two_factor_enabled() {
        let trusted_device = two_factor::inspect_trusted_device(req, &user, ctx).await?;
        if trusted_device.trusted {
            set_cookie_headers.extend(trusted_device.set_cookie_headers);
        } else {
            let redirect =
                two_factor::begin_sign_in_challenge(&user, remember_me, req, ctx).await?;
            let mut redirect_headers = trusted_device.set_cookie_headers;
            redirect_headers.extend(redirect.set_cookie_headers);
            return Ok(SignInCoreResult::TwoFactorRedirect {
                response: redirect.response,
                set_cookie_headers: redirect_headers,
            });
        }
    }

    // Send verification email on sign-in if configured
    if let Some(ev) = email_verification
        && let Err(e) = ev
            .send_verification_on_sign_in_with_request(&user, callback_url, Some(req), ctx)
            .await
    {
        tracing::warn!(
            error = %e,
            "Failed to send verification email on sign-in"
        );
    }

    let expires_in = if remember_me == Some(false) {
        chrono::Duration::days(1)
    } else {
        ctx.config.session.expires_in
    };
    let issued = issue_user_session_with_lifetime(
        ctx,
        &user.id(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
        expires_in,
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    let token = issued.session.token().to_string();
    let manager = ctx.session_manager();
    manager
        .set_session_cookie(
            req,
            manager.internal_data(&issued.user, &issued.session).await?,
            Some(remember_me == Some(false)),
        )
        .await?;

    if let Some(callback) = callback_url.filter(|url| !url.is_empty()) {
        req.set_response_header("Location", callback)?;
    }
    let response = SignInResponse {
        redirect: callback_url.is_some_and(|url| !url.is_empty()),
        token: token.clone(),
        url: callback_url.map(str::to_owned),
        user: ctx.user_view(&issued.user)?,
    };
    Ok(SignInCoreResult::Success {
        response,
        set_cookie_headers,
    })
}

/// Core sign-in by email.
pub(crate) async fn sign_in_core(
    req: &AuthRequest,
    body: &SignInRequest,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    ctx.password_policy.validate_max_length(&body.password)?;
    let verification = EmailVerificationPlugin::from_context(ctx);
    let email_verification = email_verification.or(verification.as_ref());
    let Some(user) = ctx.database.get_user_by_email(&body.email).await? else {
        _ = password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.password)
            .await?;
        return Err(AuthError::InvalidCredentials);
    };

    let stored_hash = match load_credential_password_hash(&user, ctx).await {
        Ok(hash) if !hash.is_empty() => hash,
        Ok(_) | Err(AuthError::InvalidCredentials) => {
            _ = password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.password)
                .await?;
            return Err(AuthError::InvalidCredentials);
        }
        Err(error) => return Err(error),
    };
    password_utils::verify_password(
        ctx.password_policy.hasher.as_ref(),
        &body.password,
        &stored_hash,
    )
    .await?;

    if (config.require_email_verification
        || email_verification.is_some_and(EmailVerificationPlugin::is_verification_required))
        && !user.email_verified()
    {
        if let Some(verification) = email_verification {
            verification
                .send_verification_on_sign_in_with_request(
                    &user,
                    body.callback_url.as_deref(),
                    Some(req),
                    ctx,
                )
                .await?;
        }
        return Err(AuthError::forbidden(MESSAGE_EMAIL_NOT_VERIFIED));
    }

    finalize_sign_in_with_user_core(
        req,
        user,
        body.remember_me,
        email_verification,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
}

/// Core sign-in by username.
pub(crate) async fn sign_in_username_core(
    req: &AuthRequest,
    body: &SignInUsernameRequest,
    normalized_username: &str,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<SignInCoreResult<UserView>, SignInUsernameFailure> {
    ctx.password_policy
        .validate_max_length(&body.password)
        .map_err(SignInUsernameFailure::Auth)?;
    let verification = EmailVerificationPlugin::from_context(ctx);
    let email_verification = email_verification.or(verification.as_ref());
    let Some(user) = ctx
        .database
        .get_user_by_username(normalized_username)
        .await
        .map_err(SignInUsernameFailure::Auth)?
    else {
        let _ = password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.password)
            .await
            .map_err(SignInUsernameFailure::Auth)?;
        return Err(SignInUsernameFailure::InvalidUsernameOrPassword);
    };

    verify_user_password(&user, &body.password, ctx)
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => SignInUsernameFailure::InvalidUsernameOrPassword,
            other => SignInUsernameFailure::Auth(other),
        })?;

    if (config.require_email_verification
        || email_verification.is_some_and(EmailVerificationPlugin::is_verification_required))
        && !user.email_verified()
    {
        if let Some(ev) = email_verification {
            ev.send_verification_on_sign_in_with_request(
                &user,
                body.callback_url.as_deref(),
                Some(req),
                ctx,
            )
            .await
            .map_err(SignInUsernameFailure::Auth)?;
        }
        return Err(SignInUsernameFailure::EmailNotVerified);
    }

    finalize_sign_in_with_user_core(
        req,
        user,
        body.remember_me,
        None,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
    .map_err(SignInUsernameFailure::Auth)
}

pub(crate) enum SignInUsernameFailure {
    InvalidUsernameOrPassword,
    EmailNotVerified,
    Auth(AuthError),
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enable_signup: true,
            username: false,
            require_email_verification: false,
            password_min_length: 8,
            password_max_length: 128,
            auto_sign_in: true,
            password_hasher: None,
            on_existing_user_sign_up: None,
            custom_synthetic_user: None,
        }
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }

    fn password_hasher(&self) -> Option<Arc<dyn PasswordHasher>> {
        self.config.password_hasher.clone()
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.password_policy.min_length = self.config.password_min_length;
        ctx.password_policy.max_length = self.config.password_max_length;
        ctx.extensions.insert(self.config.clone());
        if self.config.username {
            <super::username::UsernamePlugin as AuthPlugin<S>>::on_init(
                &super::username::UsernamePlugin::default(),
                ctx,
            )
            .await?;
        }
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            AuthRoute::post("/sign-in/email", "sign_in_email")
                .allowed_media_types(&["application/x-www-form-urlencoded", "application/json"]),
        ];
        if self.config.username {
            routes.push(AuthRoute::post("/sign-in/username", "sign_in_username"));
            routes.push(AuthRoute::post(
                "/is-username-available",
                "is_username_available",
            ));
        }

        if self.config.enable_signup {
            routes.push(
                AuthRoute::post("/sign-up/email", "sign_up_email").allowed_media_types(&[
                    "application/x-www-form-urlencoded",
                    "application/json",
                ]),
            );
        }

        routes
    }

    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::BeforeRequestAction>> {
        if self.config.username {
            super::username::UsernamePlugin::default()
                .before_endpoint(req, ctx)
                .await
        } else {
            Ok(None)
        }
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
            (HttpMethod::Post, "/sign-in/username") if self.config.username => {
                Ok(Some(self.handle_sign_in_username(req, ctx).await?))
            }
            (HttpMethod::Post, "/is-username-available") if self.config.username => {
                Ok(Some(self.handle_is_username_available(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::AuthContext;
    use better_auth_core::config::AuthConfig;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    async fn create_test_context(plugin: &EmailPasswordPlugin) -> Arc<AuthContext<TestSchema>> {
        let config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        let config = Arc::new(config);
        let database = crate::plugins::test_helpers::create_test_database().await;
        let mut init = better_auth_core::AuthInitContext::new(config.clone(), database.clone());
        init.password_policy.hasher =
            <EmailPasswordPlugin as AuthPlugin<TestSchema>>::password_hasher(plugin);
        plugin.on_init(&mut init).await.unwrap();
        let parts = init.into_parts();
        let (adapter, endpoint) = better_auth_core::plugin_runtime::resolve_user_fields(
            &config.user,
            parts.plugin_user_fields.clone(),
        );
        let mut adapter_config = (*config).clone();
        adapter_config.user = adapter;
        let database = database
            .with_runtime(Arc::new(adapter_config), parts.database_hooks.clone())
            .unwrap();
        let mut endpoint_config = (*config).clone();
        endpoint_config.user = endpoint;
        let mut context = AuthContext::new(Arc::new(endpoint_config), database);
        parts.apply_request_runtime(&mut context);
        context.extensions = parts.extensions;
        context.email_verification_policy = parts.email_verification_policy;
        context.email_provider = parts.email_provider;
        context.secondary_storage = parts.secondary_storage;
        context.password_policy = parts.password_policy;
        context.metadata = parts.metadata;
        let context = Arc::new(context);
        parts.runtime.bind(&context).unwrap();
        context
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
        let ctx = create_test_context(&plugin).await;

        let req = create_signup_request("auto@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        let response = test_helpers::finalize_response(&ctx, &req, response);
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
        let ctx = create_test_context(&plugin).await;

        let req = create_signup_request("autotrue@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        let response = test_helpers::finalize_response(&ctx, &req, response);
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
        let ctx = create_test_context(&plugin).await;

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
        let ctx = create_test_context(&plugin).await;

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
            .get_user_accounts(&user.id())
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

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts :: sign-in path verifies the password once before creating a session; adapted to ensure the Rust username path does not duplicate expensive password verification.
    #[tokio::test]
    async fn test_sign_in_username_verifies_password_once() {
        struct CountingHasher {
            verify_calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl PasswordHasher for CountingHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("hashed:{password}"))
            }

            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                self.verify_calls.fetch_add(1, Ordering::SeqCst);
                Ok(hash == format!("hashed:{password}"))
            }
        }

        let verify_calls = Arc::new(AtomicUsize::new(0));
        let hasher: Arc<dyn PasswordHasher> = Arc::new(CountingHasher {
            verify_calls: verify_calls.clone(),
        });
        let plugin = EmailPasswordPlugin::new()
            .username(true)
            .password_hasher(hasher);
        let ctx = create_test_context(&plugin).await;

        let signup_body = serde_json::json!({
            "email": "username-counter@example.com",
            "password": "Password123!",
            "name": "Counter User",
            "username": "Counter_User",
        });
        let signup_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_string(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let signup_response = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(signup_response.status, 200);

        verify_calls.store(0, Ordering::SeqCst);

        let signin_body = serde_json::json!({
            "username": "COUNTER_USER",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/username".to_string(),
            HashMap::from([("content-type".into(), "application/json".into())]),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let signin_response = plugin
            .handle_sign_in_username(&signin_req, &ctx)
            .await
            .unwrap();
        assert_eq!(signin_response.status, 200);
        assert_eq!(verify_calls.load(Ordering::SeqCst), 1);
    }

    // Rust-specific surface: route-table registration for the endpoint declared in
    // packages/better-auth/src/plugins/username/index.ts :: isUsernameAvailable.
    #[tokio::test]
    async fn test_is_username_available_route_registered() {
        let plugin = EmailPasswordPlugin::new().username(true);
        let routes =
            <EmailPasswordPlugin as better_auth_core::AuthPlugin<TestSchema>>::routes(&plugin);
        assert!(
            routes.iter().any(|r| r.path == "/is-username-available"),
            "route /is-username-available should be registered"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable returns `{ available: true }` when no user holds the
    // normalized username; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_fresh() {
        let plugin = EmailPasswordPlugin::new().username(true);
        let ctx = create_test_context(&plugin).await;

        let body = serde_json::json!({ "username": "fresh_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_string(),
            HashMap::from([("content-type".into(), "application/json".into())]),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(json["available"], true);
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable returns `{ available: false }` when the adapter finds a
    // user on the normalized username; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_taken() {
        let plugin = EmailPasswordPlugin::new().username(true);
        let ctx = create_test_context(&plugin).await;

        // Sign up a user with a username
        let signup_body = serde_json::json!({
            "name": "Taken User",
            "email": "taken@example.com",
            "password": "Password123!",
            "username": "taken_user",
        });
        let signup_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_string(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let resp = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);

        let body = serde_json::json!({ "username": "taken_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_string(),
            HashMap::from([("content-type".into(), "application/json".into())]),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(json["available"], false);
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable throws UNPROCESSABLE_ENTITY with code USERNAME_TOO_SHORT
    // below `minUsernameLength` (default 3); adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_too_short() {
        let plugin = EmailPasswordPlugin::new().username(true);
        let ctx = create_test_context(&plugin).await;

        let body = serde_json::json!({ "username": "ab" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_string(),
            HashMap::from([("content-type".into(), "application/json".into())]),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(response.status, 422);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(json["code"], "USERNAME_TOO_SHORT");
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable rejects usernames that fail `defaultUsernameValidator`
    // with UNPROCESSABLE_ENTITY; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_invalid_chars() {
        let plugin = EmailPasswordPlugin::new().username(true);
        let ctx = create_test_context(&plugin).await;

        let body = serde_json::json!({ "username": "bad user!" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_string(),
            HashMap::from([("content-type".into(), "application/json".into())]),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(response.status, 422);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(json["code"], "INVALID_USERNAME");
    }
}
