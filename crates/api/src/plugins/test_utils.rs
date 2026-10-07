//! Native test factories, database setup, and authenticated browser cookies.

mod cookies;
mod organization;

pub use cookies::TestCookie;
pub use organization::TestOrganizationApi;

use super::endpoint_context::EndpointContext;
use super::user_admission::{
    self, UserValidationAction, UserValidationRejection, UserValidationSource, ValidateUserInfo,
};
use async_trait::async_trait;
use better_auth_core::store::database_hooks::{DatabaseHookContext, DatabaseHooks};
use better_auth_core::wire::{SessionView, UserView, VerificationView};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateSession, CreateUser, FieldMap,
};
use chrono::Utc;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Enable native test helpers. This plugin exposes privileged database operations.
#[derive(Debug, Clone, Default)]
pub struct TestUtilsPlugin {
    /// Capture OTP values after successful verification creation.
    pub capture_otp: bool,
}

/// Per-instance OTP capture. Clearing the sink does not delete verification records.
#[derive(Default)]
pub struct OtpCapture(RwLock<HashMap<String, String>>);
impl OtpCapture {
    /// Read the last captured OTP for an identifier after prefix normalization.
    pub fn get(&self, identifier: &str) -> AuthResult<Option<String>> {
        Ok(self
            .0
            .read()
            .map_err(|_| AuthError::internal("OTP capture lock poisoned"))?
            .get(identifier)
            .cloned())
    }
    /// Clear captured OTPs without changing persisted verification records.
    pub fn clear(&self) -> AuthResult<()> {
        self.0
            .write()
            .map_err(|_| AuthError::internal("OTP capture lock poisoned"))?
            .clear();
        Ok(())
    }
}
struct TestState {
    otps: Option<Arc<OtpCapture>>,
}
struct CaptureHook(Arc<OtpCapture>);
#[better_auth_core::database_hooks("plugin:test-utils")]
impl<S: AuthSchema> DatabaseHooks<S> for CaptureHook {
    async fn after_create_verification(
        &self,
        verification: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let value = verification.value.field_value();
        if !value.is_truthy() {
            return Ok(());
        }
        let identifier = verification.identifier.field_value();
        if !identifier.is_truthy() {
            return Ok(());
        }
        let value = value
            .as_str()
            .ok_or_else(|| AuthError::internal("verification.value.split is not a function"))?;
        let Some(value) = value.split(':').next().filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        let identifier = identifier
            .as_str()
            .ok_or_else(|| AuthError::internal("identifier.startsWith is not a function"))?;
        let identifier = [
            "email-verification-otp-",
            "sign-in-otp-",
            "forget-password-otp-",
            "phone-verification-otp-",
        ]
        .into_iter()
        .find_map(|prefix| identifier.strip_prefix(prefix))
        .unwrap_or(identifier);
        let _ = self
            .0
            .0
            .write()
            .map_err(|_| AuthError::internal("OTP capture lock poisoned"))?
            .insert(identifier.to_owned(), value.to_owned());
        Ok(())
    }
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for TestUtilsPlugin {
    fn name(&self) -> &'static str {
        "test-utils"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let otps = self.capture_otp.then(|| Arc::new(OtpCapture::default()));
        if let Some(sink) = &otps {
            context.register_database_hook(Arc::new(CaptureHook(sink.clone())));
        }
        context.extensions.insert(TestState { otps });
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

/// Input shared by the session and cookie helpers. Core session keys are ignored.
#[derive(Debug, Clone)]
pub struct TestAuthOptions {
    /// Existing user ID. `login` checks existence; cookie helpers do not.
    pub user_id: String,
    /// Plugin and application session fields.
    pub session: FieldMap,
}
impl TestAuthOptions {
    /// Use the configured session defaults for this user.
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            session: FieldMap::new(),
        }
    }
}

/// The session, user, and credentials from one native login operation.
#[derive(Debug)]
pub struct TestLogin {
    /// Session created by this login operation.
    pub session: SessionView,
    /// Internal adapter user projection, including fields hidden from public responses.
    pub user: UserView,
    /// Raw signed Cookie request header.
    pub headers: HashMap<String, String>,
    /// Browser cookie values and attributes for the same session.
    pub cookies: Vec<TestCookie>,
    /// Unsigned session token.
    pub token: String,
}

/// Native helpers bound to one initialized authentication instance.
pub struct TestUtilsApi<'a, S: AuthSchema> {
    auth: &'a AuthContext<S>,
    state: &'a TestState,
    endpoint: Option<&'a EndpointContext<'a, S>>,
}
impl<'a, S: AuthSchema> TestUtilsApi<'a, S> {
    /// Access helpers only when `TestUtilsPlugin` is installed on this instance.
    pub fn from_context(auth: &'a AuthContext<S>) -> AuthResult<Self> {
        let state = auth
            .extensions
            .get::<TestState>()
            .ok_or_else(|| AuthError::config("TestUtilsPlugin is not enabled"))?;
        Ok(Self {
            auth,
            state,
            endpoint: None,
        })
    }
    /// Preserve the active transaction when invoking helpers from an endpoint callback.
    pub fn from_endpoint(endpoint: &'a EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.endpoint = Some(endpoint);
        Ok(api)
    }
    /// Build a user without persisting it. The configured ID generator still runs for explicit IDs.
    pub fn create_user(&self, mut overrides: CreateUser) -> AuthResult<CreateUser> {
        let id = self.generate_id("user")?;
        let now = better_auth_core::FieldDate::from(Utc::now());
        let _ = overrides.id.get_or_insert(id);
        let _ = overrides
            .email
            .get_or_insert_with(|| format!("test-{}@example.com", random_lower(8)));
        if overrides.name.is_undefined() {
            overrides.name = Some("Test User".into()).into();
        }
        let _ = overrides.email_verified.get_or_insert(true);
        if overrides.image.is_undefined() {
            overrides.image = None.into();
        }
        let _ = overrides.created_at.get_or_insert(now.clone());
        let _ = overrides.updated_at.get_or_insert(now);
        Ok(overrides)
    }
    /// Persist a user through admission and database hooks. A cancelled before hook returns `None`.
    pub async fn save_user(&self, mut user: CreateUser) -> AuthResult<Option<UserView>> {
        if let Some(endpoint) = self.endpoint {
            user_admission::validate_create(
                &user,
                UserValidationSource::new("test", UserValidationAction::CreateUser),
                endpoint,
            )
            .await
            .map_err(UserValidationRejection::into_auth_error)?;
        } else if self
            .auth
            .extensions
            .get::<Arc<dyn ValidateUserInfo<S>>>()
            .is_some()
        {
            let current =
                better_auth_core::hooks::current_request_hook_context().ok_or_else(|| {
                    UserValidationRejection::new("validation_context_missing")
                        .with_description("User validation requires an endpoint context")
                        .into_auth_error()
                })?;
            let endpoint = EndpointContext::new(Some(&current.request), current.body, self.auth);
            user_admission::validate_create(
                &user,
                UserValidationSource::new("test", UserValidationAction::CreateUser),
                &endpoint,
            )
            .await
            .map_err(UserValidationRejection::into_auth_error)?;
        }
        if let Some(email) = &mut user.email {
            *email = email.to_lowercase();
        }
        super::helpers::apply_default_role(self.auth, &mut user);
        match self.endpoint.and_then(|endpoint| endpoint.transaction) {
            Some(tx) => tx.create_user_optional(user).await,
            None => self.auth.database.create_user_optional(user).await,
        }
    }
    /// Delete the user through the internal adapter's session and account cleanup.
    pub async fn delete_user(&self, id: &str) -> AuthResult<()> {
        match self.endpoint.and_then(|endpoint| endpoint.transaction) {
            Some(tx) => tx.delete_user(id).await,
            None => self.auth.database.delete_user(id).await,
        }
    }
    /// Organization factories are available only when the organization plugin is installed.
    pub fn organization(&self) -> Option<TestOrganizationApi<'_, S>> {
        (self
            .auth
            .metadata
            .get("organization.enabled")
            .and_then(Value::as_bool)
            == Some(true))
        .then_some(TestOrganizationApi { api: self })
    }
    /// OTP capture is absent unless explicitly enabled for this instance.
    pub fn otps(&self) -> Option<&OtpCapture> {
        self.state.otps.as_deref()
    }
    /// Create one session after confirming that the user exists.
    pub async fn login(&self, options: TestAuthOptions) -> AuthResult<TestLogin> {
        let user = match self.endpoint.and_then(|endpoint| endpoint.transaction) {
            Some(tx) => tx.get_user_by_id(&options.user_id).await?,
            None => self.auth.database.get_user_by_id(&options.user_id).await?,
        }
        .ok_or_else(|| AuthError::internal(format!("User not found: {}", options.user_id)))?;
        let session = self.create_session(options).await?;
        let token = session.token.clone();
        Ok(TestLogin {
            headers: cookies::headers(self.auth, &token),
            cookies: cookies::cookies(self.auth, &token, None),
            token,
            session,
            user,
        })
    }
    /// Create a fresh session and its raw signed Cookie request header without a user lookup.
    pub async fn get_auth_headers(
        &self,
        options: TestAuthOptions,
    ) -> AuthResult<HashMap<String, String>> {
        let session = self.create_session(options).await?;
        Ok(cookies::headers(self.auth, &session.token))
    }
    /// Create a fresh session and browser-cookie attributes without a user lookup.
    pub async fn get_cookies(
        &self,
        options: TestAuthOptions,
        domain: Option<&str>,
    ) -> AuthResult<Vec<TestCookie>> {
        let session = self.create_session(options).await?;
        Ok(cookies::cookies(self.auth, &session.token, domain))
    }
    fn generate_id(&self, model: &str) -> AuthResult<String> {
        Ok(self
            .auth
            .config
            .advanced
            .generate_id(model, None)?
            .unwrap_or_else(|| better_auth_core::id::random_id(Some(24))))
    }
    async fn create_session(&self, mut options: TestAuthOptions) -> AuthResult<SessionView> {
        for field in [
            "id",
            "userId",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "token",
            "ipAddress",
            "userAgent",
        ] {
            let _ = options.session.remove(field);
        }
        for (name, plugin) in [
            ("impersonatedBy", "admin.enabled"),
            ("activeOrganizationId", "organization.enabled"),
            ("activeTeamId", "organization.teams_enabled"),
        ] {
            if self.auth.metadata.get(plugin).and_then(Value::as_bool) != Some(true) {
                let _ = options.session.remove(name);
            }
        }
        let meta = if let Some(endpoint) = self.endpoint {
            let request = AuthRequest::new(better_auth_core::HttpMethod::Post, "/")
                .with_optional_headers(
                    endpoint
                        .headers()
                        .cloned()
                        .or_else(|| endpoint.request.map(|request| request.headers.clone())),
                );
            better_auth_core::RequestMeta::from_request_with_config(
                &request,
                &self.auth.config.advanced.ip_address,
            )
        } else {
            better_auth_core::hooks::current_request_hook_context()
                .map(|context| context.meta)
                .unwrap_or_default()
        };
        let input = CreateSession {
            user_id: options.user_id.into(),
            expires_at: (Utc::now() + self.auth.config.session.expires_in()).into(),
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: options.session,
        };
        match self.endpoint.and_then(|endpoint| endpoint.transaction) {
            Some(tx) => tx.create_session_optional(input).await?,
            None => self.auth.database.create_session_optional(input).await?,
        }
        .ok_or_else(|| AuthError::internal("Cannot read properties of null (reading 'token')"))
    }
}

fn random_lower(length: usize) -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .filter(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
        .take(length)
        .map(char::from)
        .collect()
}
