mod grant;
mod redemption;
mod request;
mod request_fields;
pub use better_auth_core::DeviceCodeOwnership;
use chrono::{Duration, Utc};
pub use grant::{DeviceGrant, DeviceGrantAuthorization, DeviceGrantFuture};
use rand::{
    RngCore,
    distributions::{Alphanumeric, DistString},
};
pub use redemption::{
    DeviceCodeRedemptionAuthorization, DeviceCodeRedemptionResult, DeviceRedemptionFuture,
    redeem_device_code,
};
pub use request_fields::{
    DeviceFieldValidation, DeviceRequestField, DeviceRequestFields, DeviceRequestIssue,
};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
pub use types::DeviceAuthorizationRequest;
use url::Url;

use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::helpers::{SessionIssueError, issue_user_session};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateDeviceCode, DatabaseError,
    DeviceCode, RequestMeta, UpdateDeviceCode,
};

pub(super) mod types;

#[cfg(test)]
mod tests;

use types::{
    DeviceActionRequest, DeviceActionResponse, DeviceCodeResponse, DeviceErrorResponse,
    DeviceReviewContext, DeviceTokenRequest, DeviceTokenResponse, DeviceVerifyResponse,
};

const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_STATUS_PENDING: &str = "pending";
const DEVICE_STATUS_APPROVED: &str = "approved";
const DEVICE_STATUS_DENIED: &str = "denied";
const DEFAULT_USER_CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const INVALID_DEVICE_CODE: &str = "Invalid device code";
const EXPIRED_DEVICE_CODE: &str = "Device code has expired";
const EXPIRED_USER_CODE: &str = "User code has expired";
const AUTHORIZATION_PENDING: &str = "Authorization pending";
const ACCESS_DENIED: &str = "Access denied";
const INVALID_USER_CODE: &str = "Invalid user code";
const DEVICE_CODE_ALREADY_PROCESSED: &str = "Device code already processed";
const DEVICE_CODE_NOT_CLAIMED: &str = "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying";
const POLLING_TOO_FREQUENTLY: &str = "Polling too frequently";
const USER_NOT_FOUND: &str = "User not found";
const FAILED_TO_CREATE_SESSION: &str = "Failed to create session";
const INVALID_DEVICE_CODE_STATUS: &str = "Invalid device code status";
const AUTHENTICATION_REQUIRED: &str = "Authentication required";
const INVALID_CLIENT_ID: &str = "Invalid client ID";
const CLIENT_ID_MISMATCH: &str = "Client ID mismatch";
const INVALID_REQUEST: &str = "Invalid request";

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type ValidateClientCallback = dyn Fn(String) -> BoxFuture<AuthResult<bool>> + Send + Sync;
type DeviceAuthRequestCallback =
    dyn Fn(String, Option<String>) -> BoxFuture<AuthResult<()>> + Send + Sync;
type CodeGenerator = dyn Fn() -> BoxFuture<AuthResult<String>> + Send + Sync;

#[derive(Clone)]
struct DeviceAuthorizationConfig {
    expires_in: Duration,
    interval: Duration,
    device_code_length: usize,
    user_code_length: usize,
    generate_device_code: Option<Arc<CodeGenerator>>,
    generate_user_code: Option<Arc<CodeGenerator>>,
    validate_client: Option<Arc<ValidateClientCallback>>,
    on_device_auth_request: Option<Arc<DeviceAuthRequestCallback>>,
    verification_uri: Option<String>,
    request_fields: Option<DeviceRequestFields>,
    grant_fields: Option<better_auth_core::user_fields::UserConfig>,
    grant_metadata: grant::GrantMetadata,
}

impl Default for DeviceAuthorizationConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(30),
            interval: Duration::seconds(5),
            device_code_length: 40,
            user_code_length: 8,
            generate_device_code: None,
            generate_user_code: None,
            validate_client: None,
            on_device_auth_request: None,
            verification_uri: None,
            request_fields: None,
            grant_fields: None,
            grant_metadata: grant::GrantMetadata::default(),
        }
    }
}

impl fmt::Debug for DeviceAuthorizationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorizationConfig")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .field("device_code_length", &self.device_code_length)
            .field("user_code_length", &self.user_code_length)
            .field(
                "generate_device_code",
                &self.generate_device_code.as_ref().map(|_| "custom"),
            )
            .field(
                "generate_user_code",
                &self.generate_user_code.as_ref().map(|_| "custom"),
            )
            .field(
                "validate_client",
                &self.validate_client.as_ref().map(|_| "custom"),
            )
            .field(
                "on_device_auth_request",
                &self.on_device_auth_request.as_ref().map(|_| "custom"),
            )
            .field("verification_uri", &self.verification_uri)
            .field(
                "request_fields",
                &self.request_fields.as_ref().map(|_| "configured"),
            )
            .field("grant", &self.grant_fields.as_ref().map(|_| "configured"))
            .finish()
    }
}

#[derive(Clone, Copy)]
enum DeviceDecision {
    Approve,
    Deny,
}

impl DeviceDecision {
    fn status(self) -> &'static str {
        match self {
            Self::Approve => DEVICE_STATUS_APPROVED,
            Self::Deny => DEVICE_STATUS_DENIED,
        }
    }

    fn forbidden_message(self) -> &'static str {
        match self {
            Self::Approve => "You are not authorized to approve this device authorization",
            Self::Deny => "You are not authorized to deny this device authorization",
        }
    }
}

/// OAuth 2.0 device authorization grant plugin.
pub struct DeviceAuthorizationPlugin {
    config: DeviceAuthorizationConfig,
}

impl Default for DeviceAuthorizationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuthorizationPlugin {
    /// Create the plugin with TS-aligned defaults.
    pub fn new() -> Self {
        Self {
            config: DeviceAuthorizationConfig::default(),
        }
    }

    /// Validate additional request fields without changing client authorization or storing those fields.
    pub fn request_fields(mut self, fields: DeviceRequestFields) -> Self {
        self.config.request_fields = Some(fields);
        self
    }

    /// Override the device-code expiration window.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.config.expires_in = duration;
        self
    }

    /// Override the minimum polling interval enforced by `/device/token`.
    pub fn interval(mut self, duration: Duration) -> Self {
        self.config.interval = duration;
        self
    }

    /// Override the generated device-code length.
    pub fn device_code_length(mut self, length: usize) -> Self {
        self.config.device_code_length = length;
        self
    }

    /// Override the generated user-code length.
    pub fn user_code_length(mut self, length: usize) -> Self {
        self.config.user_code_length = length;
        self
    }

    /// Override the verification page URI returned to devices.
    pub fn verification_uri(mut self, uri: impl Into<String>) -> Self {
        self.config.verification_uri = Some(uri.into());
        self
    }

    /// Await a custom device-code generator before generating the user code.
    pub fn generate_device_code_with<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.config.generate_device_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    /// Await a custom user-code generator before persisting the code pair.
    pub fn generate_user_code_with<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.config.generate_user_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    /// Validate the OAuth client identifier before issuing or redeeming codes.
    pub fn validate_client<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<bool>> + Send + 'static,
    {
        self.config.validate_client =
            Some(Arc::new(move |client_id| Box::pin(callback(client_id))));
        self
    }

    /// Run a hook when a device authorization request is created.
    pub fn on_device_auth_request<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(String, Option<String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<()>> + Send + 'static,
    {
        self.config.on_device_auth_request = Some(Arc::new(move |client_id, scope| {
            Box::pin(callback(client_id, scope))
        }));
        self
    }

    async fn handle_device_code<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body = request::normalize_code(
            req,
            request::read_code(
                req,
                self.config.request_fields.as_ref(),
                self.config.grant_fields.is_some(),
            )
            .await?,
        )?;

        let authorization = if self.config.grant_fields.is_some() {
            let endpoint = EndpointContext::new(Some(req), serde_json::to_value(&body)?, ctx);
            self.authorize_request(&body, &endpoint).await?
        } else {
            let Some(client_id) = body.client_id.as_ref() else {
                return Err(device_error_response(
                    400,
                    "invalid_request",
                    "client_id is required",
                )?
                .into());
            };
            if !self.validate_client_id(client_id).await? {
                return device_error_response(400, "invalid_client", INVALID_CLIENT_ID);
            }
            DeviceGrantAuthorization {
                client_id: client_id.clone(),
                additional_fields: Default::default(),
            }
        };

        if let Some(callback) = &self.config.on_device_auth_request {
            callback(authorization.client_id.clone(), body.scope.clone()).await?;
        }

        let expires_at = Utc::now() + self.config.expires_in;
        let polling_interval = self.config.interval.num_seconds() as f64 * 1000.0
            + f64::from(self.config.interval.subsec_nanos()) / 1_000_000.0;
        for _ in 0..3 {
            let device_code = self.generate_device_code().await?;
            let user_code = self.generate_user_code().await?;
            match ctx
                .database
                .create_device_code(CreateDeviceCode {
                    additional_fields: authorization.additional_fields.clone(),
                    device_code: device_code.clone(),
                    user_code: user_code.clone(),
                    user_id: body.user_id.clone().filter(|id| !id.is_empty()),
                    expires_at,
                    status: DEVICE_STATUS_PENDING.to_string(),
                    last_polled_at: None,
                    polling_interval: Some(polling_interval),
                    client_id: Some(authorization.client_id.clone()),
                    scope: body
                        .scope
                        .clone()
                        .map(|scope| Some(scope).into())
                        .unwrap_or_default(),
                })
                .await
            {
                Ok(_) => {}
                Err(AuthError::Database(DatabaseError::UniqueConstraint(_))) => continue,
                Err(error) => return Err(error),
            }

            let (verification_uri, verification_uri_complete) = build_verification_uris(
                self.config.verification_uri.as_deref(),
                ctx.base_url(),
                &user_code,
            )?;

            return Ok(AuthResponse::json(
                200,
                &DeviceCodeResponse {
                    device_code,
                    user_code,
                    verification_uri,
                    verification_uri_complete,
                    expires_in: self.config.expires_in.as_seconds_f64().floor() as i64,
                    interval: self.config.interval.as_seconds_f64().floor() as i64,
                },
            )?
            .with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache"));
        }
        device_error_response(
            500,
            "server_error",
            "Failed to generate a unique device code",
        )
    }

    async fn handle_device_token<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body: DeviceTokenRequest = request::read(req, request::token)?;

        if !self.validate_client_id(&body.client_id).await? {
            return device_error_response(400, "invalid_grant", INVALID_CLIENT_ID);
        }

        let endpoint = EndpointContext::new(Some(req), serde_json::to_value(&body)?, ctx);
        let client_id = body.client_id;
        let grant = self.configured_grant(ctx)?;
        let redemption = redeem_device_code(
            &endpoint,
            &body.device_code,
            move |device_code, endpoint| {
                Box::pin(async move {
                    let stored_client_id: Option<String> = serde_json::from_value(
                        device_code
                            .client_id
                            .json()?
                            .unwrap_or(serde_json::Value::Null),
                    )?;
                    if let Some(stored_client_id) = stored_client_id.as_deref()
                        && stored_client_id != client_id
                    {
                        return Err(device_error_response(
                            400,
                            "invalid_grant",
                            CLIENT_ID_MISMATCH,
                        )?
                        .into());
                    }
                    if let Some(grant) = grant {
                        grant
                            .assert_session_redemption(device_code, endpoint)
                            .await?;
                    }
                    Ok(DeviceCodeRedemptionAuthorization {
                        ownership: DeviceCodeOwnership::ClientId(client_id),
                        context: (),
                    })
                })
            },
            |_device_code, _authorization, _endpoint| Box::pin(async { Ok(()) }),
        )
        .await;
        let device_code = match redemption {
            Ok(redemption) => redemption.claimed_device_code,
            Err(error @ AuthError::Response(_)) => return Ok(error.to_auth_response()),
            Err(error) => return Err(error),
        };
        let Some(user_id) = device_code.user_id.as_deref() else {
            return device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS);
        };
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        let session = match issue_user_session(ctx, user_id, meta.ip_address, meta.user_agent)
            .await
            .map_err(SessionIssueError::into_auth_error)
        {
            Ok(issued) => issued.session,
            Err(error) => {
                better_auth_core::observability::logger::current().error(
                    "failed to create session after device code redemption",
                    &[
                        better_auth_core::observability::LogArgument::Error(&error),
                        better_auth_core::observability::LogArgument::Value(&serde_json::json!(
                            device_code.id
                        )),
                        better_auth_core::observability::LogArgument::Value(&serde_json::json!(
                            user_id
                        )),
                    ],
                );
                return device_error_response(500, "server_error", FAILED_TO_CREATE_SESSION);
            }
        };

        Ok(AuthResponse::json(
            200,
            &DeviceTokenResponse {
                access_token: session.token().to_string(),
                token_type: "Bearer",
                expires_in: (session.expires_at().timestamp_millis()
                    - Utc::now().timestamp_millis())
                .div_euclid(1000)
                .max(0),
                scope: serde_json::from_value::<Option<String>>(
                    device_code.scope.json()?.unwrap_or(serde_json::Value::Null),
                )?
                .unwrap_or_default(),
            },
        )?
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache"))
    }

    async fn handle_device_verify<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let Some(user_code) = req.query_string("user_code")?.map(str::to_owned) else {
            return device_error_response(400, "invalid_request", INVALID_REQUEST);
        };

        let Some(mut device_code) = find_device_code_by_user_code(ctx, &user_code).await? else {
            return device_error_response(400, "invalid_request", INVALID_USER_CODE);
        };

        if device_code.expires_at < Utc::now() {
            return device_error_response(400, "expired_token", EXPIRED_USER_CODE);
        }

        let user_id = match ctx.require_session(req).await {
            Ok((user, _)) => Some(user.id().into_owned()),
            Err(AuthError::Unauthenticated) => None,
            Err(error) => return Err(error),
        };
        if let Some(user_id) = user_id.as_ref().and_then(|id| id.as_str())
            && device_code.user_id.is_none()
            && device_code.status == DEVICE_STATUS_PENDING
            && ctx
                .database
                .claim_device_code(&device_code.id, user_id)
                .await?
        {
            device_code.user_id = Some(user_id.to_string());
        }
        let can_review = user_id.is_some()
            && device_code.user_id.as_deref() == user_id.as_ref().and_then(|id| id.as_str());
        let additional_fields = if can_review {
            match self.configured_grant(ctx)? {
                Some(grant) => grant.verification_context_for(&device_code)?,
                None => Default::default(),
            }
        } else {
            Default::default()
        };

        AuthResponse::json(
            200,
            &DeviceVerifyResponse {
                user_code,
                status: device_code.status,
                review: can_review.then_some(DeviceReviewContext {
                    additional_fields,
                    client_id: device_code.client_id,
                    scope: device_code.scope,
                }),
            },
        )
        .map_err(AuthError::from)
    }

    async fn handle_device_approve(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.handle_device_decision(req, ctx, DeviceDecision::Approve)
            .await
    }

    async fn handle_device_deny(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.handle_device_decision(req, ctx, DeviceDecision::Deny)
            .await
    }

    async fn handle_device_decision(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        decision: DeviceDecision,
    ) -> AuthResult<AuthResponse> {
        let user = match ctx.require_session(req).await {
            Ok((user, _session)) => user,
            Err(AuthError::Unauthenticated) | Err(AuthError::SessionNotFound) => {
                return device_error_response(401, "unauthorized", AUTHENTICATION_REQUIRED);
            }
            Err(error) => return Err(error),
        };

        let current_user_id = user.id().into_owned();
        let body: DeviceActionRequest = request::read(req, request::action)?;

        let Some(device_code) = find_device_code_by_user_code(ctx, &body.user_code).await? else {
            return device_error_response(400, "invalid_request", INVALID_USER_CODE);
        };

        if device_code.expires_at < Utc::now() {
            return device_error_response(400, "expired_token", EXPIRED_USER_CODE);
        }

        if device_code.status != DEVICE_STATUS_PENDING {
            return device_error_response(400, "invalid_request", DEVICE_CODE_ALREADY_PROCESSED);
        }

        // The code must already be bound to a user by `GET /device`. Without
        // this, any signed-in caller who knows a user_code could approve a
        // device they never claimed.
        let Some(claimed_user_id) = device_code.user_id.as_deref() else {
            return device_error_response(400, "invalid_request", DEVICE_CODE_NOT_CLAIMED);
        };

        if current_user_id != claimed_user_id {
            return device_error_response(403, "access_denied", decision.forbidden_message());
        }

        let updated_user_id = claimed_user_id.to_string();

        let updated = ctx
            .database
            .update_device_code_if_status(
                &device_code.id,
                DEVICE_STATUS_PENDING,
                UpdateDeviceCode {
                    status: Some(decision.status().to_string()),
                    user_id: Some(Some(updated_user_id)),
                    ..Default::default()
                },
            )
            .await?;

        if !updated {
            return device_error_response(400, "invalid_request", DEVICE_CODE_ALREADY_PROCESSED);
        }

        AuthResponse::json(200, &DeviceActionResponse { success: true }).map_err(AuthError::from)
    }

    async fn validate_client_id(&self, client_id: &str) -> AuthResult<bool> {
        match &self.config.validate_client {
            Some(callback) => callback(client_id.to_string()).await,
            None => Ok(true),
        }
    }

    async fn generate_device_code(&self) -> AuthResult<String> {
        let code = match &self.config.generate_device_code {
            Some(generator) => generator().await?,
            None => {
                Alphanumeric.sample_string(&mut rand::rngs::OsRng, self.config.device_code_length)
            }
        };
        validate_generated_code(code, "device")
    }

    async fn generate_user_code(&self) -> AuthResult<String> {
        let code = match &self.config.generate_user_code {
            Some(generator) => generator().await?,
            None => default_generate_user_code(self.config.user_code_length),
        };
        validate_generated_code(code, "user")
    }
}

fn validate_generated_code(code: String, label: &str) -> AuthResult<String> {
    if code.chars().count() > 191 {
        return Err(device_error_response(
            400,
            "invalid_request",
            &format!("Generated {label} code must be at most 191 characters"),
        )?
        .into());
    }
    Ok(code)
}

#[async_trait::async_trait]
impl<S: better_auth_core::AuthSchema> better_auth_core::AuthPlugin<S>
    for DeviceAuthorizationPlugin
{
    fn name(&self) -> &'static str {
        "device-authorization"
    }

    fn openapi(&self) -> AuthResult<better_auth_core::openapi::OpenApiPluginMetadata> {
        let metadata = better_auth_core::openapi::OpenApiPluginMetadata::from_routes(
            "device-authorization",
            <Self as better_auth_core::AuthPlugin<S>>::routes(self),
        )?;
        if self.config.grant_fields.is_none() {
            return Ok(metadata);
        }
        metadata.device_authorization_grant(
            &self.config.grant_metadata.request_error_codes,
            &self.config.grant_metadata.request_responses,
            &self.config.grant_metadata.verification_properties,
        )
    }

    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        use better_auth_core::AuthRoute;
        let code = AuthRoute::post("/device/code", "deviceCode")
            .allowed_media_types(&["application/json", "application/x-www-form-urlencoded"]);
        let grant = self.config.grant_fields.is_some();
        let code = match (&self.config.request_fields, grant) {
            (None, false) => code.body_validator(request::code),
            (fields, grant) => {
                let fields = fields.as_ref().cloned().unwrap_or_default();
                code.body_validator_async(move |request| {
                    let fields = fields.clone();
                    async move { request::code_with_fields(&request, &fields, grant).await }
                })
            }
        };
        vec![
            code,
            AuthRoute::post("/device/token", "deviceToken").body_validator(request::token),
            AuthRoute::get("/device", "deviceVerify")
                .query_validator(crate::plugins::query_input::device),
            AuthRoute::post("/device/approve", "deviceApprove")
                .body_validator(request::action)
                .require_headers(true),
            AuthRoute::post("/device/deny", "deviceDeny")
                .body_validator(request::action)
                .require_headers(true),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        use better_auth_core::HttpMethod;
        let response = match (req.method(), req.path()) {
            (HttpMethod::Post, "/device/code") => self.handle_device_code(req, ctx).await?,
            (HttpMethod::Post, "/device/token") => self.handle_device_token(req, ctx).await?,
            (HttpMethod::Get, "/device") => self.handle_device_verify(req, ctx).await?,
            (HttpMethod::Post, "/device/approve") => self.handle_device_approve(req, ctx).await?,
            (HttpMethod::Post, "/device/deny") => self.handle_device_deny(req, ctx).await?,
            _ => return Ok(None),
        };
        Ok(Some(response))
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        for (name, length) in [
            ("deviceCodeLength", self.config.device_code_length),
            ("userCodeLength", self.config.user_code_length),
        ] {
            if !(1..=191).contains(&length) {
                return Err(AuthError::config(format!(
                    "{name} must be between 1 and 191"
                )));
            }
        }
        if let Some(fields) = &self.config.grant_fields {
            grant::register_fields(ctx, fields)?;
        }
        Ok(())
    }
    fn rate_limits(&self) -> AuthResult<Vec<better_auth_core::middleware::PluginRateLimit>> {
        let window = self.config.expires_in.num_seconds() as f64
            + f64::from(self.config.expires_in.subsec_nanos()) / 1_000_000_000.0;
        Ok(vec![better_auth_core::middleware::PluginRateLimit::exact(
            "/device",
            better_auth_core::middleware::EndpointRateLimit {
                window,
                max_requests: 5.0,
            },
        )])
    }
}

async fn find_device_code_by_user_code(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_code: &str,
) -> AuthResult<Option<DeviceCode>> {
    if let Some(code) = ctx.database.get_device_code_by_user_code(user_code).await?
        && code.user_code == user_code
    {
        return Ok(Some(code));
    }
    let normalized: String = user_code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if normalized == user_code
        || normalized.is_empty()
        || !normalized
            .bytes()
            .all(|byte| DEFAULT_USER_CODE_CHARSET.contains(&byte))
    {
        return Ok(None);
    }
    Ok(ctx
        .database
        .get_device_code_by_user_code(&normalized)
        .await?
        .filter(|code| code.user_code == normalized))
}

fn build_verification_uris(
    verification_uri: Option<&str>,
    base_url: &str,
    user_code: &str,
) -> AuthResult<(String, String)> {
    let uri = verification_uri
        .filter(|uri| !uri.is_empty())
        .unwrap_or("/device");
    let verification_url = match Url::parse(uri) {
        Ok(url) => url,
        Err(_) => Url::parse(base_url)
            .map_err(|error| AuthError::config(format!("Invalid base URL: {error}")))?
            .join(uri)
            .map_err(|error| {
                AuthError::bad_request(format!("Invalid verification URI: {error}"))
            })?,
    };

    let mut verification_uri_complete = verification_url.clone();
    {
        let mut pairs = verification_uri_complete.query_pairs_mut();
        let _ = pairs.clear();
        let mut replaced = false;
        for (name, value) in verification_url.query_pairs() {
            if name == "user_code" {
                if !replaced {
                    let _ = pairs.append_pair(&name, user_code);
                    replaced = true;
                }
            } else {
                let _ = pairs.append_pair(&name, &value);
            }
        }
        if !replaced {
            let _ = pairs.append_pair("user_code", user_code);
        }
    }

    Ok((
        verification_url.to_string(),
        verification_uri_complete.to_string(),
    ))
}

fn default_generate_user_code(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| {
            let index = usize::from(byte) % DEFAULT_USER_CODE_CHARSET.len();
            DEFAULT_USER_CODE_CHARSET
                .get(index)
                .copied()
                .unwrap_or(b'A') as char
        })
        .collect()
}

fn device_error_response(
    status: u16,
    error: &str,
    error_description: &str,
) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &DeviceErrorResponse {
            error: error.to_string(),
            error_description: error_description.to_string(),
        },
    )
    .map_err(AuthError::from)
}
