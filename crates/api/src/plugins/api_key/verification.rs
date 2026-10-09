use better_auth_core::entity::AuthUser;
use better_auth_core::store::ConsumeApiKeyResult;
use better_auth_core::wire::{ApiKeyView, SessionView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, BeforeRequestAction,
};
use serde::Serialize;

use super::{ApiKeyEndpoint, ApiKeyErrorCode, ApiKeyPlugin, ApiKeyReferences, config_id_matches};

/// Inputs for server-only API key verification. Verification consumes one use.
pub struct VerifyApiKey<'a> {
    /// The plaintext API key presented by the caller.
    pub key: &'a str,
    /// Restrict verification to this configuration, or use the default lookup configuration.
    pub config_id: Option<&'a str>,
    /// Required resource permissions, checked before quota or rate-limit consumption.
    pub permissions: Option<&'a serde_json::Value>,
}

/// Additional information returned when a key reaches its rate limit.
#[derive(Debug, Serialize)]
pub struct ApiKeyErrorDetails {
    /// Milliseconds until the key's rate-limit window elapses.
    #[serde(rename = "tryAgainIn")]
    pub try_again_in: f64,
}

/// An API key rejection with the upstream error code and response fields.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiKeyErrorMessage {
    /// A public error message.
    Text(String),
    /// Upstream returns its complete error constant on selected verification failures.
    Code {
        code: ApiKeyErrorCode,
        message: String,
    },
}

impl std::fmt::Display for ApiKeyErrorMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(message) | Self::Code { message, .. } => formatter.write_str(message),
        }
    }
}

/// An API key rejection with the upstream error code and response fields.
#[derive(Debug, Serialize)]
pub struct ApiKeyValidationError {
    /// Stable upstream API key error code.
    pub code: ApiKeyErrorCode,
    /// Upstream error message.
    pub message: ApiKeyErrorMessage,
    /// Rate-limit timing, when the rejection is a rate limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ApiKeyErrorDetails>,
}

impl ApiKeyValidationError {
    fn new(code: ApiKeyErrorCode) -> Self {
        Self {
            code,
            message: ApiKeyErrorMessage::Text(code.message().to_owned()),
            details: None,
        }
    }

    fn invalid_constant(code: ApiKeyErrorCode) -> Self {
        Self {
            code,
            message: ApiKeyErrorMessage::Code {
                code: ApiKeyErrorCode::InvalidApiKey,
                message: ApiKeyErrorCode::InvalidApiKey.message().to_owned(),
            },
            details: None,
        }
    }

    fn status(&self) -> u16 {
        match self.code {
            ApiKeyErrorCode::NoDefaultConfiguration => 400,
            ApiKeyErrorCode::RateLimited | ApiKeyErrorCode::UsageExceeded => 429,
            _ => 401,
        }
    }

    fn response(&self) -> AuthResult<AuthResponse> {
        AuthResponse::json(self.status(), self)
    }
}

/// Distinguishes a rejected credential from a storage or infrastructure failure.
#[derive(Debug)]
pub enum ApiKeyVerificationError {
    /// The credential or its permissions, quota, or configuration was rejected.
    Validation(ApiKeyValidationError),
    /// An application API error caught by unscoped verification, including its complete response body.
    Rejected(AuthError),
    /// An internal operation failed. The original typed error is preserved.
    Internal(AuthError),
    /// An endpoint hook or scoped validator failed before the verification catch boundary.
    Endpoint(AuthError),
}

impl std::fmt::Display for ApiKeyVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => write!(formatter, "{}", error.message),
            Self::Internal(error) | Self::Endpoint(error) | Self::Rejected(error) => {
                write!(formatter, "API key verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for ApiKeyVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) | Self::Endpoint(error) | Self::Rejected(error) => Some(error),
            Self::Validation(_) => None,
        }
    }
}

impl ApiKeyVerificationError {
    /// Render the server-only endpoint's upstream response while retaining typed errors until this boundary.
    pub fn into_response(self) -> AuthResult<AuthResponse> {
        let error = match self {
            Self::Endpoint(error) => return Ok(error.to_auth_response()),
            Self::Rejected(error) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&error.to_auth_response().body.bytes()?)?;
                return AuthResponse::json(
                    None,
                    &serde_json::json!({"valid":false,"error":body,"key":null}),
                );
            }
            Self::Validation(error) => error,
            Self::Internal(error) => {
                better_auth_core::observability::logger::current().error(
                    "Failed to validate API key",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                ApiKeyValidationError::invalid_constant(ApiKeyErrorCode::InvalidApiKey)
            }
        };
        AuthResponse::json(
            None,
            &serde_json::json!({"valid":false,"error":error,"key":null}),
        )
    }
}

impl From<AuthError> for ApiKeyVerificationError {
    fn from(error: AuthError) -> Self {
        Self::Internal(error)
    }
}

impl From<ApiKeyErrorCode> for ApiKeyVerificationError {
    fn from(code: ApiKeyErrorCode) -> Self {
        Self::Validation(ApiKeyValidationError::new(code))
    }
}

impl ApiKeyPlugin {
    /// Verify a machine credential without a user session or public HTTP endpoint.
    ///
    /// A successful verification consumes quota and a rate-limit slot. Permissions
    /// and configuration mismatches do not consume usage. The returned key omits
    /// the plaintext credential and stored hash.
    ///
    /// Without `config_id`, lookup uses the default configuration's hashing
    /// setting. Validation then uses the configuration that issued the key.
    pub async fn verify_api_key(
        &self,
        input: &VerifyApiKey<'_>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        let mut body = serde_json::Map::from_iter([("key".into(), input.key.into())]);
        if let Some(config_id) = input.config_id {
            let _ = body.insert("configId".into(), config_id.into());
        }
        if let Some(permissions) = input.permissions {
            let _ = body.insert("permissions".into(), permissions.clone());
        }
        let body = serde_json::Value::Object(body);
        let endpoint = ApiKeyEndpoint::new(ctx, None, None, &body);
        let session = self
            .authenticate_api_key(endpoint, ctx)
            .await
            .map_err(ApiKeyVerificationError::Endpoint)?;
        let _ = super::request::validate_value("verifyApiKey", Some(&body))
            .map_err(ApiKeyVerificationError::Endpoint)?;
        let endpoint = ApiKeyEndpoint {
            path: Some(if session.is_some() { "/" } else { "virtual:" }),
            ..endpoint
        };
        let config = self
            .resolve_configuration(input.config_id)
            .map_err(ApiKeyVerificationError::Endpoint)?;
        if input.config_id.is_some()
            && let Some(validator) = &config.custom_api_key_validator
            && !validator
                .validate(input.key, endpoint)
                .await
                .map_err(ApiKeyVerificationError::Endpoint)?
        {
            return Err(ApiKeyVerificationError::Validation(
                ApiKeyValidationError::invalid_constant(ApiKeyErrorCode::KeyNotFound),
            ));
        }
        let key = self
            .validate_api_key(input, ctx, endpoint, input.config_id.is_none())
            .await?;
        let config = self
            .resolve_configuration(key.config_id.as_str())
            .map_err(ApiKeyVerificationError::Endpoint)?;
        super::metadata::single(key, config, ctx)
            .await
            .map_err(ApiKeyVerificationError::Endpoint)
    }

    async fn validate_api_key(
        &self,
        input: &VerifyApiKey<'_>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        endpoint: ApiKeyEndpoint<'_>,
        run_custom_validator: bool,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        let lookup_config = self
            .resolve_configuration(input.config_id)
            .map_err(|_| ApiKeyErrorCode::NoDefaultConfiguration)?;
        let hashed = if lookup_config.disable_key_hashing {
            input.key.to_owned()
        } else {
            Self::hash_key(input.key)
        };
        let api_key = super::storage::get_by_hash(lookup_config, ctx, &hashed)
            .await?
            .ok_or(ApiKeyErrorCode::InvalidApiKey)?;

        if input
            .config_id
            .is_some_and(|expected| !config_id_matches(&api_key.config_id, expected))
        {
            return Err(ApiKeyErrorCode::InvalidApiKey.into());
        }
        let config = self
            .resolve_configuration(api_key.config_id.as_str())
            .map_err(|_| ApiKeyErrorCode::NoDefaultConfiguration)?;

        if run_custom_validator && let Some(validator) = &config.custom_api_key_validator {
            match validator.validate(input.key, endpoint).await {
                Ok(true) => {}
                Ok(false) => return Err(ApiKeyErrorCode::KeyNotFound.into()),
                Err(
                    error @ (AuthError::Internal(_)
                    | AuthError::Database(_)
                    | AuthError::Config(_)
                    | AuthError::Serialization(_)),
                ) => return Err(ApiKeyVerificationError::Internal(error)),
                Err(error) => return Err(ApiKeyVerificationError::Rejected(error)),
            }
        }

        if api_key.enabled.field_value().strict_equals(&false.into()) {
            return Err(ApiKeyErrorCode::KeyDisabled.into());
        }
        if api_key.expires_at.is_truthy()?
            && chrono::Utc::now().timestamp_millis() as f64
                > better_auth_core::query::field_date(&api_key.expires_at.field_value())?
                    .milliseconds()
        {
            super::storage::delete_for_verification(config, ctx, &api_key).await?;
            return Err(ApiKeyErrorCode::KeyExpired.into());
        }

        if let Some(required) = input.permissions {
            let permissions = api_key.permissions.field_value();
            let permitted = permissions.is_truthy()
                && super::permissions::check_permissions(&permissions, required)?;
            if !permitted {
                return Err(ApiKeyErrorCode::KeyNotFound.into());
            }
        }

        let updated = match super::storage::consume(config, ctx, &api_key, &hashed).await? {
            ConsumeApiKeyResult::Allowed(key) => key,
            ConsumeApiKeyResult::RateLimited { try_again_in } => {
                let mut error = ApiKeyValidationError::new(ApiKeyErrorCode::RateLimited);
                error.details = Some(ApiKeyErrorDetails { try_again_in });
                return Err(ApiKeyVerificationError::Validation(error));
            }
            ConsumeApiKeyResult::UsageExhausted => {
                return Err(ApiKeyErrorCode::UsageExceeded.into());
            }
        };
        Ok(ApiKeyView::try_from_api_key(updated.as_ref())?)
    }

    pub(super) async fn api_key_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let body = if let Some(body) = req.parsed_http_body() {
            body.clone()
        } else {
            match req.body.as_deref().filter(|body| !body.is_empty()) {
                Some(body)
                    if req.headers.iter().any(|(name, value)| {
                        name.eq_ignore_ascii_case("content-type")
                            && value
                                .to_ascii_lowercase()
                                .contains("application/x-www-form-urlencoded")
                    }) =>
                {
                    serde_json::Value::Object(
                        url::form_urlencoded::parse(body)
                            .map(|(name, value)| {
                                (
                                    name.into_owned(),
                                    serde_json::Value::String(value.into_owned()),
                                )
                            })
                            .collect(),
                    )
                }
                Some(body) => crate::plugins::json_body::decode(body).map_err(AuthError::from)?,
                None => serde_json::Value::Null,
            }
        };
        let endpoint = ApiKeyEndpoint::new(ctx, Some(req), Some(req.path()), &body);
        let (session, user) = match self.authenticate_api_key(endpoint, ctx).await {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(None),
            Err(error @ AuthError::Response(_)) => {
                return Ok(Some(BeforeRequestAction::Respond(error.to_auth_response())));
            }
            Err(error) => return Err(error),
        };
        // Upstream answers this path in its hook before the route method gate.
        if req.path() == "/get-session" {
            let mut fields = better_auth_core::FieldMap::from(session);
            fields.retain(|name, _| {
                [
                    "id",
                    "token",
                    "userId",
                    "userAgent",
                    "ipAddress",
                    "createdAt",
                    "updatedAt",
                    "expiresAt",
                ]
                .contains(&name.as_str())
            });
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::native(
                None,
                better_auth_core::FieldMap::from([
                    ("user".into(), better_auth_core::FieldMap::from(user).into()),
                    ("session".into(), fields.into()),
                ])
                .into(),
            ))));
        }
        Ok(Some(BeforeRequestAction::InjectSession {
            session: Box::new(session),
        }))
    }

    pub(super) async fn authenticate_api_key(
        &self,
        endpoint: ApiKeyEndpoint<'_>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<(SessionView, better_auth_core::wire::UserView)>> {
        // Upstream invokes extraction once in the hook matcher, then again in its handler.
        match self.find_session_key(endpoint) {
            Ok(None) => return Ok(None),
            Ok(Some(_)) => {}
            Err(error) => {
                better_auth_core::observability::logger::current().error(
                    "API key hook matcher failed",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                return Err(AuthResponse::json(500, &serde_json::json!({
                    "message": "An error occurred during hook matcher execution. Check the logs for more details."
                }))?.into());
            }
        }
        let context = better_auth_core::hooks::current_request_hook_context();
        let route = context
            .as_ref()
            .map(|context| context.path.as_deref().unwrap_or("/:virtual"))
            .or(endpoint.path)
            .unwrap_or("/");
        let operation_id = context
            .as_ref()
            .and_then(|context| context.operation_id.as_deref())
            .unwrap_or(route);
        better_auth_core::observability::with_span(
            &ctx.config.experimental.instrumentation,
            &format!("hook before {route} plugin:api-key"),
            better_auth_core::observability::SpanAttributes {
                route: Some(route),
                operation_id: Some(operation_id),
                hook_type: Some("before"),
                context: Some("plugin:api-key"),
                ..Default::default()
            },
            async {
                let endpoint = ApiKeyEndpoint {
                    path: endpoint.path.or(Some("/")),
                    ..endpoint
                };
                let Some((config, key)) = self
                    .find_session_key(endpoint)
                    .map_err(|error| super::callbacks::callback_error(error, endpoint.request))?
                else {
                    return Err(AuthError::internal(
                        "API key getter stopped matching during hook execution",
                    ));
                };
                if key.encode_utf16().count() < config.key_length {
                    return Err(AuthResponse::json(
                        403,
                        &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
                    )?
                    .into());
                }
                if let Some(validator) = &config.custom_api_key_validator
                    && !validator.validate(&key, endpoint).await.map_err(|error| {
                        super::callbacks::callback_error(error, endpoint.request)
                    })?
                {
                    return Err(AuthResponse::json(
                        403,
                        &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
                    )?
                    .into());
                }
                let input = VerifyApiKey {
                    key: &key,
                    config_id: Some(&config.config_id),
                    permissions: None,
                };
                let view = match self.validate_api_key(&input, ctx, endpoint, false).await {
                    Ok(view) => view,
                    Err(ApiKeyVerificationError::Validation(error)) => {
                        return Err(error.response()?.into());
                    }
                    Err(
                        ApiKeyVerificationError::Internal(error)
                        | ApiKeyVerificationError::Endpoint(error)
                        | ApiKeyVerificationError::Rejected(error),
                    ) => return Err(error),
                };
                self.maybe_delete_expired(ctx).await;

                if config.references != ApiKeyReferences::User {
                    return Err(ApiKeyValidationError::new(
                        ApiKeyErrorCode::InvalidReferenceIdFromApiKey,
                    )
                    .response()?
                    .into());
                }
                let Some(user) = ctx
                    .database
                    .get_user_by_id_field(&view.reference_id)
                    .await?
                else {
                    return Err(ApiKeyValidationError::new(
                        ApiKeyErrorCode::InvalidReferenceIdFromApiKey,
                    )
                    .response()?
                    .into());
                };

                let now = chrono::Utc::now();
                let fallback_expiration = better_auth_core::FieldDate::from(
                    now + chrono::Duration::milliseconds(
                        ctx.config.session.expires_in().num_seconds(),
                    ),
                );
                let expires_at = view.expires_at.field_value();
                let expires_at = if expires_at.is_truthy() {
                    expires_at
                } else {
                    fallback_expiration.clone().into()
                };
                let meta = endpoint.request.map(|req| {
                    better_auth_core::RequestMeta::from_request_with_config(
                        req,
                        &ctx.config.advanced.ip_address,
                    )
                });
                let session = SessionView {
                    visible_fields: None,
                    id: view.id,
                    token: key.to_owned().into(),
                    user_id: user.id().into_owned(),
                    created_at: now.into(),
                    updated_at: now.into(),
                    expires_at: better_auth_core::SchemaValue::from_field(expires_at),
                    ip_address: meta
                        .as_ref()
                        .and_then(|meta| meta.ip_address.clone())
                        .into(),
                    user_agent: meta.and_then(|meta| meta.user_agent).into(),
                    impersonated_by: None.into(),
                    active_organization_id: None.into(),
                    active_team_id: None.into(),
                    active: true,
                    ..Default::default()
                };
                Ok(Some((session, ctx.user_view(&user).await?)))
            },
        )
        .await
    }

    fn find_session_key(
        &self,
        endpoint: ApiKeyEndpoint<'_>,
    ) -> AuthResult<Option<(&super::ApiKeyConfig, String)>> {
        for config in &self.configurations {
            if !config.enable_session_for_api_keys {
                continue;
            }
            let key = if let Some(getter) = &config.custom_api_key_getter {
                getter.get(endpoint)?
            } else {
                config.api_key_headers.iter().find_map(|header| {
                    endpoint
                        .request
                        .and_then(|request| request.headers.get(&header.to_ascii_lowercase()))
                        .filter(|key| !key.is_empty())
                        .cloned()
                })
            };
            if let Some(key) = key.filter(|key| !key.is_empty()) {
                return Ok(Some((config, key)));
            }
        }
        Ok(None)
    }
}
