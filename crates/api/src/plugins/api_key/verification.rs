use better_auth_core::store::ConsumeApiKeyResult;
use better_auth_core::wire::{ApiKeyView, SessionView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, BeforeRequestAction, FieldValue,
};

use super::request::{CapturedInput, VerifyKeyRequest};
use super::{ApiKeyEndpoint, ApiKeyErrorCode, ApiKeyPlugin, ApiKeyReferences, config_id_matches};

#[cfg(test)]
#[path = "validator_error_tests.rs"]
mod validator_error_tests;

/// Inputs for server-only API key verification. Verification consumes one use.
pub struct VerifyApiKey<'a> {
    /// The plaintext API key presented by the caller.
    pub key: &'a str,
    /// Restrict verification to this configuration, or use the default lookup configuration.
    pub config_id: Option<&'a str>,
    /// Required resource permissions, checked before quota or rate-limit consumption.
    pub permissions: Option<&'a serde_json::Value>,
}

#[path = "verification_error.rs"]
mod error;
pub use error::{
    ApiKeyErrorDetails, ApiKeyErrorMessage, ApiKeyValidationError, ApiKeyVerificationError,
};

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
        let body = FieldValue::from_json(serde_json::Value::Object(body))?;
        let endpoint = ApiKeyEndpoint::new(ctx, None, None, &body);
        let session = self
            .authenticate_api_key(endpoint, ctx, None)
            .await
            .map_err(ApiKeyVerificationError::Endpoint)?;
        let validated = super::request::validate_value("verifyApiKey", &body)
            .map_err(ApiKeyVerificationError::Endpoint)?;
        let body = validated.field_value();
        let input = validated.get::<VerifyKeyRequest>().ok_or_else(|| {
            ApiKeyVerificationError::Endpoint(AuthError::internal(
                "API key body validator returned a different input type",
            ))
        })?;
        let endpoint = ApiKeyEndpoint {
            path: Some(if session.is_some() { "/" } else { "virtual:" }),
            body: &body,
            ..endpoint
        };
        let config = self
            .resolve_configuration(input.config_id.as_deref())
            .map_err(ApiKeyVerificationError::Endpoint)?;
        if input.config_id.is_some()
            && let Some(validator) = &config.custom_api_key_validator
            && !validator
                .validate(&input.key, endpoint)
                .await
                .map_err(ApiKeyVerificationError::Endpoint)?
        {
            return Err(ApiKeyVerificationError::Validation(
                ApiKeyValidationError::invalid_constant(ApiKeyErrorCode::KeyNotFound),
            ));
        }
        let result = async {
            let captured = CapturedInput::new(input, &body)?;
            let key = self
                .validate_api_key(&captured, ctx, endpoint, input.config_id.is_none())
                .await?;
            let config = self.resolve_configuration(key.config_id.as_str())?;
            if config.defer_updates {
                self.start_expired_cleanup(ctx, true, true).await?;
            }
            Ok(key)
        }
        .await;
        let key = match result {
            Ok(key) => key,
            Err(mut error) => {
                let cause: &(dyn std::error::Error + Send + Sync + 'static) = match &mut error {
                    ApiKeyVerificationError::Rejected(error)
                    | ApiKeyVerificationError::Internal(error)
                    | ApiKeyVerificationError::Endpoint(error) => error,
                    ApiKeyVerificationError::Validation(error) => error.capture_native(),
                };
                ctx.logger()
                    .error(
                        "Failed to validate API key:",
                        &[better_auth_core::observability::LogArgument::Error(cause)],
                    )
                    .map_err(ApiKeyVerificationError::Endpoint)?;
                return Err(match error {
                    ApiKeyVerificationError::Internal(error) => {
                        if error
                            .is_api_error()
                            .map_err(ApiKeyVerificationError::Endpoint)?
                        {
                            ApiKeyVerificationError::Rejected(error)
                        } else {
                            ApiKeyVerificationError::Internal(error)
                        }
                    }
                    error => error,
                });
            }
        };
        let config = self
            .resolve_configuration(key.config_id.as_str())
            .map_err(ApiKeyVerificationError::Endpoint)?;
        super::metadata::single(key, config, ctx)
            .await
            .map_err(ApiKeyVerificationError::Endpoint)
    }

    async fn validate_api_key(
        &self,
        input: &CapturedInput<'_, VerifyKeyRequest>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        endpoint: ApiKeyEndpoint<'_>,
        run_custom_validator: bool,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        let lookup_config = self
            .resolve_configuration(input.typed.config_id.as_deref())
            .map_err(|_| ApiKeyErrorCode::NoDefaultConfiguration)?;
        let hashed = if lookup_config.disable_key_hashing {
            input.typed.key.clone()
        } else {
            Self::hash_key(&input.typed.key)
        };
        let api_key = super::storage::get_by_hash(lookup_config, ctx, &hashed)
            .await?
            .ok_or(ApiKeyErrorCode::InvalidApiKey)?;

        if input
            .typed
            .config_id
            .as_deref()
            .is_some_and(|expected| !config_id_matches(&api_key.config_id, expected))
        {
            return Err(ApiKeyErrorCode::InvalidApiKey.into());
        }
        let config = self
            .resolve_configuration(api_key.config_id.as_str())
            .map_err(|_| ApiKeyErrorCode::NoDefaultConfiguration)?;

        if run_custom_validator
            && let Some(validator) = &config.custom_api_key_validator
            && !validator.validate(&input.typed.key, endpoint).await?
        {
            return Err(ApiKeyErrorCode::KeyNotFound.into());
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

        let required = input.field("permissions");
        if required.is_truthy() {
            let permissions = api_key.permissions.field_value();
            let permitted = permissions.is_truthy()
                && super::permissions::check_permissions(&permissions, &required)?;
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
        let body = req.input_field_value()?;
        let endpoint = ApiKeyEndpoint::from_request(ctx, req, &body);
        let Some((session, user)) = self.authenticate_api_key(endpoint, ctx, Some(req)).await?
        else {
            return Ok(None);
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
        request: Option<&AuthRequest>,
    ) -> AuthResult<Option<(SessionView, better_auth_core::wire::UserView)>> {
        // Upstream invokes extraction once in the hook matcher, then again in its handler.
        if better_auth_core::hooks::run_before_hook_matcher(
            &ctx.config,
            request,
            "plugin:api-key",
            || self.find_session_key(endpoint),
        )?
        .is_none()
        {
            return Ok(None);
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
                let Some((config, key)) = self.find_session_key(endpoint)? else {
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
                    && !validator.validate(&key, endpoint).await?
                {
                    return Err(AuthResponse::json(
                        403,
                        &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
                    )?
                    .into());
                }
                let input = VerifyKeyRequest {
                    key: key.clone(),
                    config_id: Some(config.config_id.clone()),
                };
                let input = CapturedInput::new(&input, &FieldValue::Undefined)?;
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
                self.start_expired_cleanup(ctx, config.defer_updates, true)
                    .await?;

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
                    user_id: view.reference_id,
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
                        .headers
                        .and_then(|headers| headers.get(&header.to_ascii_lowercase()))
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
