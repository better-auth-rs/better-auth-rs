use better_auth_core::entity::AuthUser;
use better_auth_core::store::ConsumeApiKeyResult;
use better_auth_core::wire::{ApiKeyView, SessionView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, BeforeRequestAction,
};
use serde::Serialize;

use super::{ApiKeyErrorCode, ApiKeyPlugin, ApiKeyReferences, config_id_matches};

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
pub struct ApiKeyValidationError {
    /// Stable upstream API key error code.
    pub code: ApiKeyErrorCode,
    /// Upstream error message.
    pub message: String,
    /// Rate-limit timing, when the rejection is a rate limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ApiKeyErrorDetails>,
}

impl ApiKeyValidationError {
    fn new(code: ApiKeyErrorCode) -> Self {
        Self {
            code,
            message: code.message().to_owned(),
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
        Ok(AuthResponse::json(self.status(), self)?)
    }
}

/// Distinguishes a rejected credential from a storage or infrastructure failure.
#[derive(Debug)]
pub enum ApiKeyVerificationError {
    /// The credential or its permissions, quota, or configuration was rejected.
    Validation(ApiKeyValidationError),
    /// An internal operation failed. The original typed error is preserved.
    Internal(AuthError),
}

impl std::fmt::Display for ApiKeyVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => formatter.write_str(&error.message),
            Self::Internal(error) => write!(formatter, "API key verification failed: {error}"),
        }
    }
}

impl std::error::Error for ApiKeyVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => Some(error),
            Self::Validation(_) => None,
        }
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
        let lookup_config = self
            .resolve_configuration(input.config_id)
            .map_err(|_| ApiKeyErrorCode::NoDefaultConfiguration)?;
        let hashed = if lookup_config.disable_key_hashing {
            input.key.to_owned()
        } else {
            Self::hash_key(input.key)
        };
        let api_key = ctx
            .database
            .get_api_key_by_hash(&hashed)
            .await?
            .ok_or(ApiKeyErrorCode::InvalidApiKey)?;

        if input
            .config_id
            .is_some_and(|expected| !config_id_matches(&api_key.config_id, expected))
        {
            return Err(ApiKeyErrorCode::InvalidApiKey.into());
        }
        let config = self
            .resolve_configuration(Some(&api_key.config_id))
            .map_err(|_| ApiKeyErrorCode::NoDefaultConfiguration)?;

        if !api_key.enabled {
            return Err(ApiKeyErrorCode::KeyDisabled.into());
        }
        if let Some(expires_at) = api_key.expires_at.as_deref() {
            let expiration = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(|error| {
                AuthError::internal(format!("Invalid stored API key expiration: {error}"))
            })?;
            if chrono::Utc::now() > expiration {
                ctx.database.delete_api_key(&api_key.id).await?;
                return Err(ApiKeyErrorCode::KeyExpired.into());
            }
        }
        if let Some(required) = input.permissions {
            let permitted = api_key.permissions.as_deref().is_some_and(|permissions| {
                super::handlers::check_permissions(permissions, required)
            });
            if !permitted {
                return Err(ApiKeyErrorCode::KeyNotFound.into());
            }
        }

        let updated = match ctx
            .database
            .consume_api_key_usage(&api_key.id, config.rate_limit.enabled)
            .await?
        {
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
        Ok(ApiKeyView::from(updated.as_ref()))
    }

    pub(super) async fn api_key_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let Some((config, key)) = self
            .configurations
            .iter()
            .filter(|config| config.enable_session_for_api_keys)
            .find_map(|config| {
                config.api_key_headers.iter().find_map(|header| {
                    req.headers
                        .get(&header.to_ascii_lowercase())
                        .filter(|key| !key.is_empty())
                        .map(|key| (config, key))
                })
            })
        else {
            return Ok(None);
        };

        if key.encode_utf16().count() < config.key_length {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                403,
                &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
            )?)));
        }
        let input = VerifyApiKey {
            key,
            config_id: Some(&config.config_id),
            permissions: None,
        };
        let view = match self.verify_api_key(&input, ctx).await {
            Ok(view) => view,
            Err(ApiKeyVerificationError::Validation(error)) => {
                return Ok(Some(BeforeRequestAction::Respond(error.response()?)));
            }
            Err(ApiKeyVerificationError::Internal(error)) => return Err(error),
        };
        self.maybe_delete_expired(ctx).await;

        if config.references != ApiKeyReferences::User {
            return Ok(Some(BeforeRequestAction::Respond(
                ApiKeyValidationError::new(ApiKeyErrorCode::InvalidReferenceIdFromApiKey)
                    .response()?,
            )));
        }
        let Some(user) = ctx.database.get_user_by_id(&view.reference_id).await? else {
            return Ok(Some(BeforeRequestAction::Respond(
                ApiKeyValidationError::new(ApiKeyErrorCode::InvalidReferenceIdFromApiKey)
                    .response()?,
            )));
        };

        let now = chrono::Utc::now();
        let expires_at = match view.expires_at {
            Some(value) => chrono::DateTime::parse_from_rfc3339(&value)
                .map_err(|error| {
                    AuthError::internal(format!("Invalid stored API key expiration: {error}"))
                })?
                .with_timezone(&chrono::Utc),
            // Upstream passes its session lifetime in seconds to getDate(..., "ms").
            None => {
                now + chrono::Duration::milliseconds(ctx.config.session.expires_in.num_seconds())
            }
        };
        let meta = better_auth_core::RequestMeta::from_request(req);
        let session = SessionView {
            visible_fields: None,
            id: view.id,
            token: key.to_owned(),
            user_id: user.id().into_owned(),
            created_at: now,
            updated_at: now,
            expires_at,
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            active: true,
            additional_fields: Default::default(),
        };
        // Upstream answers this path in its hook before the route method gate.
        if req.path() == "/get-session" {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &serde_json::json!({
                    "user": ctx.user_view(&user)?,
                    "session": {
                        "id": session.id,
                        "token": session.token,
                        "userId": session.user_id,
                        "userAgent": session.user_agent,
                        "ipAddress": session.ip_address,
                        "createdAt": session.created_at,
                        "updatedAt": session.updated_at,
                        "expiresAt": session.expires_at,
                    },
                }),
            )?)));
        }
        Ok(Some(BeforeRequestAction::InjectSession {
            session: Box::new(session),
        }))
    }
}
