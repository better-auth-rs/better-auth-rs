//! Typed server operations using the plugins registered on [`BetterAuth`].

use std::any::Any;
use std::collections::HashMap;

use better_auth_core::AuthContext;
use better_auth_core::wire::ApiKeyView;
use serde_json::Value;

use crate::plugins::api_key::{
    ApiKeyPlugin, ApiKeyVerificationError, CreateKeyRequest, CreateKeyResponse, UpdateKeyRequest,
    VerifyApiKey,
};
use crate::{AuthError, AuthResult, AuthSchema, BetterAuth};

/// Input to a registered endpoint called from trusted server code.
#[derive(Debug, Default)]
pub struct EndpointInput {
    /// Preserve omitted headers separately from an explicitly empty header collection.
    pub headers: Option<HashMap<String, String>>,
    /// JSON input subject to the endpoint's schema.
    pub body: Option<Value>,
    /// Endpoint query parameters.
    pub query: HashMap<String, String>,
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Call a registered endpoint with its plugin hooks, without the HTTP transport phase.
    /// API errors retain response headers; ordinary errors retain their original Rust variant.
    pub async fn call_endpoint(
        &self,
        method: better_auth_core::HttpMethod,
        path: &str,
        input: EndpointInput,
    ) -> AuthResult<better_auth_core::AuthResponse> {
        let mut request =
            better_auth_core::AuthRequest::new(method, path).with_optional_headers(input.headers);
        request.body = input
            .body
            .map(|body| serde_json::to_vec(&body))
            .transpose()?;
        request.query = input.query;
        let mut context = better_auth_core::RequestHookContext::from_request(&request);
        context.body = request
            .body
            .as_ref()
            .map(|_| request.body_as_json())
            .transpose()?;
        context.meta = better_auth_core::RequestMeta::from_request_with_config(
            &request,
            &self.config().advanced.ip_address,
        );
        let route = self
            .plugins()
            .iter()
            .flat_map(|plugin| plugin.routes())
            .find(|route| route.matches(request.method(), path));
        better_auth_core::with_request_hook_context_value(context, async {
            better_auth_core::hooks::set_request_hook_route(path, route.as_ref());
            self.dispatch_endpoint(&mut request, false).await
        })
        .await
    }
}

/// A nullable field update with an explicit distinction between omission and clearing.
#[derive(Debug, Default)]
pub enum FieldUpdate<T> {
    /// Keep the stored value.
    #[default]
    Unchanged,
    /// Remove the stored value.
    Clear,
    /// Replace the stored value.
    Set(T),
}

impl<T> FieldUpdate<T> {
    fn into_option(self) -> Option<Option<T>> {
        match self {
            Self::Unchanged => None,
            Self::Clear => Some(None),
            Self::Set(value) => Some(Some(value)),
        }
    }
}

/// Optional API key settings. The acting user is a required argument to [`ApiKeyApi::create`].
#[derive(Debug, Default)]
pub struct CreateKeyOptions {
    /// Configuration to use; omission selects the default configuration.
    pub config_id: Option<String>,
    /// Required by configurations that assign keys to organizations.
    pub organization_id: Option<String>,
    /// Display name.
    pub name: Option<String>,
    /// Prefix prepended to the generated key.
    pub prefix: Option<String>,
    /// Lifetime in seconds; omission uses the configured default.
    pub expires_in: Option<f64>,
    /// Initial usage quota.
    pub remaining: Option<f64>,
    /// Override the configuration's rate limiting setting.
    pub rate_limit_enabled: Option<bool>,
    /// Rate limit window in milliseconds.
    pub rate_limit_time_window: Option<f64>,
    /// Requests per rate limit window.
    pub rate_limit_max: Option<f64>,
    /// Refill interval in milliseconds.
    pub refill_interval: Option<f64>,
    /// Uses restored per refill.
    pub refill_amount: Option<f64>,
    /// Granted actions for each resource; omission uses the configured defaults.
    pub permissions: Option<HashMap<String, Vec<String>>>,
    /// Metadata stored when the configuration enables metadata.
    pub metadata: Option<Value>,
}

/// Changes to an existing API key. Omitted fields retain their current values.
#[derive(Debug, Default)]
pub struct UpdateKeyOptions {
    /// Configuration used to locate the key; omission selects the default configuration.
    pub config_id: Option<String>,
    /// Replacement display name.
    pub name: Option<String>,
    /// Set to false to revoke authentication with this key.
    pub enabled: Option<bool>,
    /// Replacement usage quota.
    pub remaining: Option<f64>,
    /// Enable or disable rate limiting.
    pub rate_limit_enabled: Option<bool>,
    /// Replacement rate limit window in milliseconds.
    pub rate_limit_time_window: Option<f64>,
    /// Replacement requests per rate limit window.
    pub rate_limit_max: Option<f64>,
    /// Replacement refill interval in milliseconds.
    pub refill_interval: Option<f64>,
    /// Replacement uses restored per refill.
    pub refill_amount: Option<f64>,
    /// Replace or clear granted actions.
    pub permissions: FieldUpdate<HashMap<String, Vec<String>>>,
    /// Replace or clear metadata when the configuration enables metadata.
    pub metadata: FieldUpdate<Value>,
    /// Set the lifetime in seconds from now, or clear expiration.
    pub expires_in: FieldUpdate<f64>,
}

/// Actions required on one resource during API key verification.
#[derive(Debug)]
pub enum RequiredActions {
    /// Require every action, matching the upstream AND connector.
    All(Vec<String>),
    /// Require at least one action, matching the upstream OR connector.
    Any(Vec<String>),
}

/// Constraints checked before verification consumes quota or rate limit capacity.
#[derive(Debug, Default)]
pub struct VerifyKeyOptions {
    /// Restrict verification to this configuration.
    pub config_id: Option<String>,
    /// Each resource must satisfy its requested actions.
    pub permissions: Option<HashMap<String, RequiredActions>>,
}

/// Server API bound to the registered API key plugin and initialized auth context.
pub struct ApiKeyApi<'a, S: AuthSchema> {
    plugin: &'a ApiKeyPlugin,
    context: &'a AuthContext<S>,
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Access the API key plugin registered on this auth instance.
    ///
    /// Returns a configuration error when [`ApiKeyPlugin`] is not registered.
    pub fn api_keys(&self) -> AuthResult<ApiKeyApi<'_, S>> {
        let plugin = self
            .plugins()
            .iter()
            .find_map(|plugin| (plugin.as_ref() as &dyn Any).downcast_ref::<ApiKeyPlugin>())
            .ok_or_else(|| AuthError::config("ApiKeyPlugin is not registered"))?;
        Ok(ApiKeyApi {
            plugin,
            context: self.context(),
        })
    }
}

impl<S: AuthSchema> ApiKeyApi<'_, S> {
    /// Issue a key on behalf of a user from trusted server code.
    ///
    /// Organization configurations check the acting user's organization permissions.
    /// The response returns the plaintext key once; later operations cannot retrieve it.
    pub async fn create(
        &self,
        user_id: &str,
        options: CreateKeyOptions,
    ) -> AuthResult<CreateKeyResponse> {
        self.plugin
            .create_key(
                self.context,
                &CreateKeyRequest {
                    config_id: options.config_id,
                    user_id: Some(user_id.to_owned()),
                    organization_id: options.organization_id,
                    name: options.name,
                    prefix: options.prefix,
                    expires_in: options.expires_in,
                    remaining: options.remaining,
                    rate_limit_enabled: options.rate_limit_enabled,
                    rate_limit_time_window: options.rate_limit_time_window,
                    rate_limit_max: options.rate_limit_max,
                    refill_interval: options.refill_interval,
                    refill_amount: options.refill_amount,
                    permissions: options.permissions,
                    metadata: options.metadata,
                },
            )
            .await
    }

    /// Update a key on behalf of its owner or an authorized organization member.
    ///
    /// The caller must authorize the acting user before calling this server API.
    pub async fn update(
        &self,
        user_id: &str,
        key_id: &str,
        options: UpdateKeyOptions,
    ) -> AuthResult<ApiKeyView> {
        self.plugin
            .update_key(
                self.context,
                &UpdateKeyRequest {
                    config_id: options.config_id,
                    key_id: key_id.to_owned(),
                    user_id: Some(user_id.to_owned()),
                    name: options.name,
                    enabled: options.enabled,
                    remaining: options.remaining,
                    rate_limit_enabled: options.rate_limit_enabled,
                    rate_limit_time_window: options.rate_limit_time_window,
                    rate_limit_max: options.rate_limit_max,
                    refill_interval: options.refill_interval,
                    refill_amount: options.refill_amount,
                    permissions: options.permissions.into_option(),
                    metadata: options
                        .metadata
                        .into_option()
                        .map(|value| value.unwrap_or(Value::Null)),
                    expires_in: options.expires_in.into_option(),
                },
            )
            .await
    }

    /// Verify a presented credential and consume one use after its permissions pass.
    ///
    /// Validation errors reject the credential; internal errors preserve infrastructure failures.
    pub async fn verify(
        &self,
        key: &str,
        options: VerifyKeyOptions,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        let permissions = options.permissions.map(|resources| {
            Value::Object(
                resources
                    .into_iter()
                    .map(|(resource, actions)| {
                        let actions = match actions {
                            RequiredActions::All(actions) => serde_json::json!(actions),
                            RequiredActions::Any(actions) => {
                                serde_json::json!({ "actions": actions, "connector": "OR" })
                            }
                        };
                        (resource, actions)
                    })
                    .collect(),
            )
        });
        self.plugin
            .verify_api_key(
                &VerifyApiKey {
                    key,
                    config_id: options.config_id.as_deref(),
                    permissions: permissions.as_ref(),
                },
                self.context,
            )
            .await
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Access server-only Email OTP creation and retrieval using the registered plugin.
    pub fn email_otp(&self) -> AuthResult<better_auth_api::plugins::email_otp::EmailOtpApi<'_, S>> {
        better_auth_api::plugins::email_otp::EmailOtpApi::from_context(self.context())
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Provision users through the registered Admin plugin from trusted server code.
    pub fn admin(&self) -> AuthResult<better_auth_api::plugins::admin::AdminApi<'_, S>> {
        better_auth_api::plugins::admin::AdminApi::from_context(self.context())
    }
}
