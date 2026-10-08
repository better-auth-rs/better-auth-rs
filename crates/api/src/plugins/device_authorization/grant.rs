use super::{
    DeviceAuthorizationPlugin, DeviceAuthorizationRequest, INVALID_CLIENT_ID, device_error_response,
};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthResult, AuthSchema, DeviceCode,
    FieldMap, store::schema::EntityRole, user_fields::UserConfig,
};
use serde_json::{Map, Value};
use std::{future::Future, pin::Pin, sync::Arc};

/// A grant callback that borrows its request or device code and active endpoint.
pub type DeviceGrantFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;

type Authorize<S> = dyn for<'a> Fn(
        &'a DeviceAuthorizationRequest,
        &'a EndpointContext<'_, S>,
    ) -> DeviceGrantFuture<'a, Option<DeviceGrantAuthorization>>
    + Send
    + Sync;
type SessionPolicy<S> = dyn for<'a> Fn(&'a DeviceCode, &'a EndpointContext<'_, S>) -> DeviceGrantFuture<'a, ()>
    + Send
    + Sync;
type VerificationContext = dyn Fn(&DeviceCode) -> AuthResult<Option<FieldMap>> + Send + Sync;

#[derive(Clone, Default)]
pub(super) struct GrantMetadata {
    pub(super) request_error_codes: Vec<String>,
    pub(super) request_responses: Map<String, Value>,
    pub(super) verification_properties: Map<String, Value>,
}

/// The client binding and declared fields produced by grant request authorization.
pub struct DeviceGrantAuthorization {
    /// Client identifier that owns the issued code.
    pub client_id: String,
    /// Logical stored fields; native code, owner, status, and scope remain authoritative.
    pub additional_fields: better_auth_core::FieldMap,
}

/// Request authorization and session redemption policy for one Device plugin.
pub struct DeviceGrant<S: AuthSchema> {
    stored_fields: UserConfig,
    metadata: GrantMetadata,
    authorize: Arc<Authorize<S>>,
    session_policy: Arc<SessionPolicy<S>>,
    verification: Option<Arc<VerificationContext>>,
}

impl<S: AuthSchema> DeviceGrant<S> {
    /// Require both request authorization and a session redemption policy.
    ///
    /// Authorization returning `None` uses the configured client validator.
    /// The session policy runs after the stored client check and before redemption state changes.
    pub fn new<A, R>(authorize_request: A, assert_session_redemption: R) -> Self
    where
        A: for<'a> Fn(
                &'a DeviceAuthorizationRequest,
                &'a EndpointContext<'_, S>,
            ) -> DeviceGrantFuture<'a, Option<DeviceGrantAuthorization>>
            + Send
            + Sync
            + 'static,
        R: for<'a> Fn(&'a DeviceCode, &'a EndpointContext<'_, S>) -> DeviceGrantFuture<'a, ()>
            + Send
            + Sync
            + 'static,
    {
        Self {
            stored_fields: UserConfig::default(),
            metadata: GrantMetadata::default(),
            authorize: Arc::new(authorize_request),
            session_policy: Arc::new(assert_session_redemption),
            verification: None,
        }
    }

    /// Register declared grant fields through the existing adapter field policies.
    pub fn stored_fields(mut self, fields: UserConfig) -> Self {
        self.stored_fields = fields;
        self
    }

    /// Append documented request error codes in order, retaining duplicate values.
    pub fn request_error_codes(mut self, codes: Vec<String>) -> Self {
        self.metadata.request_error_codes = codes;
        self
    }

    /// Document additional request responses. The fixed 200, 400, and 500 responses take precedence.
    pub fn request_openapi_responses(mut self, responses: Map<String, Value>) -> Self {
        self.metadata.request_responses = responses;
        self
    }

    /// Document verification display properties. Initialization rejects native property names.
    pub fn verification_openapi_properties(mut self, properties: Map<String, Value>) -> Self {
        self.metadata.verification_properties = properties;
        self
    }

    /// Add display data only when the current session owns the verification request.
    /// Native response fields retain precedence, including their omission.
    pub fn verification_context(
        mut self,
        callback: impl Fn(&DeviceCode) -> AuthResult<Option<FieldMap>> + Send + Sync + 'static,
    ) -> Self {
        self.verification = Some(Arc::new(callback));
        self
    }

    pub(super) async fn assert_session_redemption(
        &self,
        device_code: &DeviceCode,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<()> {
        (self.session_policy)(device_code, endpoint).await
    }

    pub(super) fn verification_context_for(
        &self,
        device_code: &DeviceCode,
    ) -> AuthResult<FieldMap> {
        Ok(match &self.verification {
            Some(callback) => callback(device_code)?.unwrap_or_default(),
            None => FieldMap::new(),
        })
    }
}

impl DeviceAuthorizationPlugin {
    /// Attach a grant after configuring ordinary plugin options and request fields.
    pub fn grant<S: AuthSchema>(mut self, grant: DeviceGrant<S>) -> impl AuthPlugin<S> {
        self.config.grant_fields = Some(grant.stored_fields.clone());
        self.config.grant_metadata = grant.metadata.clone();
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(grant),
        }
    }

    pub(super) fn configured_grant<S: AuthSchema>(
        &self,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<Arc<DeviceGrant<S>>>> {
        if self.config.grant_fields.is_none() {
            return Ok(None);
        }
        context
            .extensions
            .get::<Arc<DeviceGrant<S>>>()
            .cloned()
            .map(Some)
            .ok_or_else(|| AuthError::internal("Device grant callbacks are not registered"))
    }

    pub(super) async fn authorize_request<S: AuthSchema>(
        &self,
        request: &DeviceAuthorizationRequest,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<DeviceGrantAuthorization> {
        let grant = self
            .configured_grant(endpoint.auth)?
            .ok_or_else(|| AuthError::internal("Device grant callbacks are not registered"))?;
        let authorization = (grant.authorize)(request, endpoint).await?;
        let authorization = match authorization {
            Some(authorization) => authorization,
            None => {
                let Some(client_id) = request
                    .client_id
                    .as_deref()
                    .filter(|value| !value.is_empty())
                else {
                    return Err(missing_client()?);
                };
                if self.config.validate_client.is_none()
                    || !self.validate_client_id(client_id).await?
                {
                    return Err(
                        device_error_response(400, "invalid_client", INVALID_CLIENT_ID)?.into(),
                    );
                }
                DeviceGrantAuthorization {
                    client_id: client_id.to_owned(),
                    additional_fields: Default::default(),
                }
            }
        };
        if authorization.client_id.is_empty() {
            return Err(missing_client()?);
        }
        Ok(authorization)
    }
}

fn missing_client() -> AuthResult<AuthError> {
    Ok(device_error_response(400, "invalid_request", "client_id is required")?.into())
}

pub(super) fn register_fields<S: AuthSchema>(
    context: &mut AuthInitContext<S>,
    fields: &UserConfig,
) -> AuthResult<()> {
    let native =
        better_auth_core::plugin_runtime::ModelFields::plugin_native_fields(EntityRole::DeviceCode);
    let conflicts: Vec<_> = fields
        .fields()
        .keys()
        .filter(|name| native.fields().contains_key(*name))
        .map(String::as_str)
        .collect();
    if !conflicts.is_empty() {
        return Err(AuthError::config(format!(
            "Device authorization grant fields must be additional and cannot redefine deviceCode fields: {}",
            conflicts.join(", "),
        )));
    }
    context.register_model_fields(EntityRole::DeviceCode, fields.clone())
}
