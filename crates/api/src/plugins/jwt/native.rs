use super::{JwtCallOverrides, JwtKeyPairConfig, JwtPlugin, JwtPluginConfig, JwtSigningOptions};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, HttpMethod, Jwk, NativeRequest,
    store::AuthTransaction,
};
use serde_json::{Map, Value, json};

/// Server operations bound to the registered JWT plugin and active transaction.
pub struct JwtApi<'a, S: AuthSchema> {
    plugin: JwtPlugin,
    context: &'a AuthContext<S>,
    transaction: Option<&'a dyn AuthTransaction<S>>,
    source: NativeRequest<'a>,
    request: AuthRequest,
}

impl<'a, S: AuthSchema> JwtApi<'a, S> {
    /// Bind to the options and callbacks registered on this authentication instance.
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let config = context
            .extensions
            .get::<JwtPluginConfig>()
            .ok_or_else(|| AuthError::config("JwtPlugin is not registered"))?;
        Ok(Self {
            plugin: JwtPlugin::with_config(config.clone()),
            context,
            transaction: None,
            source: NativeRequest::default(),
            request: AuthRequest::new(HttpMethod::Post, "virtual:").with_optional_headers(None),
        })
    }

    /// Keep key reads and writes inside the calling endpoint's transaction.
    pub fn from_endpoint(endpoint: &EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.transaction = endpoint.transaction;
        Ok(api)
    }

    /// Supply native Request and headers independently for dynamic URL and callback context.
    pub fn with_request(mut self, source: NativeRequest<'a>) -> Self {
        self.source = source;
        self.request = AuthRequest::new(HttpMethod::Post, "virtual:")
            .with_optional_headers(source.headers.cloned());
        if let Some(original) = source.request {
            self.request = self.request.with_original_request(original.clone());
        }
        self
    }

    fn endpoint<'ctx>(
        &'ctx self,
        body: Value,
        context: &'ctx AuthContext<S>,
    ) -> EndpointContext<'ctx, S> {
        let mut endpoint =
            EndpointContext::native(Some(&self.request), self.source.request, body, context);
        endpoint.path = Some("virtual:");
        endpoint.transaction = self.transaction;
        endpoint
    }

    /// Sign application claims with the registered plugin defaults.
    pub async fn sign(&self, payload: Map<String, Value>) -> AuthResult<String> {
        self.sign_with_options(payload, &JwtSigningOptions::default())
            .await
    }

    /// Replace supplied option groups for one call, preserving omitted groups and instance defaults.
    pub async fn sign_with_overrides(
        &self,
        payload: Map<String, Value>,
        overrides: JwtCallOverrides<S>,
    ) -> AuthResult<String> {
        self.context
            .with_native_context(self.source, |resolved| async move {
                let mut context = (*resolved).clone();
                let mut config = self.plugin.config.clone();
                let overrides = overrides.apply(&mut config, &mut context);
                let endpoint = self.endpoint(
                    json!({"payload":payload,"overrideOptions":overrides}),
                    &context,
                );
                JwtPlugin::with_config(config)
                    .sign_in_endpoint(payload, &JwtSigningOptions::default(), &endpoint)
                    .await
            })
            .await
    }

    /// Sign application claims with explicit key selection and protected headers.
    pub async fn sign_with_options(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
    ) -> AuthResult<String> {
        self.context
            .with_native_context(self.source, |resolved| async move {
                let endpoint = self.endpoint(json!({"payload": payload}), &resolved);
                self.plugin
                    .sign_in_endpoint(payload, options, &endpoint)
                    .await
            })
            .await
    }

    /// Provision a key using the registered storage callbacks and encryption policy.
    pub async fn create_key_pair(&self, parameters: JwtKeyPairConfig) -> AuthResult<Jwk> {
        self.context
            .with_native_context(self.source, |resolved| async move {
                self.plugin
                    .create_key_pair_in_endpoint(parameters, &self.endpoint(Value::Null, &resolved))
                    .await
            })
            .await
    }

    /// Return verified claims, or `None` for invalid tokens and verification adapter errors.
    pub async fn verify(
        &self,
        token: &str,
        issuer: Option<&str>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        let body = super::verification::verification_body(token, issuer);
        self.context
            .with_native_context(self.source, |resolved| async move {
                self.plugin
                    .verify_in_endpoint(token, issuer, &self.endpoint(body, &resolved))
                    .await
            })
            .await
    }
}
