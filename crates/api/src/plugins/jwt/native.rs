use super::{JwtCallOverrides, JwtKeyPairConfig, JwtPlugin, JwtPluginConfig, JwtSigningOptions};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod, Jwk, NativeRequest, store::AuthTransaction,
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
        body: better_auth_core::FieldValue,
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
        let mut config = self.plugin.config.clone();
        let mut override_context = self.context.clone();
        let options = overrides.apply(&mut config, &mut override_context);
        self.sign_native(
            payload,
            &JwtSigningOptions::default(),
            Some(options),
            config,
            Some(override_context),
        )
        .await
    }

    /// Sign application claims with explicit key selection and protected headers.
    pub async fn sign_with_options(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
    ) -> AuthResult<String> {
        self.sign_native(payload, options, None, self.plugin.config.clone(), None)
            .await
    }

    async fn sign_native(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
        overrides: Option<Value>,
        config: JwtPluginConfig,
        override_context: Option<AuthContext<S>>,
    ) -> AuthResult<String> {
        let mut body = Map::from_iter([("payload".into(), Value::Object(payload))]);
        if let Some(overrides) = &overrides {
            let _ = body.insert("overrideOptions".into(), overrides.clone());
        }
        let route = AuthRoute::server_only(HttpMethod::Post, "signJWT")
            .body_validator(|request| validate(request, true));
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                Some(body.into()),
                None,
                |request, resolved| async move {
                    let input = request.validated_body::<SignInput>().ok_or_else(|| {
                        AuthError::internal("Missing validated JWT signing input")
                    })?;
                    let mut context = (*resolved).clone();
                    let mut effective_config = self.plugin.config.clone();
                    if let Some(value) = &input.override_options {
                        let updated =
                            super::overrides::from_input::<S>(value, &config, overrides.as_ref())?;
                        let _ = updated.apply(&mut effective_config, &mut context);
                    }
                    if input
                        .override_options
                        .as_ref()
                        .is_some_and(|value| value.get("adapter").is_some())
                    {
                        let callbacks = override_context
                            .as_ref()
                            .filter(|_| {
                                overrides
                                    .as_ref()
                                    .is_some_and(|value| value.get("adapter").is_some())
                            })
                            .and_then(|context| {
                                context
                                    .extensions
                                    .get::<std::sync::Arc<super::JwtCallbacks<S>>>()
                            })
                            .cloned()
                            .unwrap_or_else(|| {
                                std::sync::Arc::new(super::JwtCallbacks::<S>::default())
                            });
                        context.extensions.insert(callbacks);
                    }
                    let mut endpoint = EndpointContext::native(
                        Some(&request),
                        request.original_request(),
                        request.input_field_value()?,
                        &context,
                    );
                    endpoint.transaction = self.transaction;
                    let token = JwtPlugin::with_config(effective_config)
                        .sign_in_endpoint(input.payload.clone(), options, &endpoint)
                        .await?;
                    AuthResponse::json(200, &json!({"token":token})).map_err(Into::into)
                },
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Result {
            token: String,
        }
        Ok(serde_json::from_slice::<Result>(&response.body.bytes()?)?.token)
    }

    /// Provision a key using the registered storage callbacks and encryption policy.
    pub async fn create_key_pair(&self, parameters: JwtKeyPairConfig) -> AuthResult<Option<Jwk>> {
        self.context
            .with_native_context(self.source, |resolved| async move {
                self.plugin
                    .create_key_pair_in_endpoint(
                        parameters,
                        &self.endpoint(better_auth_core::FieldValue::Null, &resolved),
                    )
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
        let route = AuthRoute::server_only(HttpMethod::Post, "verifyJWT")
            .body_validator(|request| validate(request, false));
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                Some(body),
                None,
                |request, context| async move {
                    let input = request.validated_body::<VerifyInput>().ok_or_else(|| {
                        AuthError::internal("Missing validated JWT verification input")
                    })?;
                    let mut endpoint = EndpointContext::native(
                        Some(&request),
                        request.original_request(),
                        request.input_field_value()?,
                        &context,
                    );
                    endpoint.transaction = self.transaction;
                    let payload = self
                        .plugin
                        .verify_in_endpoint(&input.token, input.issuer.as_deref(), &endpoint)
                        .await?;
                    AuthResponse::json(200, &json!({"payload":payload})).map_err(Into::into)
                },
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Result {
            payload: Option<Map<String, Value>>,
        }
        Ok(serde_json::from_slice::<Result>(&response.body.bytes()?)?.payload)
    }
}

#[derive(serde::Deserialize)]
struct SignInput {
    payload: Map<String, Value>,
    #[serde(rename = "overrideOptions")]
    override_options: Option<Value>,
}
#[derive(serde::Deserialize)]
struct VerifyInput {
    token: String,
    issuer: Option<String>,
}

fn validate(
    request: &AuthRequest,
    sign: bool,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    use crate::plugins::json_body::{invalid_type, validation_error};
    use better_auth_core::endpoint_input::ValidatedBody;
    let input = request.input_body()?;
    let object = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            input.as_ref(),
        )))
    })?;
    let fields = if sign {
        [
            ("payload", "record", true),
            ("overrideOptions", "record", false),
        ]
    } else {
        [("token", "string", true), ("issuer", "string", false)]
    };
    let mut errors = Vec::new();
    let mut projected = Map::new();
    for (field, kind, required) in fields {
        let value = object.get(field);
        if value.is_none() && !required {
            continue;
        }
        if !value.is_some_and(|value| {
            if kind == "string" {
                value.is_string()
            } else {
                value.is_object()
            }
        }) {
            errors.push(invalid_type(&format!("body.{field}"), kind, value));
        } else if let Some(value) = value {
            let _ = projected.insert(field.into(), value.clone());
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let value = Value::Object(projected);
    if sign {
        Ok(ValidatedBody::new(
            Some(value.clone()),
            serde_json::from_value::<SignInput>(value)?,
        ))
    } else {
        Ok(ValidatedBody::new(
            Some(value.clone()),
            serde_json::from_value::<VerifyInput>(value)?,
        ))
    }
}
