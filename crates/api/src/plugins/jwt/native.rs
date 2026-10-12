use super::{JwtCallOverrides, JwtKeyPairConfig, JwtPlugin, JwtPluginConfig, JwtSigningOptions};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema, FieldMap,
    FieldValue, HttpMethod, Jwk, NativeRequest, store::AuthTransaction,
};
use serde_json::{Map, Value, json};

/// Server operations bound to the registered JWT plugin and active transaction.
pub struct JwtApi<'a, S: AuthSchema> {
    plugin: JwtPlugin,
    context: &'a AuthContext<S>,
    caller: Option<&'a EndpointContext<'a, S>>,
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
            plugin: JwtPlugin {
                config: config.clone(),
                options: super::overrides::NativeOptions::registered(context)?,
            },
            context,
            caller: None,
            transaction: None,
            source: NativeRequest::default(),
            request: AuthRequest::new(HttpMethod::Post, "virtual:").with_optional_headers(None),
        })
    }

    /// Borrow the caller for direct helpers and retain its transaction for dispatched operations.
    pub fn from_endpoint(endpoint: &'a EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.caller = Some(endpoint);
        api.transaction = endpoint.transaction;
        Ok(api)
    }

    /// Supply Request and headers for dispatched operations or standalone key provisioning.
    /// Direct helpers bound to an endpoint retain that endpoint's original context.
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
        self.sign_value(FieldMap::from_json(payload)?.into())
            .await?
            .decode()
    }

    /// Sign native application claims and retain the custom signer's return value.
    pub async fn sign_value(&self, payload: FieldValue) -> AuthResult<FieldValue> {
        self.sign_native(payload, None, None).await
    }

    /// Sign native claims with explicit key selection and protected headers.
    pub async fn sign_value_with_options(
        &self,
        payload: FieldValue,
        options: &JwtSigningOptions,
    ) -> AuthResult<FieldValue> {
        self.sign_native(payload, Some(options), None).await
    }

    /// Replace supplied option groups for one call, preserving omitted groups and instance defaults.
    pub async fn sign_with_overrides(
        &self,
        payload: Map<String, Value>,
        overrides: JwtCallOverrides<S>,
    ) -> AuthResult<String> {
        self.sign_native(
            FieldMap::from_json(payload)?.into(),
            None,
            Some(overrides.into_native()),
        )
        .await?
        .decode()
    }

    /// Replace option groups without serializing nested values, accessors, or callbacks.
    pub async fn sign_value_with_overrides(
        &self,
        payload: FieldValue,
        overrides: FieldValue,
    ) -> AuthResult<FieldValue> {
        self.sign_native(payload, None, Some(overrides)).await
    }

    /// Sign application claims with explicit key selection and protected headers.
    pub async fn sign_with_options(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
    ) -> AuthResult<String> {
        self.sign_value_with_options(FieldMap::from_json(payload)?.into(), options)
            .await?
            .decode()
    }

    async fn sign_native(
        &self,
        payload: FieldValue,
        options: Option<&JwtSigningOptions>,
        overrides: Option<FieldValue>,
    ) -> AuthResult<FieldValue> {
        let mut body = FieldMap::from([("payload".into(), payload)]);
        if let Some(overrides) = overrides {
            let _ = body.insert("overrideOptions".into(), overrides);
        }
        let route =
            AuthRoute::server_only(HttpMethod::Post, "signJWT").body_validator(validate_sign);
        let response = self
            .context
            .dispatch_native_value(
                self.source,
                route,
                body.into(),
                FieldValue::Undefined,
                |request, resolved| async move {
                    let input = request.validated_body::<SignInput>().ok_or_else(|| {
                        AuthError::internal("Missing validated JWT signing input")
                    })?;
                    let defaults = self.plugin.options.clone();
                    let effective = defaults.merge(
                        input
                            .override_options
                            .as_ref()
                            .unwrap_or(&FieldValue::Undefined),
                    )?;
                    let mut endpoint = EndpointContext::native(
                        Some(&request),
                        request.original_request(),
                        request.input_field_value()?,
                        &resolved,
                    );
                    endpoint.transaction = self.transaction;
                    let token = self
                        .plugin
                        .sign_native_options(input.payload.clone(), options, &effective, &endpoint)
                        .await?;
                    Ok(AuthResponse::native(
                        None,
                        FieldMap::from([("token".into(), token)]).into(),
                    ))
                },
            )
            .await?;
        response.body.field_value()?.model_property("token")
    }

    /// Provision a key using the caller's complete endpoint, or a standalone context when unbound.
    pub async fn create_key_pair(&self, parameters: JwtKeyPairConfig) -> AuthResult<Option<Jwk>> {
        if let Some(endpoint) = self.caller {
            return self
                .plugin
                .create_key_pair_in_endpoint(parameters, endpoint)
                .await;
        }
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
        let route =
            AuthRoute::server_only(HttpMethod::Post, "verifyJWT").body_validator(validate_verify);
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
                    AuthResponse::json(None, &json!({"payload":payload}))
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

struct SignInput {
    payload: FieldValue,
    override_options: Option<FieldValue>,
}
#[derive(serde::Deserialize)]
struct VerifyInput {
    token: String,
    issuer: Option<String>,
}

fn validate_verify(
    request: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    use crate::plugins::json_body::{invalid_type, validation_error};
    use better_auth_core::endpoint_input::ValidatedBody;
    let input = request.input_body()?;
    let object = input
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| validation_error(&invalid_type("body", "object", input.as_ref())))?;
    let fields = [("token", "string", true), ("issuer", "string", false)];
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
        return Err(validation_error(&errors.join("; ")));
    }
    let value = Value::Object(projected);
    Ok(ValidatedBody::new(
        Some(value.clone()),
        serde_json::from_value::<VerifyInput>(value)?,
    ))
}

fn validate_sign(
    request: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    use crate::plugins::json_body::{native_invalid_type, validation_error};
    use better_auth_core::endpoint_input::ValidatedBody;
    let body = request.input_field_value()?;
    if !crate::plugins::json_body::native_object(&body) {
        return Err(validation_error(&native_invalid_type(
            "body",
            "object",
            Some(&body),
        )));
    }
    let mut projected = FieldMap::new();
    let mut errors = Vec::new();
    for (name, required) in [("payload", true), ("overrideOptions", false)] {
        let value = body.model_property(name)?;
        if value.is_undefined() && !required {
            if body.has_property(name)? {
                let _ = projected.insert(name.into(), value);
            }
        } else if let Some(fields) = crate::plugins::json_body::native_record(&value)? {
            let _ = projected.insert(name.into(), fields.into());
        } else {
            errors.push(native_invalid_type(
                &format!("body.{name}"),
                "record",
                Some(&value),
            ));
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")));
    }
    let input = SignInput {
        payload: projected.get("payload").cloned().unwrap_or_default(),
        override_options: projected.get("overrideOptions").cloned(),
    };
    Ok(ValidatedBody::native(projected.into(), input))
}
