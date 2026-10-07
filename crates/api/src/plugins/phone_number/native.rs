use super::{PhoneNumberPlugin, PhoneOtp};
use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::endpoint_input::ValidatedBody;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod, NativeRequest,
};
use serde_json::{Value, json};

/// The registered server-only phone OTP endpoint. No user or session is created.
pub struct PhoneNumberApi<'a, S: AuthSchema> {
    plugin: PhoneNumberPlugin,
    context: &'a AuthContext<S>,
    source: NativeRequest<'a>,
    transaction: Option<&'a dyn better_auth_core::store::AuthTransaction<S>>,
}

impl<'a, S: AuthSchema> PhoneNumberApi<'a, S> {
    /// Bind the configuration and callbacks installed on this auth instance.
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let plugin = context
            .extensions
            .get::<PhoneNumberPlugin>()
            .ok_or_else(|| AuthError::config("PhoneNumberPlugin is not registered"))?;
        Ok(Self {
            plugin: plugin.clone(),
            context,
            source: NativeRequest::default(),
            transaction: None,
        })
    }

    /// Preserve the active transaction for verification reads, writes and consumption.
    pub fn from_endpoint(endpoint: &EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.transaction = endpoint.transaction;
        Ok(api)
    }

    /// Supply the original native Request and independently present headers.
    pub fn with_request(mut self, source: NativeRequest<'a>) -> Self {
        self.source = source;
        self
    }

    /// Validate and consume a phone OTP through endpoint hooks and the configured verifier.
    pub async fn consume(&self, body: Option<Value>) -> AuthResult<bool> {
        let route = AuthRoute::server_only(HttpMethod::Post, "consumePhoneNumberOTP")
            .body_validator(validate);
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                body,
                None,
                |request, context| async move {
                    let otp = request
                        .validated_body::<PhoneOtp>()
                        .ok_or_else(|| AuthError::internal("Missing validated phone OTP input"))?;
                    let mut endpoint = EndpointContext::native(
                        Some(&request),
                        request.original_request(),
                        request.input_field_value()?,
                        &context,
                    );
                    endpoint.transaction = self.transaction;
                    self.plugin
                        .consume_with_context(&endpoint, otp.clone())
                        .await?;
                    AuthResponse::json(200, &json!({"status":true})).map_err(Into::into)
                },
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Result {
            status: bool,
        }
        Ok(serde_json::from_slice::<Result>(&response.body.bytes()?)?.status)
    }
}

fn validate(request: &AuthRequest) -> AuthResult<ValidatedBody> {
    let input = request.input_body()?;
    let object = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            input.as_ref(),
        )))
    })?;
    let errors: Vec<_> = ["phoneNumber", "code"]
        .into_iter()
        .filter(|name| !object.get(*name).is_some_and(Value::is_string))
        .map(|name| invalid_type(&format!("body.{name}"), "string", object.get(name)))
        .collect();
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let body = Value::Object(
        object
            .iter()
            .filter(|(name, _)| matches!(name.as_str(), "phoneNumber" | "code"))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    );
    let typed: PhoneOtp = serde_json::from_value(body.clone())?;
    Ok(ValidatedBody::new(Some(body), typed))
}

pub(super) async fn delete_verification<S: AuthSchema>(
    endpoint: &EndpointContext<'_, S>,
    identifier: &str,
) -> AuthResult<()> {
    match endpoint.transaction {
        Some(transaction) => {
            transaction
                .delete_verification_by_identifier(identifier)
                .await
        }
        None => {
            endpoint
                .auth
                .database
                .delete_verification_by_identifier(identifier)
                .await
        }
    }
}
