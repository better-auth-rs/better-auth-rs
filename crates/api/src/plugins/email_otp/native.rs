use super::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod, NativeRequest,
};

/// Trusted server operations using the registered Email OTP plugin configuration.
/// These methods have no HTTP routes and never send email.
/// A dynamic base URL requires a configured fallback or an explicitly bound endpoint context.
pub struct EmailOtpApi<'a, S: AuthSchema> {
    plugin: EmailOtpPlugin,
    context: &'a AuthContext<S>,
    source: NativeRequest<'a>,
    transaction: Option<&'a dyn better_auth_core::store::AuthTransaction<S>>,
}
impl<'a, S: AuthSchema> EmailOtpApi<'a, S> {
    /// Bind to an initialized context. Callback wrappers use the same registered configuration.
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let config = context
            .extensions
            .get::<EmailOtpConfig>()
            .ok_or_else(|| AuthError::config("EmailOtpPlugin is not registered"))?;
        Ok(Self {
            plugin: EmailOtpPlugin::with_config(config.clone()),
            context,
            transaction: None,
            source: NativeRequest::default(),
        })
    }

    /// Bind native OTP operations to the endpoint's active database transaction.
    pub fn from_endpoint(endpoint: &EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.transaction = endpoint.transaction;
        Ok(api)
    }

    /// Supply an original Request and independently present endpoint headers.
    pub fn with_request(mut self, source: NativeRequest<'a>) -> Self {
        self.source = source;
        self
    }

    /// Generate and store a new code even when resend reuse is enabled.
    pub async fn create(&self, email: &str, kind: EmailOtpType) -> AuthResult<String> {
        let route = AuthRoute::server_only(HttpMethod::Post, "createEmailVerificationOTP")
            .body_validator(validate_body);
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                Some(serde_json::json!({"email":email,"type":kind})),
                None,
                |request, context| async move {
                    let body = request
                        .validated_body::<OtpInput>()
                        .ok_or_else(|| AuthError::internal("Missing validated OTP input"))?;
                    let mut endpoint = EndpointContext::native(
                        Some(&request),
                        request.original_request(),
                        request.input_body()?.unwrap_or_default(),
                        &context,
                    );
                    endpoint.transaction = self.transaction;
                    let email = body.email.to_lowercase();
                    let otp = self
                        .plugin
                        .create_otp(&endpoint, &email, body.kind, &body.kind.identifier(&email))
                        .await?;
                    AuthResponse::json(200, &otp).map_err(Into::into)
                },
            )
            .await?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Read a live plaintext or decrypted code without consuming it or changing attempts.
    pub async fn get(&self, email: &str, kind: EmailOtpType) -> AuthResult<Option<String>> {
        let route = AuthRoute::server_only(HttpMethod::Get, "getEmailVerificationOTP")
            .query_validator(validate_query);
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                None,
                Some(serde_json::json!({"email":email,"type":kind})),
                |request, context| async move {
                    let query: OtpInput =
                        serde_json::from_value(request.query.unwrap_or_default())?;
                    let identifier = query.kind.identifier(&query.email.to_lowercase());
                    let record = match self.transaction {
                        Some(transaction) => {
                            transaction
                                .get_verification_including_expired(&identifier)
                                .await?
                        }
                        None => {
                            context
                                .database
                                .get_verification_including_expired(&identifier)
                                .await?
                        }
                    };
                    let otp = if let Some(record) = record
                        && !record.expires_at.is_before(chrono::Utc::now())?
                    {
                        let (stored, _) = super::otp::split(record.value.typed()?);
                        Some(
                            self.plugin
                                .recover(stored, context.config.encryption_secret())
                                .await?
                                .ok_or_else(|| {
                                    AuthError::bad_request(
                                        "OTP is hashed, cannot return the plain text OTP",
                                    )
                                })?,
                        )
                    } else {
                        None
                    };
                    AuthResponse::json(200, &serde_json::json!({"otp":otp})).map_err(Into::into)
                },
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Result {
            otp: Option<String>,
        }
        Ok(serde_json::from_slice::<Result>(&response.body)?.otp)
    }
}

#[derive(serde::Deserialize)]
struct OtpInput {
    email: String,
    #[serde(rename = "type")]
    kind: EmailOtpType,
}

fn validate_body(
    request: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let body = project(request.input_body()?, "body")?;
    let input: OtpInput = serde_json::from_value(body.clone())?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(body),
        input,
    ))
}
fn validate_query(query: Option<serde_json::Value>) -> AuthResult<Option<serde_json::Value>> {
    project(query, "query").map(Some)
}
fn project(input: Option<serde_json::Value>, location: &str) -> AuthResult<serde_json::Value> {
    use crate::plugins::json_body::{invalid_type, validation_error};
    use serde_json::{Map, Value};
    let body = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&invalid_type(
            location,
            "object",
            input.as_ref(),
        )))
    })?;
    let mut errors = Vec::new();
    if !body.get("email").is_some_and(Value::is_string) {
        errors.push(invalid_type(
            &format!("{location}.email"),
            "string",
            body.get("email"),
        ));
    }
    if !matches!(
        body.get("type").and_then(Value::as_str),
        Some("email-verification" | "sign-in" | "forget-password" | "change-email")
    ) {
        errors.push(format!("[{location}.type] Invalid option: expected one of \"email-verification\"|\"sign-in\"|\"forget-password\"|\"change-email\""));
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let projected: Map<String, Value> = body
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "email" | "type"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(Value::Object(projected))
}
