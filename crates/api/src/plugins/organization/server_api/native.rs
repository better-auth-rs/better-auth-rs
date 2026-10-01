use super::{AddMemberInput, EndpointContext, OrganizationPlugin};
use better_auth_core::endpoint_input::ValidatedBody;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod, NativeRequest,
};
use serde_json::Value;

/// The registered pathless organization endpoint and its captured configuration.
pub struct OrganizationApi<'a, S: AuthSchema> {
    plugin: OrganizationPlugin,
    context: &'a AuthContext<S>,
    source: NativeRequest<'a>,
    transaction: Option<&'a dyn better_auth_core::store::AuthTransaction<S>>,
}

impl<'a, S: AuthSchema> OrganizationApi<'a, S> {
    /// Bind the organization configuration installed on this auth instance.
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let plugin = context
            .extensions
            .get::<OrganizationPlugin>()
            .ok_or_else(|| AuthError::config("OrganizationPlugin is not registered"))?;
        Ok(Self::with_plugin(plugin.clone(), context))
    }

    pub(super) fn with_plugin(plugin: OrganizationPlugin, context: &'a AuthContext<S>) -> Self {
        Self {
            plugin,
            context,
            source: NativeRequest::default(),
            transaction: None,
        }
    }

    /// Keep the resolved runtime and the active database transaction.
    pub fn from_endpoint(endpoint: &EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.transaction = endpoint.transaction;
        Ok(api)
    }

    /// Supply native Request and headers independently without importing ambient HTTP input.
    pub fn with_request(mut self, source: NativeRequest<'a>) -> Self {
        self.source = source;
        self
    }

    /// Add a member through global hooks, configured validation, and organization lifecycle hooks.
    /// The result retains endpoint after-hook replacements.
    pub async fn add_member(&self, body: Option<Value>) -> AuthResult<Value> {
        let schema = self.plugin.config.schema.member.clone();
        let route = AuthRoute::server_only(HttpMethod::Post, "addMember")
            .body_validator(move |request| validate(request, &schema));
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                body,
                None,
                |request, context| async move {
                    let input = request
                        .validated_body::<AddMemberInput>()
                        .ok_or_else(|| AuthError::internal("Missing validated member input"))?;
                    let mut endpoint = EndpointContext::native(
                        Some(&request),
                        request.original_request(),
                        request.input_body()?.unwrap_or_default(),
                        &context,
                    );
                    endpoint.transaction = self.transaction;
                    let member = self
                        .plugin
                        .add_member_core(input.clone(), &request, &endpoint)
                        .await?;
                    AuthResponse::json(200, &member).map_err(Into::into)
                },
            )
            .await?;
        Ok(serde_json::from_slice(&response.body)?)
    }
}

pub(super) fn validate(
    request: &AuthRequest,
    schema: &better_auth_core::user_fields::UserConfig,
) -> AuthResult<ValidatedBody> {
    use super::super::input::{self, BaseField};
    let raw = request.input_body()?;
    let mut errors = Vec::new();
    let object = input::object(raw.as_ref(), "body", &mut errors);
    input::finish(errors)?;
    let body = input::validate(
        schema,
        object.cloned().unwrap_or_default(),
        &[
            ("userId", BaseField::CoercedString, true),
            ("role", BaseField::Roles, true),
            ("organizationId", BaseField::String, false),
            ("teamId", BaseField::String, false),
        ],
    )?;
    let body = Value::Object(body);
    Ok(ValidatedBody::new(
        Some(body.clone()),
        serde_json::from_value::<AddMemberInput>(body)?,
    ))
}
