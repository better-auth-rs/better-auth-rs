use super::{AddMemberInput, EndpointContext, OrganizationPlugin};
use better_auth_core::endpoint_input::ValidatedBody;
use better_auth_core::{
    AuthContext, AuthError, AuthRecordFields, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, FieldValue, FromFieldMap, HttpMethod, NativeRequest,
};
use serde_json::Value;

enum MemberInput {
    Json(Option<Value>),
    Native(FieldValue),
}

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
        self.add_member_response(MemberInput::Json(body))
            .await?
            .body
            .json()?
            .ok_or_else(|| AuthError::internal("Native addMember returned undefined"))
    }

    pub(super) async fn add_member_value(&self, body: FieldValue) -> AuthResult<FieldValue> {
        self.add_member_response(MemberInput::Native(body))
            .await?
            .body
            .field_value()
    }

    async fn add_member_response(&self, body: MemberInput) -> AuthResult<AuthResponse> {
        let schema = self.plugin.config.schema.member.clone();
        let route = AuthRoute::server_only(HttpMethod::Post, "addMember")
            .body_validator(move |request| validate(request, &schema));
        let handler = |request: AuthRequest, context: std::sync::Arc<AuthContext<S>>| async move {
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
            Ok(AuthResponse::native(200, member.field_values()?.into()))
        };
        match body {
            MemberInput::Json(body) => {
                self.context
                    .dispatch_native(self.source, route, body, None, handler)
                    .await
            }
            MemberInput::Native(body) => {
                self.context
                    .dispatch_native_value(self.source, route, body, None, handler)
                    .await
            }
        }
    }
}

pub(super) fn validate(
    request: &AuthRequest,
    schema: &better_auth_core::user_fields::UserConfig,
) -> AuthResult<ValidatedBody> {
    use super::super::input::{self, BaseField};
    let raw = request.input_field_value()?;
    let mut errors = Vec::new();
    let Some(object) = raw.as_object() else {
        return Err(AuthError::FieldInput {
            code: "VALIDATION_ERROR",
            message: input::native_invalid_type("body", "object", Some(&raw)),
        });
    };
    let body = input::native_fields(
        schema,
        object,
        &[
            ("userId", BaseField::CoercedString, true),
            ("role", BaseField::Roles, true),
            ("organizationId", BaseField::String, false),
            ("teamId", BaseField::String, false),
        ],
        "body",
        false,
        false,
        &mut errors,
    )?;
    input::finish(errors)?;
    Ok(ValidatedBody::native(
        body.clone().into(),
        AddMemberInput::from_field_values(body)?,
    ))
}
