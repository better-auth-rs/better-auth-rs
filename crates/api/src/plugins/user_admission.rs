//! Application admission policy for user provisioning and provider authentication.

use super::endpoint_context::EndpointContext;
use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResponse, AuthResult, AuthSchema, CreateUser};
use serde::Serialize;
use serde_json::{Map, Value};
use std::sync::Arc;

/// The operation that is subject to the admission policy.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UserValidationAction {
    CreateUser,
    LinkAccount,
    SignIn,
}

/// Provider identity and the original, unmapped profile.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserValidationProvider {
    pub provider_id: String,
    /// `None` preserves an absent profile; `Some(Value::Null)` preserves explicit null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Value>,
}

/// Provenance of a user validation operation.
#[derive(Debug, Clone, Serialize)]
pub struct UserValidationSource {
    pub action: UserValidationAction,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<UserValidationProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso: Option<UserValidationProvider>,
}
impl UserValidationSource {
    pub fn new(method: impl Into<String>, action: UserValidationAction) -> Self {
        Self {
            action,
            method: method.into(),
            oauth: None,
            sso: None,
        }
    }
    pub(crate) fn oauth(
        provider: &str,
        profile: Option<&Value>,
        action: UserValidationAction,
    ) -> Self {
        Self {
            oauth: Some(UserValidationProvider {
                provider_id: provider.to_owned(),
                profile: profile.cloned(),
            }),
            ..Self::new("oauth", action)
        }
    }
}

/// User input before database hooks and adapter field transforms.
#[derive(Debug, Clone, Serialize)]
pub struct UserValidationData {
    /// Public field names. Generated identifiers are absent during creation.
    pub user: Map<String, Value>,
    pub source: UserValidationSource,
}

/// A public rejection returned by the application's admission policy.
#[derive(Debug, Clone)]
pub struct UserValidationRejection {
    pub error: String,
    pub error_description: Option<String>,
}
impl UserValidationRejection {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            error_description: None,
        }
    }
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }
    pub(crate) fn message(&self) -> &str {
        self.error_description
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.error)
    }
    pub(crate) fn into_auth_error(self) -> AuthError {
        match AuthResponse::json(
            403,
            &serde_json::json!({"code": self.error, "message": self.message()}),
        ) {
            Ok(response) => response.into(),
            Err(error) => error.into(),
        }
    }
}

/// Equivalent to `user.validateUserInfo`. Returning `None` admits the operation.
///
/// Callback errors reject with `validation_failed`; they never permit authentication.
#[async_trait]
pub trait ValidateUserInfo<S: AuthSchema>: Send + Sync {
    async fn validate(
        &self,
        data: &UserValidationData,
        context: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>>;
}

pub(crate) async fn validate<S: AuthSchema>(
    data: UserValidationData,
    endpoint: &EndpointContext<'_, S>,
) -> Result<(), UserValidationRejection> {
    let Some(callback) = endpoint
        .auth
        .extensions
        .get::<Arc<dyn ValidateUserInfo<S>>>()
    else {
        return Ok(());
    };
    let invalid_source = if data.source.method.is_empty() {
        Some("User validation source is required")
    } else if data.source.method == "oauth"
        && data
            .source
            .oauth
            .as_ref()
            .is_none_or(|provider| provider.provider_id.is_empty())
    {
        Some("OAuth user validation source requires oauth.providerId")
    } else if matches!(data.source.method.as_str(), "sso-oidc" | "sso-saml")
        && data
            .source
            .sso
            .as_ref()
            .is_none_or(|provider| provider.provider_id.is_empty())
    {
        Some("SSO user validation source requires sso.providerId")
    } else {
        None
    };
    if let Some(message) = invalid_source {
        return Err(
            UserValidationRejection::new("validation_source_missing").with_description(message)
        );
    }
    match callback.validate(&data, endpoint).await {
        Ok(Some(rejection)) if !rejection.error.is_empty() => Err(rejection),
        Ok(_) => Ok(()),
        Err(error) => {
            // Upstream deliberately masks application exceptions at this fail-closed boundary.
            better_auth_core::observability::logger::current().error(
                "User validation callback failed",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            Err(UserValidationRejection::new("validation_failed")
                .with_description("User validation failed"))
        }
    }
}

pub(crate) async fn validate_create<S: AuthSchema>(
    input: &CreateUser,
    source: UserValidationSource,
    endpoint: &EndpointContext<'_, S>,
) -> Result<(), UserValidationRejection> {
    if endpoint
        .auth
        .extensions
        .get::<Arc<dyn ValidateUserInfo<S>>>()
        .is_none()
    {
        return Ok(());
    }
    let mut user = input.additional_fields.clone();
    for (name, value) in [
        ("id", input.id.as_ref()),
        ("email", input.email.as_ref()),
        ("name", input.name.as_ref()),
        ("phoneNumber", input.phone_number.as_ref()),
        ("role", input.role.as_ref()),
    ] {
        if let Some(value) = value {
            let _ = user.insert(
                name.into(),
                Value::String(if name == "email" {
                    value.to_lowercase()
                } else {
                    value.clone()
                }),
            );
        }
    }
    for (name, value) in [
        ("image", &input.image),
        ("username", &input.username),
        ("displayUsername", &input.display_username),
    ] {
        if let Some(value) = value {
            let _ = user.insert(
                name.into(),
                value.clone().map(Value::String).unwrap_or(Value::Null),
            );
        }
    }
    for (name, value) in [
        ("banned", input.banned),
        ("emailVerified", input.email_verified),
        ("isAnonymous", input.is_anonymous),
        ("phoneNumberVerified", input.phone_number_verified),
    ] {
        if let Some(value) = value {
            let _ = user.insert(name.into(), Value::Bool(value));
        }
    }
    if let Some(value) = &input.ban_reason {
        let _ = user.insert("banReason".into(), value.clone().into());
    }
    if let Some(value) = input.ban_expires {
        let _ = user.insert("banExpires".into(), serde_json::json!(value));
    }
    if let Some(value) = &input.metadata {
        let _ = user.insert("metadata".into(), value.clone());
    }
    let now = serde_json::json!(chrono::Utc::now());
    let _ = user.entry("createdAt").or_insert_with(|| now.clone());
    let _ = user.entry("updatedAt").or_insert(now);
    validate(UserValidationData { user, source }, endpoint).await
}

pub(crate) async fn create_user<S: AuthSchema>(
    mut input: CreateUser,
    method: &str,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<better_auth_core::wire::UserView> {
    validate_create(
        &input,
        UserValidationSource::new(method, UserValidationAction::CreateUser),
        endpoint,
    )
    .await
    .map_err(UserValidationRejection::into_auth_error)?;
    super::helpers::apply_default_role(endpoint.auth, &mut input);
    endpoint.auth.database.create_user(input).await
}
