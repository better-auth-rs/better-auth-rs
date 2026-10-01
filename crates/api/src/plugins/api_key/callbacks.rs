use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    RuntimeExtensions,
    plugin::MetadataMap,
    store::{ApiKeyStore, MemberStore, OrganizationStore},
};
use serde_json::Value;
use std::collections::HashMap;

/// Resource permissions assigned to an API key.
pub type ApiKeyPermissions = HashMap<String, Vec<String>>;

/// Endpoint data available to application API key callbacks.
#[derive(Clone, Copy)]
pub struct ApiKeyEndpoint<'a> {
    /// HTTP request, absent for a requestless server API call.
    pub request: Option<&'a AuthRequest>,
    /// Endpoint path; absent in the server-only verification hook matcher.
    pub path: Option<&'a str>,
    /// Parsed endpoint input, including route defaults.
    pub body: &'a Value,
    /// Global authentication configuration.
    pub auth_config: &'a AuthConfig,
    /// Application runtime state registered with the authentication instance.
    pub extensions: &'a RuntimeExtensions,
    /// Metadata registered by enabled plugins.
    pub metadata: &'a MetadataMap,
    /// Database API key adapter, independent of the selected key storage mode.
    pub api_keys: &'a dyn ApiKeyStore,
    /// Organization adapter for organization-owned credentials.
    pub organizations: &'a dyn OrganizationStore,
    /// Organization memberships available to application permission policies.
    pub members: &'a dyn MemberStore,
}

impl<'a> ApiKeyEndpoint<'a> {
    pub(super) fn new<S: AuthSchema>(
        ctx: &'a AuthContext<S>,
        request: Option<&'a AuthRequest>,
        path: Option<&'a str>,
        body: &'a Value,
    ) -> Self {
        Self {
            request,
            path,
            body,
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
            metadata: &ctx.metadata,
            api_keys: ctx.database.as_ref(),
            organizations: ctx.database.as_ref(),
            members: ctx.database.as_ref(),
        }
    }
}

/// Application credential generation, before hashing and starting-character storage.
#[async_trait]
pub trait ApiKeyGenerator: Send + Sync {
    async fn generate(&self, length: usize, prefix: Option<&str>) -> AuthResult<String>;
}

/// Synchronous key extraction used by the session hook matcher and handler.
pub trait ApiKeyGetter: Send + Sync {
    fn get(&self, ctx: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>>;
}

/// Application validation before credential state and permission checks.
#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    async fn validate(&self, key: &str, ctx: ApiKeyEndpoint<'_>) -> AuthResult<bool>;
}

/// Dynamic creation permissions. Explicit permissions still cause this callback to run.
#[async_trait]
pub trait ApiKeyDefaultPermissions: Send + Sync {
    async fn permissions(
        &self,
        reference_id: &str,
        ctx: ApiKeyEndpoint<'_>,
    ) -> AuthResult<ApiKeyPermissions>;
}

// The HTTP router hides ordinary callback errors; requestless APIs preserve them.
pub(super) fn callback_error(error: AuthError, request: Option<&AuthRequest>) -> AuthError {
    if request.is_some()
        && error.status_code() == 500
        && !matches!(error, AuthError::Response(_) | AuthError::Upstream { .. })
    {
        better_auth_core::observability::logger::current().error(
            "API key callback failed",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
        AuthResponse::new(500).into()
    } else {
        error
    }
}
