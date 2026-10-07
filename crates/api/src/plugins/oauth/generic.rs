use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use better_auth_core::{AuthRequest, AuthResult};
use indexmap::IndexMap;
use reqwest::header::HeaderMap;
use serde_json::Value;

use super::token::{TokenEndpointAuth, TokenEndpointSecretAuthentication};
use super::{OAuthTokenSet, OAuthUserInfoRequest};

/// Authorization-code exchange values passed to a custom token handler.
pub struct OAuthCodeExchange<'a> {
    /// Authorization code returned by the provider.
    pub code: &'a str,
    /// Callback URI sent to the provider.
    pub redirect_uri: &'a str,
    /// PKCE verifier persisted with the authorization request.
    pub code_verifier: Option<&'a str>,
    /// Provider-specific device identifier from the callback.
    pub device_id: Option<&'a str>,
}

/// Exchanges a code when a provider does not use a standard token endpoint.
#[async_trait]
pub trait OAuthTokenHandler: Send + Sync {
    /// Exchange the authorization code without creating a local session.
    async fn get_token(&self, request: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet>;
}

/// Borrowed claims from the configured OIDC signature and claim validation.
pub struct VerifiedOAuthClaims<'a> {
    claims: &'a Value,
}

impl<'a> VerifiedOAuthClaims<'a> {
    pub(super) fn new(claims: &'a Value) -> Self {
        Self { claims }
    }

    /// Read the claims returned by the configured OIDC signature and claim validation.
    pub fn as_value(&self) -> &'a Value {
        self.claims
    }
}

/// Borrowed runtime inputs for a Generic OAuth profile lookup.
pub struct GenericOAuthProfileContext<'a> {
    client_id: &'a str,
    expected_nonce: Option<&'a str>,
    user_info_url: Option<&'a str>,
    verified_claims: Option<VerifiedOAuthClaims<'a>>,
}

impl<'a> GenericOAuthProfileContext<'a> {
    pub(super) fn new(
        config: &'a GenericOAuthConfig,
        expected_nonce: Option<&'a str>,
        verified_claims: Option<&'a Value>,
    ) -> Self {
        Self {
            client_id: &config.client_id,
            expected_nonce,
            user_info_url: config.user_info_url.as_deref(),
            verified_claims: verified_claims.map(VerifiedOAuthClaims::new),
        }
    }

    /// Read the client identifier from the resolved provider configuration.
    pub fn client_id(&self) -> &'a str {
        self.client_id
    }

    /// Read the nonce bound to this flow, when the caller supplied one.
    pub fn expected_nonce(&self) -> Option<&'a str> {
        self.expected_nonce
    }

    /// Read the resolved userinfo endpoint.
    pub fn user_info_url(&self) -> Option<&'a str> {
        self.user_info_url
    }

    /// Read claims that passed the configured OIDC signature and claim validation.
    pub fn verified_claims(&self) -> Option<&VerifiedOAuthClaims<'a>> {
        self.verified_claims.as_ref()
    }
}

/// Fetches the raw profile used for Generic OAuth account recognition.
#[async_trait]
pub trait GenericOAuthUserInfoHandler: Send + Sync {
    /// Return a raw provider profile, `None` when unavailable, or an application error.
    async fn get_user_info(&self, tokens: &OAuthUserInfoRequest) -> AuthResult<Option<Value>>;

    /// Read resolved options and completed verification before mapping a profile.
    /// Existing handlers retain their token-based lookup unless they override this method.
    async fn get_user_info_with_context(
        &self,
        tokens: &OAuthUserInfoRequest,
        _context: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<Option<Value>> {
        self.get_user_info(tokens).await
    }
}

/// Local profile fields; provider account identity is resolved separately.
#[derive(Debug, Clone, Default)]
pub struct OAuthProfile {
    /// Application user fields supplied by the profile mapper.
    pub additional_fields: better_auth_core::FieldMap,
    /// Leave the email unchanged with `None`, or override its string/null/undefined value.
    pub email: Option<better_auth_core::SchemaValue<Option<String>>>,
    /// Leave the name unchanged with `None`, or override its string/null/undefined value.
    pub name: Option<better_auth_core::SchemaValue<Option<String>>>,
    /// Override the profile image; `Some(None)` clears the provider value.
    pub image: Option<Option<String>>,
    /// Leave verification unchanged with `None`, or override its boolean/null/undefined value.
    pub email_verified: Option<better_auth_core::SchemaValue<Option<bool>>>,
}

/// Maps provider profile fields without changing the provider account subject.
#[async_trait]
pub trait OAuthProfileMapper: Send + Sync {
    /// Return local user fields derived from the raw provider profile.
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile>;
}

/// Resolves a stable provider account identifier from the original profile.
#[async_trait]
pub trait OAuthAccountSubject: Send + Sync {
    /// Return a nonempty immutable identifier; mapped local fields are not supplied.
    async fn resolve_subject(
        &self,
        tokens: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String>;
}

/// Resolves extra token refresh parameters for the authenticated request.
#[async_trait]
pub trait OAuthRefreshParameters: Send + Sync {
    /// Validate request-derived tenant or scope values before returning parameters.
    async fn parameters(&self, request: &AuthRequest) -> AuthResult<HashMap<String, String>>;
}

/// Static or request-dependent parameters for a token refresh.
#[derive(Clone)]
pub enum RefreshTokenParameters {
    /// Parameters shared by every refresh request.
    Static(HashMap<String, String>),
    /// Parameters computed from the authenticated request.
    Dynamic(Arc<dyn OAuthRefreshParameters>),
}

/// Generic OAuth and OpenID Connect provider configuration.
///
/// Discovery resolves once when the auth instance is built. Set
/// `require_id_token_verification` for providers whose identity comes from ID tokens.
#[derive(Clone)]
pub struct GenericOAuthConfig {
    /// OAuth client identifier.
    pub client_id: String,
    /// Client secret; omit for public clients or private-key JWT authentication.
    pub client_secret: Option<String>,
    /// OpenID configuration URL.
    pub discovery_url: Option<String>,
    /// Headers included in the discovery request.
    pub discovery_headers: HeaderMap,
    /// Require discovery to supply a usable issuer and JWKS URI.
    pub require_id_token_verification: bool,
    /// Explicit authorization endpoint; overrides discovery.
    pub authorization_url: Option<String>,
    /// Explicit token endpoint; overrides discovery.
    pub token_url: Option<String>,
    /// Explicit userinfo endpoint; overrides discovery.
    pub user_info_url: Option<String>,
    /// Explicit RP-initiated logout endpoint; overrides discovery.
    pub end_session_endpoint: Option<String>,
    /// Default redirect after provider logout.
    pub post_logout_redirect_uri: Option<String>,
    /// Complete only local logout even when the provider supports logout.
    pub disable_provider_logout: bool,
    /// Client authentication for code exchange and token refresh.
    pub token_endpoint_auth: Option<TokenEndpointAuth>,
    /// Upstream's legacy secret authentication selection.
    pub authentication: Option<TokenEndpointSecretAuthentication>,
    /// Default scopes; OIDC discovery providers also request `openid`.
    pub scopes: Vec<String>,
    /// Override the generated callback URI.
    pub redirect_uri: Option<String>,
    /// Authorization response type; defaults to `code`.
    pub response_type: Option<String>,
    /// Authorization response mode, such as `query` or `form_post`.
    pub response_mode: Option<String>,
    /// Provider authentication prompt.
    pub prompt: Option<String>,
    /// Send PKCE challenges and verifiers; defaults to true.
    pub pkce: bool,
    /// Authorization access type, such as `offline`.
    pub access_type: Option<String>,
    /// Fallback access-token lifetime when the token response omits an expiry.
    pub access_token_expires_in: Option<f64>,
    /// Extra authorization parameters in insertion order; reserved fields are protected.
    pub authorization_url_params: IndexMap<String, String>,
    /// Extra code-exchange parameters that cannot replace standard grant fields.
    pub token_url_params: HashMap<String, String>,
    /// Additional headers for authorization-code exchange.
    pub authorization_headers: HeaderMap,
    /// Extra token refresh parameters.
    pub refresh_token_params: Option<RefreshTokenParameters>,
    /// Custom code exchange for providers with a nonstandard token endpoint.
    pub get_token: Option<Arc<dyn OAuthTokenHandler>>,
    /// Custom raw-profile lookup.
    pub get_user_info: Option<Arc<dyn GenericOAuthUserInfoHandler>>,
    /// Map profile fields independently of account recognition.
    pub map_profile_to_user: Option<Arc<dyn OAuthProfileMapper>>,
    /// Override the immutable subject resolver (`sub` for OIDC, `id` for OAuth).
    pub account_subject: Option<Arc<dyn OAuthAccountSubject>>,
    /// Require an explicit `requestSignUp` to create a new user.
    pub disable_implicit_sign_up: bool,
    /// Reject creation of new users through this provider.
    pub disable_sign_up: bool,
    /// Update existing local profile fields on sign-in.
    pub override_user_info: bool,
    /// Require the local user's email to be verified before issuing a session.
    pub require_email_verification: bool,
    /// Restart callbacks without state using a fresh authorization request.
    pub allow_idp_initiated: bool,
    /// Disable the default OIDC nonce binding for providers that cannot echo a nonce.
    pub disable_id_token_nonce_binding: bool,
}

impl Default for GenericOAuthConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: None,
            discovery_url: None,
            discovery_headers: HeaderMap::new(),
            require_id_token_verification: false,
            authorization_url: None,
            token_url: None,
            user_info_url: None,
            end_session_endpoint: None,
            post_logout_redirect_uri: None,
            disable_provider_logout: false,
            token_endpoint_auth: None,
            authentication: None,
            scopes: Vec::new(),
            redirect_uri: None,
            response_type: None,
            response_mode: None,
            prompt: None,
            pkce: true,
            access_type: None,
            access_token_expires_in: None,
            authorization_url_params: IndexMap::new(),
            token_url_params: HashMap::new(),
            authorization_headers: HeaderMap::new(),
            refresh_token_params: None,
            get_token: None,
            get_user_info: None,
            map_profile_to_user: None,
            account_subject: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info: false,
            require_email_verification: false,
            allow_idp_initiated: false,
            disable_id_token_nonce_binding: false,
        }
    }
}

impl GenericOAuthConfig {
    /// Configure Auth0 discovery from a domain or URL and the default OIDC scopes.
    pub fn auth0(client_id: &str, client_secret: &str, domain: &str) -> AuthResult<Self> {
        let address = if domain.starts_with("http://") || domain.starts_with("https://") {
            domain.to_owned()
        } else {
            format!("https://{domain}")
        };
        let url = url::Url::parse(&address)
            .map_err(|error| better_auth_core::AuthError::config(error.to_string()))?;
        let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
        Ok(Self::discovery_preset(
            client_id,
            client_secret,
            format!("https://{host}/.well-known/openid-configuration"),
        ))
    }

    /// Configure Keycloak discovery from the realm issuer and default OIDC scopes.
    pub fn keycloak(client_id: &str, client_secret: &str, issuer: &str) -> Self {
        Self::discovery_preset(
            client_id,
            client_secret,
            format!(
                "{}/.well-known/openid-configuration",
                issuer.strip_suffix('/').unwrap_or(issuer)
            ),
        )
    }

    /// Configure Okta discovery from the issuer and default OIDC scopes.
    pub fn okta(client_id: &str, client_secret: &str, issuer: &str) -> Self {
        Self::keycloak(client_id, client_secret, issuer)
    }

    fn discovery_preset(client_id: &str, client_secret: &str, discovery_url: String) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            discovery_url: Some(discovery_url),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            ..Default::default()
        }
    }
}
