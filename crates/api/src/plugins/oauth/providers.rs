use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, SchemaValue};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

pub(super) mod defaults;
pub(super) mod facebook;
pub(super) mod paybin;
pub(super) mod paypal;
pub(super) mod twitter;
pub(super) mod wechat;
use super::OAuthProfileMapper;
use super::token::{TokenEndpointAuth, TokenEndpointSecretAuthentication};
use defaults::ProviderKind;
pub(super) use defaults::github_profile;
use std::{collections::HashSet, sync::Arc};

/// Configuration for the OAuth plugin, containing all registered providers.
#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub providers: IndexMap<String, OAuthProvider>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthTokenSet {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
}

/// User information extracted from an OAuth provider's user info endpoint.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    /// Mapped application fields validated by the configured user schema.
    pub additional_fields: serde_json::Map<String, Value>,
    pub id: String,
    /// Preserve a missing email with `Undefined`, null with `Typed(None)`, or a string.
    pub email: SchemaValue<Option<String>>,
    pub name: Option<String>,
    /// Omit the image with `None`, clear it with `Some(None)`, or supply a URL.
    pub image: Option<Option<String>>,
    /// Preserve omitted or null provider values without treating either as verified.
    pub email_verified: SchemaValue<Option<bool>>,
}

impl OAuthUserInfo {
    pub(super) fn email(&self) -> AuthResult<Option<&str>> {
        profile_email(&self.email)
    }

    pub(super) fn email_verified(&self) -> AuthResult<bool> {
        profile_email_verified(&self.email_verified)
    }
}

pub(super) fn profile_email_verified(value: &SchemaValue<Option<bool>>) -> AuthResult<bool> {
    match value {
        SchemaValue::Typed(Some(value)) | SchemaValue::Dynamic(Value::Bool(value)) => Ok(*value),
        SchemaValue::Undefined | SchemaValue::Typed(None) | SchemaValue::Dynamic(Value::Null) => {
            Ok(false)
        }
        SchemaValue::Dynamic(_) | SchemaValue::InvalidDate => Err(AuthError::internal(
            "OAuth profile email verification must be a boolean, null, or undefined",
        )),
    }
}

pub(super) fn profile_email(value: &SchemaValue<Option<String>>) -> AuthResult<Option<&str>> {
    match value {
        SchemaValue::Undefined | SchemaValue::Typed(None) | SchemaValue::Dynamic(Value::Null) => {
            Ok(None)
        }
        SchemaValue::Typed(Some(value)) | SchemaValue::Dynamic(Value::String(value)) => {
            Ok(Some(value))
        }
        SchemaValue::Dynamic(_) | SchemaValue::InvalidDate => Err(AuthError::internal(
            "OAuth profile email must be a string, null, or undefined",
        )),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthCallbackUserPayload {
    pub name: Option<OAuthCallbackUserName>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthCallbackUserName {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthUserInfoRequest {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
    pub user: Option<OAuthCallbackUserPayload>,
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfoResponse {
    pub user: OAuthUserInfo,
    pub data: Value,
}

/// Fetch a provider profile while preserving application errors at the endpoint boundary.
#[async_trait]
pub trait OAuthUserInfoHandler: Send + Sync {
    /// Return `None` when no profile is available, or preserve an application error.
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>>;
}

#[async_trait]
pub trait OAuthRefreshTokenHandler: Send + Sync {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String>;
}

#[async_trait]
pub trait OAuthIdTokenVerifier: Send + Sync {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String>;
}

/// Input options for a social OAuth provider. Constructors retain omitted options.
#[derive(Clone)]
pub struct OAuthProvider {
    kind: ProviderKind,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    /// Cloudflare token endpoint authentication override for code exchange and refresh.
    /// Other Social providers retain their fixed authentication methods.
    pub token_endpoint_auth: Option<TokenEndpointAuth>,
    pub user_info_url: Option<String>,
    /// Provider callback URI for authorization and code exchange; an empty value uses the route URI.
    pub redirect_uri: Option<String>,
    /// OIDC provider endpoint used for RP-initiated logout.
    pub end_session_endpoint: Option<String>,
    /// Default redirect after provider logout; a request callback overrides it.
    pub post_logout_redirect_uri: Option<String>,
    /// Additional scopes for built-in providers; omission preserves their defaults.
    pub scopes: Option<Vec<String>>,
    /// Exclude the built-in provider scopes from authorization requests.
    pub disable_default_scope: bool,
    /// Reject direct ID-token sign-in and linking before invoking the verifier.
    pub disable_id_token_sign_in: bool,
    /// Authentication prompt for providers that support this option.
    /// Omission preserves the provider default.
    pub prompt: Option<String>,
    pub authorization_params: Vec<(String, String)>,
    /// Replace the base JSON decoder for a custom provider.
    pub map_user_info: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    /// Map local fields after built-in profile decoding without changing account identity.
    pub map_profile_to_user: Option<Arc<dyn OAuthProfileMapper>>,
    pub get_user_info: Option<Arc<dyn OAuthUserInfoHandler>>,
    pub refresh_access_token: Option<Arc<dyn OAuthRefreshTokenHandler>>,
    pub verify_id_token: Option<Arc<dyn OAuthIdTokenVerifier>>,
    pub disable_implicit_sign_up: Option<bool>,
    pub disable_sign_up: Option<bool>,
    pub override_user_info_on_sign_in: bool,
}

impl OAuthProvider {
    /// Configure a Cognito hosted domain and its fixed user-pool issuer and JWKS.
    /// Set `identity_provider` through `authorization_params` to select a federated provider.
    pub fn cognito(
        client_id: &str,
        client_secret: &str,
        options: super::CognitoOptions,
    ) -> AuthResult<Self> {
        if options.domain.is_empty() || options.region.is_empty() || options.user_pool_id.is_empty()
        {
            better_auth_core::observability::logger::current().error(
                "Domain, region and userPoolId are required for Amazon Cognito. Make sure to provide them in the options.",
                &[],
            );
            return Err(AuthError::internal("DOMAIN_AND_REGION_REQUIRED"));
        }
        let domain = options
            .domain
            .strip_prefix("https://")
            .or_else(|| options.domain.strip_prefix("http://"))
            .unwrap_or(&options.domain);
        let provider = Self {
            user_info_url: Some(format!("https://{domain}/oauth2/userinfo")),
            ..Self::custom(
                client_id,
                client_secret,
                &format!("https://{domain}/oauth2/authorize"),
                &format!("https://{domain}/oauth2/token"),
            )
        };
        Ok(Self {
            kind: ProviderKind::Cognito(options),
            ..provider
        })
    }

    pub(super) fn cognito_options(&self) -> Option<&super::CognitoOptions> {
        match &self.kind {
            ProviderKind::Cognito(options) => Some(options),
            _ => None,
        }
    }

    /// Configure a custom social provider with explicit endpoints and profile handling.
    pub fn custom(client_id: &str, client_secret: &str, auth_url: &str, token_url: &str) -> Self {
        Self {
            kind: ProviderKind::Custom,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            token_endpoint_auth: None,
            user_info_url: None,
            redirect_uri: None,
            end_session_endpoint: None,
            post_logout_redirect_uri: None,
            scopes: None,
            disable_default_scope: false,
            disable_id_token_sign_in: false,
            prompt: None,
            authorization_params: Vec::new(),
            map_user_info: None,
            map_profile_to_user: None,
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: None,
            disable_sign_up: None,
            override_user_info_on_sign_in: false,
        }
    }

    /// Configure Google with its built-in endpoints and profile decoder.
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Google {
                jwks_url: super::google::JWKS_URL.to_owned(),
            },
            user_info_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".into()),
            authorization_params: vec![("include_granted_scopes".into(), "true".into())],
            ..Self::custom(
                client_id,
                client_secret,
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
            )
        }
    }

    /// Configure GitHub with its built-in profile and email lookup.
    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self::github_with_endpoints(
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            "https://api.github.com/user/emails",
        )
    }

    /// Configure GitHub with custom endpoints while retaining GitHub profile semantics.
    pub fn github_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        user_info_url: &str,
        user_emails_url: &str,
    ) -> Self {
        Self {
            kind: ProviderKind::GitHub {
                user_url: user_info_url.into(),
                emails_url: user_emails_url.into(),
            },
            user_info_url: Some(user_info_url.into()),
            ..Self::custom(client_id, client_secret, auth_url, token_url)
        }
    }

    /// Configure Discord with its built-in endpoints and profile decoder.
    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Discord,
            user_info_url: Some("https://discord.com/api/users/@me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://discord.com/api/oauth2/authorize",
                "https://discord.com/api/oauth2/token",
            )
        }
    }

    /// Configure GitLab with its built-in endpoints and active-user profile decoder.
    pub fn gitlab(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::GitLab,
            user_info_url: Some("https://gitlab.com/api/v4/user".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://gitlab.com/oauth/authorize",
                "https://gitlab.com/oauth/token",
            )
        }
    }

    /// Configure Spotify with its built-in endpoints and profile decoder.
    pub fn spotify(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Spotify,
            user_info_url: Some("https://api.spotify.com/v1/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://accounts.spotify.com/authorize",
                "https://accounts.spotify.com/api/token",
            )
        }
    }

    /// Configure Hugging Face with its built-in endpoints and HTTP profile decoder.
    pub fn huggingface(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::HuggingFace,
            user_info_url: Some("https://huggingface.co/oauth/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://huggingface.co/oauth/authorize",
                "https://huggingface.co/oauth/token",
            )
        }
    }

    /// Configure Polar with its built-in endpoints and HTTP profile decoder.
    pub fn polar(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Polar,
            user_info_url: Some("https://api.polar.sh/v1/oauth2/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://polar.sh/oauth2/authorize",
                "https://api.polar.sh/v1/oauth2/token",
            )
        }
    }

    /// Configure Vercel with its built-in endpoints and HTTP profile decoder.
    pub fn vercel(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Vercel,
            user_info_url: Some("https://api.vercel.com/login/oauth/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://vercel.com/oauth/authorize",
                "https://api.vercel.com/login/oauth/token",
            )
        }
    }

    pub(super) fn supports_refresh(&self) -> bool {
        !matches!(self.kind, ProviderKind::Vercel)
    }

    /// Configure Figma with PKCE, HTTP Basic token authentication, and its HTTP profile decoder.
    pub fn figma(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Figma,
            user_info_url: Some("https://api.figma.com/v1/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.figma.com/oauth",
                "https://api.figma.com/v1/oauth/token",
            )
        }
    }

    /// Configure Dropbox with PKCE, client-secret-post authentication, and its POST profile lookup.
    pub fn dropbox(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Dropbox,
            user_info_url: Some("https://api.dropboxapi.com/2/users/get_current_account".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.dropbox.com/oauth2/authorize",
                "https://api.dropboxapi.com/oauth2/token",
            )
        }
    }

    pub(super) fn user_info_request(
        &self,
        url: &str,
        access_token: &str,
    ) -> reqwest::RequestBuilder {
        if self.is_vk() {
            return reqwest::Client::new()
                .post(url)
                .header("Accept", "*/*")
                .form(&[
                    ("access_token", access_token),
                    ("client_id", &self.client_id),
                ]);
        }
        let method = match self.kind {
            ProviderKind::Dropbox | ProviderKind::Linear => reqwest::Method::POST,
            _ => reqwest::Method::GET,
        };
        let request = reqwest::Client::new()
            .request(method, url)
            .bearer_auth(access_token)
            .header(
                "Accept",
                if self.is_twitter() || self.cognito_options().is_some() {
                    "*/*"
                } else {
                    "application/json"
                },
            );
        if matches!(self.kind, ProviderKind::Linear) {
            request.json(&serde_json::json!({
                "query": "query { viewer { id name email avatarUrl active createdAt updatedAt } }"
            }))
        } else if self.is_reddit() {
            request.header("User-Agent", "better-auth")
        } else {
            request
        }
    }

    pub(super) fn is_figma(&self) -> bool {
        matches!(self.kind, ProviderKind::Figma)
    }

    /// Configure Kick with PKCE, client-secret-post, and its HTTP profile decoder.
    pub fn kick(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Kick,
            user_info_url: Some("https://api.kick.com/public/v1/users".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://id.kick.com/oauth/authorize",
                "https://id.kick.com/oauth/token",
            )
        }
    }

    /// Configure LinkedIn with its code flow, client-secret-post, and Bearer HTTP profile.
    /// LinkedIn omits PKCE parameters in the pinned provider protocol.
    pub fn linkedin(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::LinkedIn,
            user_info_url: Some("https://api.linkedin.com/v2/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.linkedin.com/oauth/v2/authorization",
                "https://www.linkedin.com/oauth/v2/accessToken",
            )
        }
    }

    /// Configure Slack with its code flow, client-secret-post, and OpenID HTTP profile.
    pub fn slack(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Slack,
            user_info_url: Some("https://slack.com/api/openid.connect.userInfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://slack.com/openid/connect/authorize",
                "https://slack.com/api/openid.connect.token",
            )
        }
    }

    /// Configure Naver with its code flow, client-secret-post, and HTTP profile envelope.
    pub fn naver(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Naver,
            user_info_url: Some("https://openapi.naver.com/v1/nid/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://nid.naver.com/oauth2.0/authorize",
                "https://nid.naver.com/oauth2.0/token",
            )
        }
    }

    /// Configure Linear with its code flow, client-secret-post, and GraphQL viewer profile.
    pub fn linear(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Linear,
            user_info_url: Some("https://api.linear.app/graphql".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://linear.app/oauth/authorize",
                "https://api.linear.app/oauth/token",
            )
        }
    }

    /// Configure Atlassian with PKCE, client-secret-post, and its HTTP account profile.
    pub fn atlassian(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Atlassian,
            user_info_url: Some("https://api.atlassian.com/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://auth.atlassian.com/authorize",
                "https://auth.atlassian.com/oauth/token",
            )
        }
    }

    pub(super) fn is_atlassian(&self) -> bool {
        matches!(self.kind, ProviderKind::Atlassian)
    }

    /// Configure Salesforce production with PKCE and its HTTP user-info profile.
    /// Set `auth_url`, `token_url`, and `user_info_url` together for a sandbox or custom login host.
    pub fn salesforce(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Salesforce,
            user_info_url: Some("https://login.salesforce.com/services/oauth2/userinfo".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://login.salesforce.com/services/oauth2/authorize",
                "https://login.salesforce.com/services/oauth2/token",
            )
        }
    }

    pub(super) fn is_salesforce(&self) -> bool {
        matches!(self.kind, ProviderKind::Salesforce)
    }

    pub(super) fn required_credentials_message(&self) -> Option<&'static str> {
        if self.is_paypal() {
            return Some(
                "Client Id and Client Secret is required for PayPal. Make sure to provide them in the options.",
            );
        }
        match self.kind {
            ProviderKind::Facebook(_) => Some(
                "Client ID and client secret are required for Facebook. Make sure to provide them in the options.",
            ),
            ProviderKind::Figma => Some(
                "Client Id and Client Secret are required for Figma. Make sure to provide them in the options.",
            ),
            ProviderKind::Atlassian => Some("Client Id and Secret are required for Atlassian"),
            ProviderKind::Salesforce => Some(
                "Client Id and Client Secret are required for Salesforce. Make sure to provide them in the options.",
            ),
            ProviderKind::Paybin { .. } => Some(
                "Client Id and Client Secret is required for Paybin. Make sure to provide them in the options.",
            ),
            _ => None,
        }
    }

    pub(super) fn fixed_authorization_params(&self) -> &'static [(&'static str, &'static str)] {
        match self.kind {
            ProviderKind::Atlassian => &[("audience", "api.atlassian.com")],
            _ => &[],
        }
    }

    /// Configure Reddit with HTTP Basic token authentication and its API user profile.
    /// Set `duration` to `permanent` through `authorization_params` for persistent access.
    pub fn reddit(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Reddit,
            user_info_url: Some("https://oauth.reddit.com/api/v1/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.reddit.com/api/v1/authorize",
                "https://www.reddit.com/api/v1/access_token",
            )
        }
    }

    /// Configure Kakao with ordered scopes, client-secret-post, and its account profile.
    pub fn kakao(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Kakao,
            user_info_url: Some("https://kapi.kakao.com/v2/user/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://kauth.kakao.com/oauth/authorize",
                "https://kauth.kakao.com/oauth/token",
            )
        }
    }

    /// Configure Zoom with authorization PKCE, client-secret-post, and its HTTP user profile.
    /// The pinned Zoom provider ignores configured and request scopes.
    pub fn zoom(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Zoom { pkce: true },
            user_info_url: Some("https://api.zoom.us/v2/users/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://zoom.us/oauth/authorize",
                "https://zoom.us/oauth/token",
            )
        }
    }

    /// Configure Zoom with its `pkce: false` option for the authorization URL.
    /// Code exchange still forwards the supplied verifier, matching the pinned provider.
    pub fn zoom_without_pkce(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Zoom { pkce: false },
            ..Self::zoom(client_id, client_secret)
        }
    }

    /// Configure Twitter with PKCE, HTTP Basic token authentication, and its two user-info requests.
    pub fn twitter(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Twitter,
            user_info_url: Some(
                "https://api.x.com/2/users/me?user.fields=profile_image_url".into(),
            ),
            ..Self::custom(
                client_id,
                client_secret,
                "https://x.com/i/oauth2/authorize",
                "https://api.x.com/2/oauth2/token",
            )
        }
    }

    /// Configure WeChat WebsiteApp with GET grants and its HTTP profile lookup.
    /// Set `authorization_params`'s `lang` to `en` for the English authorization page.
    pub fn wechat(client_id: &str, client_secret: &str) -> Self {
        Self::wechat_with_endpoints(
            client_id,
            client_secret,
            "https://open.weixin.qq.com/connect/qrconnect",
            "https://api.weixin.qq.com/sns/oauth2/access_token",
            "https://api.weixin.qq.com/sns/oauth2/refresh_token",
            "https://api.weixin.qq.com/sns/userinfo",
        )
    }

    /// Configure WeChat endpoints while retaining its GET grants and profile semantics.
    pub fn wechat_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        refresh_url: &str,
        user_info_url: &str,
    ) -> Self {
        Self {
            kind: ProviderKind::WeChat {
                refresh_url: refresh_url.into(),
            },
            user_info_url: Some(user_info_url.into()),
            ..Self::custom(client_id, client_secret, auth_url, token_url)
        }
    }

    pub(super) fn wechat_refresh_url(&self) -> Option<&str> {
        match &self.kind {
            ProviderKind::WeChat { refresh_url } => Some(refresh_url),
            _ => None,
        }
    }

    pub(super) fn is_twitter(&self) -> bool {
        matches!(self.kind, ProviderKind::Twitter)
    }

    /// Configure VK with PKCE, client-secret-post grants, and form-based user info.
    pub fn vk(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Vk,
            user_info_url: Some("https://id.vk.com/oauth2/user_info".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://id.vk.com/authorize",
                "https://id.vk.com/oauth2/auth",
            )
        }
    }

    pub(super) fn is_vk(&self) -> bool {
        matches!(self.kind, ProviderKind::Vk)
    }

    pub(super) fn is_reddit(&self) -> bool {
        matches!(self.kind, ProviderKind::Reddit)
    }

    pub(super) fn uses_pkce(&self) -> bool {
        !matches!(
            self.kind,
            ProviderKind::Facebook(_)
                | ProviderKind::LinkedIn
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Linear
                | ProviderKind::Reddit
                | ProviderKind::Kakao
                | ProviderKind::Zoom { pkce: false }
                | ProviderKind::WeChat { .. }
        )
    }

    pub(super) fn forwards_code_verifier(&self) -> bool {
        matches!(self.kind, ProviderKind::Zoom { .. }) || self.uses_pkce()
    }

    pub(super) fn omits_request_hints(&self) -> bool {
        matches!(
            self.kind,
            ProviderKind::Cognito(_)
                | ProviderKind::PayPal
                | ProviderKind::Cloudflare
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Atlassian
                | ProviderKind::Reddit
                | ProviderKind::Salesforce
                | ProviderKind::Kakao
                | ProviderKind::Zoom { .. }
                | ProviderKind::Twitter
                | ProviderKind::WeChat { .. }
                | ProviderKind::Vk
        )
    }

    pub(super) fn omits_device_id(&self) -> bool {
        matches!(
            self.kind,
            ProviderKind::Facebook(_)
                | ProviderKind::Cognito(_)
                | ProviderKind::PayPal
                | ProviderKind::Cloudflare
                | ProviderKind::LinkedIn
                | ProviderKind::Paybin { .. }
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Linear
                | ProviderKind::Atlassian
                | ProviderKind::Reddit
                | ProviderKind::Salesforce
                | ProviderKind::Kakao
                | ProviderKind::Zoom { .. }
                | ProviderKind::Twitter
                | ProviderKind::WeChat { .. }
        )
    }

    /// Configure Cloudflare with PKCE and its API user profile.
    /// Pass an empty secret for a public client; confidential clients default to HTTP Basic.
    pub fn cloudflare(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: ProviderKind::Cloudflare,
            user_info_url: Some("https://api.cloudflare.com/client/v4/user".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://dash.cloudflare.com/oauth2/auth",
                "https://dash.cloudflare.com/oauth2/token",
            )
        }
    }

    pub(super) fn http_profile_data(&self, mut response: Value) -> Result<Option<Value>, String> {
        if matches!(self.kind, ProviderKind::Atlassian | ProviderKind::Kakao) && response.is_null()
        {
            Ok(None)
        } else if matches!(self.kind, ProviderKind::Discord) {
            defaults::prepare_discord_profile(&mut response)?;
            Ok(Some(response))
        } else if matches!(self.kind, ProviderKind::Kick) {
            response
                .pointer_mut("/data/0")
                .map(|profile| Some(profile.take()))
                .ok_or_else(|| "Kick user info response did not contain a profile".into())
        } else if matches!(self.kind, ProviderKind::Linear) {
            Ok(response
                .pointer_mut("/data/viewer")
                .filter(|profile| !profile.is_null())
                .map(Value::take))
        } else if matches!(self.kind, ProviderKind::Cloudflare) {
            if response.get("success").and_then(Value::as_bool) != Some(true) {
                return Ok(None);
            }
            Ok(response
                .get_mut("result")
                .filter(|profile| !profile.is_null())
                .map(Value::take))
        } else {
            Ok(Some(response))
        }
    }

    pub(super) fn is_cloudflare(&self) -> bool {
        matches!(self.kind, ProviderKind::Cloudflare)
    }

    pub(super) fn token_endpoint_auth(&self) -> Option<&TokenEndpointAuth> {
        match self.kind {
            ProviderKind::Cloudflare => self.token_endpoint_auth.as_ref(),
            _ => None,
        }
    }

    pub(super) fn token_authentication(&self) -> Option<TokenEndpointSecretAuthentication> {
        (self.is_paypal()
            || self.is_figma()
            || self.is_reddit()
            || self.is_twitter()
            || matches!(self.kind, ProviderKind::Cloudflare) && !self.client_secret.is_empty())
        .then_some(TokenEndpointSecretAuthentication::Basic)
    }

    /// Return the effective implicit sign-up policy.
    pub fn disable_implicit_sign_up(&self) -> bool {
        self.disable_implicit_sign_up.unwrap_or(false)
    }

    /// Return the effective sign-up policy.
    pub fn disable_sign_up(&self) -> bool {
        self.disable_sign_up.unwrap_or(false)
    }

    pub(super) fn google_jwks_url(&self) -> Option<&str> {
        match &self.kind {
            ProviderKind::Google { jwks_url } => Some(jwks_url),
            _ => None,
        }
    }

    pub(super) fn google_hosted_domain(&self) -> Option<&str> {
        self.authorization_params
            .iter()
            .find(|(name, _)| name == "hd")
            .map(|(_, value)| value.as_str())
    }

    #[cfg(test)]
    pub(super) fn set_google_jwks_url(&mut self, url: String) {
        self.kind = ProviderKind::Google { jwks_url: url };
    }

    pub(super) fn github_endpoints(&self) -> Option<(&str, &str)> {
        match &self.kind {
            ProviderKind::GitHub {
                user_url,
                emails_url,
            } => Some((user_url, emails_url)),
            _ => None,
        }
    }

    pub(super) fn account_info_includes_id(&self) -> bool {
        self.get_user_info.is_some()
            || (self.github_endpoints().is_none() && self.map_user_info.is_some())
    }

    pub(super) fn decode_profile(
        &self,
        profile: Value,
    ) -> better_auth_core::AuthResult<Option<OAuthUserInfo>> {
        if let Some(mapper) = self.map_user_info {
            mapper(profile)
                .map(Some)
                .map_err(better_auth_core::AuthError::internal)
        } else {
            self.kind.decode_profile(profile)
        }
    }

    pub(super) fn resolve(&self) -> Self {
        let mut provider = self.clone();
        if provider.get_user_info.is_some() {
            // Upstream custom user-info handlers return before profile mapping.
            provider.map_profile_to_user = None;
        }
        provider
    }

    pub(super) fn social_scopes<'a>(&'a self, request: Option<&'a [String]>) -> Vec<&'a str> {
        if matches!(self.kind, ProviderKind::Zoom { .. } | ProviderKind::PayPal) {
            return Vec::new();
        }
        let configured = self.scopes.as_deref().unwrap_or_default();
        if matches!(self.kind, ProviderKind::Custom) {
            return request
                .unwrap_or(configured)
                .iter()
                .map(String::as_str)
                .collect();
        }
        let mut scopes = if self.disable_default_scope {
            Vec::new()
        } else {
            self.kind.scopes().to_vec()
        };
        let request = request.unwrap_or_default();
        let (first, second) = if matches!(self.kind, ProviderKind::Discord | ProviderKind::Slack) {
            (request, configured)
        } else {
            (configured, request)
        };
        scopes.extend(first.iter().chain(second).map(String::as_str));
        if matches!(self.kind, ProviderKind::Cloudflare) {
            let mut seen = HashSet::new();
            scopes.retain(|scope| seen.insert(*scope));
        }
        scopes
    }

    pub(super) fn social_prompt(&self) -> Option<&str> {
        match self.kind {
            ProviderKind::Custom
            | ProviderKind::Google { .. }
            | ProviderKind::GitHub { .. }
            | ProviderKind::Discord
            | ProviderKind::Polar
            | ProviderKind::PayPal
            | ProviderKind::Cognito(_)
            | ProviderKind::Paybin { .. }
            | ProviderKind::Atlassian => self
                .prompt
                .as_deref()
                .filter(|value| !value.is_empty())
                .or_else(|| matches!(self.kind, ProviderKind::Discord).then_some("none")),
            ProviderKind::Facebook(_)
            | ProviderKind::GitLab
            | ProviderKind::Spotify
            | ProviderKind::HuggingFace
            | ProviderKind::Vercel
            | ProviderKind::Figma
            | ProviderKind::Dropbox
            | ProviderKind::Kick
            | ProviderKind::LinkedIn
            | ProviderKind::Slack
            | ProviderKind::Naver
            | ProviderKind::Linear
            | ProviderKind::Reddit
            | ProviderKind::Cloudflare
            | ProviderKind::Salesforce
            | ProviderKind::Kakao
            | ProviderKind::Twitter
            | ProviderKind::WeChat { .. }
            | ProviderKind::Vk
            | ProviderKind::Zoom { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
