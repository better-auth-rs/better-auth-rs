use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, SchemaValue};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

pub(super) mod apple;
mod constructors;
pub(super) mod defaults;
pub(super) mod facebook;
pub(super) mod line;
pub(super) mod microsoft;
pub(super) mod paybin;
pub(super) mod paypal;
pub(super) mod tiktok;
pub(super) mod twitch;
pub(super) mod twitter;
pub(super) mod wechat;
use super::OAuthProfileMapper;
use super::token::{TokenEndpointAuth, TokenEndpointSecretAuthentication, TokenGrantType};
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
    /// Preserve a missing name with `Undefined`, null with `Typed(None)`, or a string.
    pub name: SchemaValue<Option<String>>,
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

    pub(super) fn name(&self) -> AuthResult<Option<&str>> {
        match &self.name {
            SchemaValue::Typed(Some(value)) | SchemaValue::Dynamic(Value::String(value)) => {
                Ok(Some(value))
            }
            SchemaValue::Undefined
            | SchemaValue::Typed(None)
            | SchemaValue::Dynamic(Value::Null) => Ok(None),
            SchemaValue::Dynamic(_) | SchemaValue::InvalidDate => Err(AuthError::internal(
                "OAuth profile name must be a string, null, or undefined",
            )),
        }
    }
}

pub(super) fn decode_profile_name(value: Option<&Value>) -> SchemaValue<Option<String>> {
    match value {
        Some(Value::String(value)) => Some(value.clone()).into(),
        Some(Value::Null) => None.into(),
        None | Some(_) => SchemaValue::Undefined,
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
    /// Additional key for built-in authorization-code exchanges that accept this option.
    pub client_key: Option<String>,
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
    /// Require the local user's email to be verified before issuing a session.
    pub require_email_verification: Option<bool>,
    pub override_user_info_on_sign_in: bool,
}

impl OAuthProvider {
    pub(super) fn microsoft_options(&self) -> Option<&super::MicrosoftOptions> {
        match &self.kind {
            ProviderKind::Microsoft { options, .. } => Some(options),
            _ => None,
        }
    }

    pub(super) fn cognito_options(&self) -> Option<&super::CognitoOptions> {
        match &self.kind {
            ProviderKind::Cognito(options) => Some(options),
            _ => None,
        }
    }

    pub(super) fn supports_refresh(&self) -> bool {
        !matches!(self.kind, ProviderKind::Vercel)
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
            .bearer_auth(access_token);
        let request = if self.is_tiktok() {
            request
        } else {
            request.header(
                "Accept",
                if self.is_twitter() || self.cognito_options().is_some() {
                    "*/*"
                } else {
                    "application/json"
                },
            )
        };
        if matches!(self.kind, ProviderKind::Linear) {
            request.json(&serde_json::json!({
                "query": "query { viewer { id name email avatarUrl active createdAt updatedAt } }"
            }))
        } else if self.is_reddit() {
            request.header("User-Agent", "better-auth")
        } else if matches!(self.kind, ProviderKind::Notion) {
            request.header("Notion-Version", "2022-06-28")
        } else {
            request
        }
    }

    pub(super) fn is_figma(&self) -> bool {
        matches!(self.kind, ProviderKind::Figma)
    }

    pub(super) fn is_atlassian(&self) -> bool {
        matches!(self.kind, ProviderKind::Atlassian)
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
            ProviderKind::Apple(_) => Some(
                "Client ID and client secret are required for Apple. Make sure to provide them in the options.",
            ),
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
            ProviderKind::Notion => &[("owner", "user")],
            _ => &[],
        }
    }

    pub(super) fn wechat_refresh_url(&self) -> Option<&str> {
        match &self.kind {
            ProviderKind::WeChat { refresh_url } => Some(refresh_url),
            _ => None,
        }
    }

    pub(super) fn is_tiktok(&self) -> bool {
        matches!(self.kind, ProviderKind::TikTok)
    }

    pub(super) fn is_twitter(&self) -> bool {
        matches!(self.kind, ProviderKind::Twitter)
    }

    pub(super) fn is_vk(&self) -> bool {
        matches!(self.kind, ProviderKind::Vk)
    }

    pub(super) fn is_discord(&self) -> bool {
        matches!(self.kind, ProviderKind::Discord)
    }

    pub(super) fn is_roblox(&self) -> bool {
        matches!(self.kind, ProviderKind::Roblox)
    }

    pub(super) fn omits_request_nonce(&self) -> bool {
        !matches!(self.kind, ProviderKind::Custom)
    }

    pub(super) fn is_reddit(&self) -> bool {
        matches!(self.kind, ProviderKind::Reddit)
    }

    pub(super) fn uses_pkce(&self) -> bool {
        !matches!(
            self.kind,
            ProviderKind::Facebook(_)
                | ProviderKind::Discord
                | ProviderKind::LinkedIn
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Linear
                | ProviderKind::Reddit
                | ProviderKind::Roblox
                | ProviderKind::TikTok
                | ProviderKind::Notion
                | ProviderKind::Twitch(_)
                | ProviderKind::Kakao
                | ProviderKind::Zoom { pkce: false }
                | ProviderKind::WeChat { .. }
        )
    }

    pub(super) fn forwards_code_verifier(&self) -> bool {
        matches!(self.kind, ProviderKind::Zoom { .. } | ProviderKind::TikTok) || self.uses_pkce()
    }

    pub(super) fn omits_login_hint(&self) -> bool {
        matches!(
            self.kind,
            ProviderKind::Apple(_)
                | ProviderKind::Cognito(_)
                | ProviderKind::Discord
                | ProviderKind::Spotify
                | ProviderKind::HuggingFace
                | ProviderKind::Polar
                | ProviderKind::Vercel
                | ProviderKind::Figma
                | ProviderKind::Dropbox
                | ProviderKind::Kick
                | ProviderKind::PayPal
                | ProviderKind::Cloudflare
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Atlassian
                | ProviderKind::Reddit
                | ProviderKind::Salesforce
                | ProviderKind::Railway
                | ProviderKind::Roblox
                | ProviderKind::TikTok
                | ProviderKind::Twitch(_)
                | ProviderKind::Kakao
                | ProviderKind::Zoom { .. }
                | ProviderKind::Twitter
                | ProviderKind::WeChat { .. }
                | ProviderKind::Vk
        )
    }

    pub(super) fn code_client_key(&self) -> Option<&str> {
        match self.kind {
            ProviderKind::Custom
            | ProviderKind::PayPal
            | ProviderKind::Reddit
            | ProviderKind::WeChat { .. }
            | ProviderKind::TikTok => None,
            _ => self.client_key.as_deref(),
        }
    }

    pub(super) fn omits_device_id(&self) -> bool {
        matches!(
            self.kind,
            ProviderKind::Microsoft { .. }
                | ProviderKind::Google { .. }
                | ProviderKind::Apple(_)
                | ProviderKind::Facebook(_)
                | ProviderKind::Discord
                | ProviderKind::Cognito(_)
                | ProviderKind::PayPal
                | ProviderKind::Cloudflare
                | ProviderKind::LinkedIn
                | ProviderKind::Line { .. }
                | ProviderKind::Paybin { .. }
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Linear
                | ProviderKind::Atlassian
                | ProviderKind::Reddit
                | ProviderKind::Salesforce
                | ProviderKind::Railway
                | ProviderKind::Roblox
                | ProviderKind::TikTok
                | ProviderKind::Notion
                | ProviderKind::Twitch(_)
                | ProviderKind::Kakao
                | ProviderKind::Zoom { .. }
                | ProviderKind::Twitter
                | ProviderKind::WeChat { .. }
        )
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
        } else if matches!(self.kind, ProviderKind::Notion) {
            Ok(response
                .pointer_mut("/bot/owner/user")
                .filter(|profile| crate::plugins::json_body::is_truthy(profile))
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
        match &self.kind {
            ProviderKind::Microsoft {
                token_endpoint_auth,
                ..
            } => token_endpoint_auth.as_ref(),
            ProviderKind::Cloudflare => self.token_endpoint_auth.as_ref(),
            _ => None,
        }
    }

    pub(super) fn token_authentication(
        &self,
        grant_type: TokenGrantType,
    ) -> Option<TokenEndpointSecretAuthentication> {
        (self.is_paypal()
            || self.is_figma()
            || self.is_reddit()
            || self.is_twitter()
            || matches!(self.kind, ProviderKind::Railway)
            || matches!(self.kind, ProviderKind::Notion)
                && grant_type == TokenGrantType::AuthorizationCode
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
            ProviderKind::Google { jwks_url, .. } => Some(jwks_url),
            _ => None,
        }
    }

    pub(in crate::plugins) fn google_client_ids(&self) -> Vec<String> {
        let additional = match &self.kind {
            ProviderKind::Google { options, .. } => options.additional_client_ids.as_slice(),
            _ => &[],
        };
        std::iter::once(self.client_id.clone())
            .chain(additional.iter().cloned())
            .collect()
    }

    pub(super) fn google_hosted_domain(&self) -> Option<&str> {
        self.authorization_params
            .iter()
            .find(|(name, _)| name == "hd")
            .map(|(_, value)| value.as_str())
    }

    #[cfg(test)]
    pub(super) fn set_google_jwks_url(&mut self, url: String) {
        let ProviderKind::Google { jwks_url, .. } = &mut self.kind else {
            panic!("Google fixture requires a Google provider");
        };
        *jwks_url = url;
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
            ProviderKind::Roblox => self
                .prompt
                .as_deref()
                .filter(|value| !value.is_empty())
                .or(Some("select_account consent")),
            ProviderKind::Custom
            | ProviderKind::Google { .. }
            | ProviderKind::GitHub { .. }
            | ProviderKind::Discord
            | ProviderKind::Polar
            | ProviderKind::PayPal
            | ProviderKind::Cognito(_)
            | ProviderKind::Microsoft { .. }
            | ProviderKind::Paybin { .. }
            | ProviderKind::Atlassian => self
                .prompt
                .as_deref()
                .filter(|value| !value.is_empty())
                .or_else(|| matches!(self.kind, ProviderKind::Discord).then_some("none")),
            ProviderKind::Apple(_)
            | ProviderKind::Facebook(_)
            | ProviderKind::GitLab
            | ProviderKind::Spotify
            | ProviderKind::HuggingFace
            | ProviderKind::Vercel
            | ProviderKind::Figma
            | ProviderKind::Dropbox
            | ProviderKind::Kick
            | ProviderKind::LinkedIn
            | ProviderKind::Line { .. }
            | ProviderKind::Slack
            | ProviderKind::Naver
            | ProviderKind::Linear
            | ProviderKind::Reddit
            | ProviderKind::Cloudflare
            | ProviderKind::Salesforce
            | ProviderKind::Railway
            | ProviderKind::Notion
            | ProviderKind::Twitch(_)
            | ProviderKind::Kakao
            | ProviderKind::Twitter
            | ProviderKind::WeChat { .. }
            | ProviderKind::Vk
            | ProviderKind::TikTok
            | ProviderKind::Zoom { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
