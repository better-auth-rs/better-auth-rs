use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, SchemaValue};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

mod defaults;
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
    pub email_verified: bool,
}

impl OAuthUserInfo {
    pub(super) fn email(&self) -> AuthResult<Option<&str>> {
        profile_email(&self.email)
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
        let method = match self.kind {
            ProviderKind::Dropbox | ProviderKind::Linear => reqwest::Method::POST,
            _ => reqwest::Method::GET,
        };
        let request = reqwest::Client::new()
            .request(method, url)
            .bearer_auth(access_token)
            .header("Accept", "application/json");
        if matches!(self.kind, ProviderKind::Linear) {
            request.json(&serde_json::json!({
                "query": "query { viewer { id name email avatarUrl active createdAt updatedAt } }"
            }))
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

    pub(super) fn uses_pkce(&self) -> bool {
        !matches!(
            self.kind,
            ProviderKind::LinkedIn
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Linear
        )
    }

    pub(super) fn omits_request_hints(&self) -> bool {
        matches!(
            self.kind,
            ProviderKind::Cloudflare | ProviderKind::Slack | ProviderKind::Naver
        )
    }

    pub(super) fn omits_device_id(&self) -> bool {
        matches!(
            self.kind,
            ProviderKind::Cloudflare
                | ProviderKind::LinkedIn
                | ProviderKind::Slack
                | ProviderKind::Naver
                | ProviderKind::Linear
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
        if matches!(self.kind, ProviderKind::Discord) {
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
        (self.is_figma()
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
            | ProviderKind::Polar => self
                .prompt
                .as_deref()
                .filter(|value| !value.is_empty())
                .or_else(|| matches!(self.kind, ProviderKind::Discord).then_some("none")),
            ProviderKind::GitLab
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
            | ProviderKind::Cloudflare => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Once};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    static LOCAL_PROXY_BYPASS: Once = Once::new();

    fn ensure_local_proxy_bypass() {
        LOCAL_PROXY_BYPASS.call_once(|| {
            // SAFETY: Test code in this module only needs localhost proxy bypass
            // values, and they are set once before issuing local HTTP requests.
            unsafe { std::env::set_var("NO_PROXY", "localhost,127.0.0.1") };
            // SAFETY: Test code in this module only needs localhost proxy bypass
            // values, and they are set once before issuing local HTTP requests.
            unsafe { std::env::set_var("no_proxy", "localhost,127.0.0.1") };
        });
    }

    async fn start_github_mock_server(
        profile: Value,
        emails: Value,
        statuses: (&'static str, &'static str),
    ) -> (String, String, Arc<Mutex<Vec<String>>>) {
        ensure_local_proxy_bypass();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = requests.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let profile = profile.clone();
                let emails = emails.clone();
                let requests = captured_requests.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                    requests.lock().await.push(request.clone());

                    let (status, body) = if request.contains("/user/emails") {
                        (statuses.1, emails.to_string())
                    } else if request.contains("/user") {
                        (statuses.0, profile.to_string())
                    } else {
                        (
                            "404 Not Found",
                            serde_json::json!({ "error": "not found" }).to_string(),
                        )
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );

                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });

        let base_url = format!("http://127.0.0.1:{}", addr.port());
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        (
            format!("{base_url}/user"),
            format!("{base_url}/user/emails"),
            requests,
        )
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().createAuthorizationURL default scope list.
    #[test]
    fn github_provider_uses_ts_default_scopes() {
        let provider = OAuthProvider::github("github-client-id", "github-client-secret").resolve();

        assert_eq!(
            provider.social_scopes(None),
            vec!["read:user", "user:email"]
        );
        assert!(provider.get_user_info.is_none());
        assert!(provider.map_user_info.is_none());
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo fallback from profile.email to /user/emails, login fallback for name, and request headers.
    #[tokio::test]
    async fn github_provider_get_user_info_uses_email_fallback_and_login_name() {
        let (user_url, emails_url, requests) = start_github_mock_server(
            serde_json::json!({
                "id": 42,
                "login": "octocat",
                "name": null,
                "email": null,
                "avatar_url": "https://avatars.githubusercontent.com/u/42?v=4",
            }),
            serde_json::json!([
                {
                    "email": "octocat@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                },
                {
                    "email": "secondary@example.com",
                    "primary": false,
                    "verified": false,
                    "visibility": "private"
                }
            ]),
            ("200 OK", "200 OK"),
        )
        .await;

        let provider = OAuthProvider::github_with_endpoints(
            "github-client-id",
            "github-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        )
        .resolve();
        let (user_url, emails_url) = provider.github_endpoints().unwrap();
        let response = github_profile(
            user_url,
            emails_url,
            &OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response.user.id, "42");
        assert_eq!(
            response.user.email.typed().unwrap().as_deref(),
            Some("octocat@example.com")
        );
        assert_eq!(response.user.name.as_deref(), Some("octocat"));
        assert_eq!(
            response.user.image.as_ref().and_then(Option::as_deref),
            Some("https://avatars.githubusercontent.com/u/42?v=4")
        );
        assert!(response.user.email_verified);
        assert_eq!(
            response.data["email"],
            serde_json::json!("octocat@example.com")
        );

        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            let lowered = request.to_ascii_lowercase();
            assert!(lowered.contains("authorization: bearer github-access-token"));
            assert!(lowered.contains("user-agent: better-auth"));
        }
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo keeps profile.email when present and resolves verified status from the matching email record.
    #[tokio::test]
    async fn github_provider_get_user_info_keeps_inline_email() {
        let (user_url, emails_url, _) = start_github_mock_server(
            serde_json::json!({
                "id": "github-inline-email",
                "login": "octocat",
                "name": "Octo Cat",
                "email": "public@example.com",
                "avatar_url": null,
            }),
            serde_json::json!([
                {
                    "email": "primary@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                },
                {
                    "email": "public@example.com",
                    "primary": false,
                    "verified": false,
                    "visibility": "public"
                }
            ]),
            ("200 OK", "200 OK"),
        )
        .await;

        let provider = OAuthProvider::github_with_endpoints(
            "github-client-id",
            "github-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        )
        .resolve();
        let (user_url, emails_url) = provider.github_endpoints().unwrap();
        let response = github_profile(
            user_url,
            emails_url,
            &OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            response.user.email.typed().unwrap().as_deref(),
            Some("public@example.com")
        );
        assert_eq!(response.user.name.as_deref(), Some("Octo Cat"));
        assert!(!response.user.email_verified);
    }
    #[tokio::test]
    async fn github_http_errors_distinguish_missing_profile_from_optional_email_data() {
        for primary_failure in [false, true] {
            let (user_url, emails_url, requests) = start_github_mock_server(
                serde_json::json!({"id":42,"login":"octocat","email":"public@example.test"}),
                serde_json::json!({"error":"temporarily_unavailable"}),
                if primary_failure {
                    ("503 Service Unavailable", "200 OK")
                } else {
                    ("200 OK", "503 Service Unavailable")
                },
            )
            .await;
            let response = github_profile(
                &user_url,
                &emails_url,
                &OAuthUserInfoRequest {
                    access_token: Some("ordinary-access-token".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            if primary_failure {
                assert!(response.is_none());
                assert_eq!(requests.lock().await.len(), 1);
            } else {
                let response = response.unwrap();
                assert_eq!(
                    response.user.email.typed().unwrap().as_deref(),
                    Some("public@example.test")
                );
                assert!(!response.user.email_verified);
                assert_eq!(requests.lock().await.len(), 2);
            }
        }
    }

    struct GitHubEmailMapper {
        expected: Value,
        requests: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl OAuthProfileMapper for GitHubEmailMapper {
        async fn map_profile(
            &self,
            profile: &Value,
        ) -> AuthResult<crate::plugins::oauth::OAuthProfile> {
            assert_eq!(profile, &self.expected);
            self.requests.lock().await.push("mapper".into());
            Ok(Default::default())
        }
    }

    #[tokio::test]
    async fn github_email_presence_and_fallback_match_pinned_normal_json() {
        use serde_json::json;

        let primary = json!([
            {"email":"secondary@example.test","primary":false,"verified":false},
            {"email":"primary@example.test","primary":true,"verified":true}
        ]);
        let cases = [
            (
                "omitted with empty list",
                None,
                "200 OK",
                json!([]),
                None,
                false,
            ),
            (
                "null with empty list",
                Some(Value::Null),
                "200 OK",
                json!([]),
                None,
                false,
            ),
            (
                "empty with empty list",
                Some(json!("")),
                "200 OK",
                json!([]),
                None,
                false,
            ),
            (
                "omitted with unavailable list",
                None,
                "503 Service Unavailable",
                json!({}),
                None,
                false,
            ),
            (
                "null with unavailable list",
                Some(Value::Null),
                "503 Service Unavailable",
                json!({}),
                Some(Value::Null),
                false,
            ),
            (
                "empty with unavailable list",
                Some(json!("")),
                "503 Service Unavailable",
                json!({}),
                Some(json!("")),
                false,
            ),
            (
                "null selects primary",
                Some(Value::Null),
                "200 OK",
                primary.clone(),
                Some(json!("primary@example.test")),
                true,
            ),
            (
                "empty selects primary",
                Some(json!("")),
                "200 OK",
                primary,
                Some(json!("primary@example.test")),
                true,
            ),
            (
                "nonempty with empty list",
                Some(json!("public@example.test")),
                "200 OK",
                json!([]),
                Some(json!("public@example.test")),
                false,
            ),
            (
                "no primary selects first",
                Some(Value::Null),
                "200 OK",
                json!([
                    {"email":"first@example.test","primary":false,"verified":true},
                    {"email":"second@example.test","primary":false,"verified":false}
                ]),
                Some(json!("first@example.test")),
                true,
            ),
            (
                "selected empty email is retained",
                Some(Value::Null),
                "200 OK",
                json!([
                    {"email":"secondary@example.test","primary":false,"verified":false},
                    {"email":"","primary":true,"verified":true}
                ]),
                Some(json!("")),
                true,
            ),
        ];
        for (label, email, status, emails, expected_email, verified) in cases {
            let base = json!({
                "id":42, "login":"octocat", "name":"Octo Cat",
                "avatar_url":"https://images.example.test/octocat.png"
            });
            let mut profile = base.clone();
            if let Some(email) = email {
                profile["email"] = email;
            }
            let mut expected_data = base;
            if let Some(email) = &expected_email {
                expected_data["email"] = email.clone();
            }
            let (user_url, emails_url, requests) =
                start_github_mock_server(profile, emails, ("200 OK", status)).await;
            let mut config = OAuthProvider::github_with_endpoints(
                "ordinary-client",
                "ordinary-client-secret",
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                &user_url,
                &emails_url,
            );
            config.map_profile_to_user = Some(Arc::new(GitHubEmailMapper {
                expected: expected_data.clone(),
                requests: requests.clone(),
            }));
            let provider = crate::plugins::oauth::resolved::ResolvedProvider {
                config,
                generic: None,
            };
            let response = crate::plugins::oauth::social_profile::fetch_user_info_for_code(
                &provider,
                OAuthUserInfoRequest {
                    access_token: Some("ordinary-github-token".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                response.user.email.is_undefined(),
                expected_email.is_none(),
                "{label}"
            );
            let user = crate::plugins::oauth::types::AccountInfoUser {
                id: None,
                name: response.user.name,
                email: response.user.email,
                image: response.user.image,
                email_verified: response.user.email_verified,
                additional_fields: response.user.additional_fields,
            };
            let mut expected_user = json!({
                "name":"Octo Cat", "image":"https://images.example.test/octocat.png",
                "emailVerified":verified
            });
            if let Some(email) = expected_email {
                expected_user["email"] = email;
            }
            // serde_json::Value represents upstream own undefined email by omitting the JSON key.
            assert_eq!(
                json!({"user":user,"data":response.data}),
                json!({"user":expected_user,"data":expected_data}),
                "{label}"
            );
            let requests = requests.lock().await;
            assert_eq!(requests.len(), 3, "{label}");
            assert!(requests[0].starts_with("GET /user HTTP/1.1\r\n"), "{label}");
            assert!(
                requests[1].starts_with("GET /user/emails HTTP/1.1\r\n"),
                "{label}"
            );
            assert_eq!(requests[2], "mapper", "{label}");
        }
    }

    #[tokio::test]
    async fn github_rejects_nonstring_profile_email_before_using_fallback_values() {
        let (user_url, emails_url, _) = start_github_mock_server(
            serde_json::json!({
                "id":42, "login":"octocat", "name":"Octo Cat", "email":123,
                "avatar_url":"https://images.example.test/octocat.png"
            }),
            serde_json::json!([{"email":"primary@example.test","primary":true,"verified":true}]),
            ("200 OK", "200 OK"),
        )
        .await;
        let error = github_profile(
            &user_url,
            &emails_url,
            &OAuthUserInfoRequest {
                access_token: Some("ordinary-github-token".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message.starts_with("Invalid provider email:"))
        );
    }
}
