use async_trait::async_trait;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

mod defaults;
use super::OAuthProfileMapper;
use defaults::ProviderKind;
use std::sync::Arc;

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
    pub email: String,
    pub name: Option<String>,
    /// Omit the image with `None`, clear it with `Some(None)`, or supply a URL.
    pub image: Option<Option<String>>,
    pub email_verified: bool,
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

#[async_trait]
pub trait OAuthUserInfoHandler: Send + Sync {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String>;
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
    pub user_info_url: Option<String>,
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
    /// Provider authentication prompt; omission preserves the provider default.
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
            user_info_url: None,
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

    pub(super) fn resolve(&self) -> Self {
        let mut provider = self.clone();
        if provider.get_user_info.is_some() {
            // Upstream custom user-info handlers return before profile mapping.
            provider.map_profile_to_user = None;
        } else {
            self.kind.apply(&mut provider);
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
        let (first, second) = if matches!(self.kind, ProviderKind::Discord) {
            (request, configured)
        } else {
            (configured, request)
        };
        scopes.extend(first.iter().chain(second).map(String::as_str));
        scopes
    }

    pub(super) fn social_prompt(&self) -> Option<&str> {
        self.prompt
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| matches!(self.kind, ProviderKind::Discord).then_some("none"))
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
                        ("200 OK", emails.to_string())
                    } else if request.contains("/user") {
                        ("200 OK", profile.to_string())
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
        assert!(provider.get_user_info.is_some());
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
        let handler = provider.get_user_info.as_ref().unwrap();

        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(response.user.id, "42");
        assert_eq!(response.user.email, "octocat@example.com");
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
        let handler = provider.get_user_info.as_ref().unwrap();

        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(response.user.email, "public@example.com");
        assert_eq!(response.user.name.as_deref(), Some("Octo Cat"));
        assert!(!response.user.email_verified);
    }
}
