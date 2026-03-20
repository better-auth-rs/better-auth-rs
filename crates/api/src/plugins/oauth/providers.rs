use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for the OAuth plugin, containing all registered providers.
#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProvider>,
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
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthCallbackUserPayload {
    pub name: Option<OAuthCallbackUserName>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Deserialize)]
struct GitHubEmailAddress {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Clone)]
struct GitHubUserInfoHandler {
    user_url: String,
    emails_url: String,
}

impl GitHubUserInfoHandler {
    fn new(user_url: String, emails_url: String) -> Self {
        Self {
            user_url,
            emails_url,
        }
    }

    async fn fetch_json<T: DeserializeOwned>(
        &self,
        client: &reqwest::Client,
        url: &str,
        access_token: &str,
    ) -> Result<T, String> {
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .header("User-Agent", "better-auth")
            .send()
            .await
            .map_err(|error| format!("Failed to fetch GitHub user info: {error}"))?;

        if !response.status().is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("GitHub user info request failed: {body}"));
        }

        response
            .json()
            .await
            .map_err(|error| format!("Failed to parse GitHub user info: {error}"))
    }
}

#[async_trait]
impl OAuthUserInfoHandler for GitHubUserInfoHandler {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .as_deref()
            .ok_or("Missing access token for user-info lookup")?;

        let client = reqwest::Client::new();
        let mut profile: Value = self
            .fetch_json(&client, &self.user_url, access_token)
            .await?;
        let emails = self
            .fetch_json::<Vec<GitHubEmailAddress>>(&client, &self.emails_url, access_token)
            .await
            .unwrap_or_default();

        let resolved_email = profile
            .get("email")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| {
                emails
                    .iter()
                    .find(|record| record.primary)
                    .or_else(|| emails.first())
                    .map(|record| record.email.clone())
            })
            .unwrap_or_default();

        if let Some(profile_object) = profile.as_object_mut()
            && profile_object
                .get("email")
                .and_then(Value::as_str)
                .is_none()
            && !resolved_email.is_empty()
        {
            let _ =
                profile_object.insert("email".to_string(), Value::String(resolved_email.clone()));
        }

        let email_verified = emails
            .iter()
            .find(|record| record.email == resolved_email)
            .map(|record| record.verified)
            .unwrap_or(false);

        let id = profile
            .get("id")
            .and_then(|value| value.as_i64().map(|value| value.to_string()))
            .or_else(|| profile.get("id").and_then(Value::as_str).map(String::from))
            .ok_or("missing id")?;

        let login = profile
            .get("login")
            .and_then(Value::as_str)
            .map(String::from);

        Ok(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id,
                email: resolved_email,
                name: profile
                    .get("name")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or(login),
                image: profile
                    .get("avatar_url")
                    .and_then(Value::as_str)
                    .map(String::from),
                email_verified,
            },
            data: profile,
        })
    }
}

/// Configuration for a single OAuth provider.
#[derive(Clone)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: Option<String>,
    pub scopes: Vec<String>,
    pub authorization_params: Vec<(String, String)>,
    pub map_user_info: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    pub get_user_info: Option<Arc<dyn OAuthUserInfoHandler>>,
    pub refresh_access_token: Option<Arc<dyn OAuthRefreshTokenHandler>>,
    pub verify_id_token: Option<Arc<dyn OAuthIdTokenVerifier>>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub override_user_info_on_sign_in: bool,
}

impl OAuthProvider {
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_string()),
            scopes: vec![
                "email".to_string(),
                "profile".to_string(),
                "openid".to_string(),
            ],
            authorization_params: vec![("include_granted_scopes".to_string(), "true".to_string())],
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    id: v
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .ok_or("missing sub")?
                        .to_string(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .ok_or("missing email")?
                        .to_string(),
                    name: v.get("name").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("picture").and_then(|v| v.as_str()).map(String::from),
                    email_verified: v
                        .get("email_verified")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

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

    /// Construct a GitHub provider using custom endpoints.
    ///
    /// This keeps the built-in GitHub semantics while allowing local test
    /// harnesses or GitHub Enterprise-style deployments to override the URLs.
    pub fn github_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        user_info_url: &str,
        user_emails_url: &str,
    ) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: auth_url.to_string(),
            token_url: token_url.to_string(),
            user_info_url: Some(user_info_url.to_string()),
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
            authorization_params: Vec::new(),
            map_user_info: None,
            get_user_info: Some(Arc::new(GitHubUserInfoHandler::new(
                user_info_url.to_string(),
                user_emails_url.to_string(),
            ))),
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://discord.com/api/oauth2/authorize".to_string(),
            token_url: "https://discord.com/api/oauth2/token".to_string(),
            user_info_url: Some("https://discord.com/api/users/@me".to_string()),
            scopes: vec!["identify".to_string(), "email".to_string()],
            authorization_params: Vec::new(),
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    id: v
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or("missing id")?
                        .to_string(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .ok_or("missing email")?
                        .to_string(),
                    name: v.get("username").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("avatar").and_then(|v| v.as_str()).map(|a| {
                        format!(
                            "https://cdn.discordapp.com/avatars/{}/{}.png",
                            v.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            a
                        )
                    }),
                    email_verified: v.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
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
        let provider = OAuthProvider::github("github-client-id", "github-client-secret");

        assert_eq!(
            provider.scopes,
            vec!["read:user".to_string(), "user:email".to_string()]
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
        );
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
            response.user.image.as_deref(),
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
        );
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
