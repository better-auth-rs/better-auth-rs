#![expect(
    clippy::panic_in_result_fn,
    reason = "contract tests propagate setup failures and assert upstream results"
)]

use super::google_test_support::GoogleFixture;
use super::*;
use better_auth_core::AuthError;
use serde_json::{Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> AuthResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/social-provider-options-1.7.6.json"
    ))?)
}

async fn google_fixture() -> GoogleFixture {
    GoogleFixture::start(json!({"sub":"google-subject","email":"owner@example.test","name":"Owner","picture":"https://images.test/owner.png","email_verified":true})).await
}

fn provider(id: &str) -> AuthResult<OAuthProvider> {
    match id {
        "google" => Ok(OAuthProvider::google("client", "secret")),
        "github" => Ok(OAuthProvider::github("client", "secret")),
        "discord" => Ok(OAuthProvider::discord("client", "secret")),
        _ => Err(AuthError::internal("unknown fixture provider")),
    }
}

async fn resolve(id: &str, provider: OAuthProvider) -> AuthResult<resolved::ResolvedOAuthConfig> {
    resolved::ResolvedOAuthConfig::new(
        &OAuthConfig {
            providers: [(id.to_owned(), provider)].into_iter().collect(),
        },
        &HashMap::new(),
        None,
    )
    .await
}

#[tokio::test]
async fn social_authorization_scope_and_prompt_match_upstream() -> AuthResult<()> {
    let fixture = fixture()?;
    for id in ["google", "github", "discord"] {
        for name in ["defaults", "empty", "merged", "noDefaults", "noScopes"] {
            let mut provider = provider(id)?;
            let request = match name {
                "empty" | "noScopes" => {
                    provider.scopes = Some(vec![]);
                    Some(vec![])
                }
                "merged" => {
                    provider.scopes = Some(vec!["configured".into(), "shared".into()]);
                    provider.prompt = Some("consent".into());
                    Some(vec!["request".into(), "shared".into()])
                }
                "noDefaults" => {
                    provider.scopes = Some(vec!["configured".into()]);
                    Some(vec!["request".into()])
                }
                _ => None,
            };
            provider.disable_default_scope = name == "noDefaults" || name == "noScopes";
            let config = resolve(id, provider).await?;
            let provider = config
                .providers
                .get(id)
                .ok_or_else(|| AuthError::internal("missing resolved provider"))?;
            let url = authorization::build_authorization_url(
                provider,
                authorization::AuthorizationRequest {
                    callback_url: "https://example.test/api/auth/callback/provider",
                    scopes: request.as_deref(),
                    state: "state",
                    code_challenge: "challenge",
                    login_hint: None,
                    nonce: None,
                    additional_params: None,
                },
            )?;
            let params: HashMap<_, _> = url::Url::parse(&url)
                .map_err(|error| AuthError::internal(error.to_string()))?
                .query_pairs()
                .into_owned()
                .collect();
            let actual = json!({"scope":params.get("scope"), "prompt":params.get("prompt")});
            assert_eq!(
                Some(&actual),
                fixture
                    .get("authorization")
                    .and_then(|cases| cases.get(format!("{id}-{name}"))),
                "{id}-{name}"
            );
        }
    }
    Ok(())
}

struct ProfileServer {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ProfileServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ProfileServer {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept local profile request");
                let mut bytes = [0; 4096];
                let count = stream
                    .read(&mut bytes)
                    .await
                    .expect("read local profile request");
                let request = String::from_utf8_lossy(&bytes[..count]);
                let path = request.split_whitespace().nth(1).expect("request path");
                let body = match path {
                    "/google" => json!({"sub":"google-subject","email":"owner@example.test","name":"Owner","picture":"https://images.test/owner.png","email_verified":true}),
                    "/github" => json!({"id":123,"email":"owner@example.test","name":"Owner","login":"owner","avatar_url":"https://images.test/owner.png"}),
                    "/github/emails" => json!([{"email":"owner@example.test","primary":true,"verified":true}]),
                    "/discord" => json!({"id":"123456789","email":"owner@example.test","username":"Owner","avatar":"portrait","verified":true}),
                    _ => panic!("unexpected local profile path: {path}"),
                }.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write local profile response");
            }
        });
        Ok(Self { url, task })
    }
}

struct Mapper {
    partial: bool,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        self.calls
            .lock()
            .map_err(|_| AuthError::internal("callback log poisoned"))?
            .push("map");
        assert_eq!(raw.get("email"), Some(&json!("owner@example.test")));
        let mut mapped = OAuthProfile {
            additional_fields: [("locale".into(), json!("zh-TW"))].into_iter().collect(),
            ..Default::default()
        };
        if !self.partial {
            mapped.name = Some(Some("Mapped".into()));
            mapped.image = Some(None);
            mapped.email = Some(Some("mapped@example.test".into()).into());
            mapped.email_verified = Some(Some(false).into());
        }
        Ok(mapped)
    }
}
struct CustomProfile(Arc<Mutex<Vec<&'static str>>>);
#[async_trait]
impl OAuthUserInfoHandler for CustomProfile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0
            .lock()
            .map_err(|_| better_auth_core::AuthError::internal("callback log poisoned"))?
            .push("get");
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "custom-subject".into(),
                email: Some("custom@example.test".into()).into(),
                name: Some("Custom".into()),
                image: Some(Some("https://images.test/custom.png".into())),
                email_verified: Some(true).into(),
                additional_fields: [("locale".into(), json!("en"))].into_iter().collect(),
            },
            data: json!({"id":"custom-subject"}),
        }))
    }
}

#[tokio::test]
async fn social_profile_mapping_matches_upstream_and_keeps_subject()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let server = ProfileServer::start().await?;
    let google = google_fixture().await;
    for (id, subject) in [
        ("google", "google-subject"),
        ("github", "123"),
        ("discord", "123456789"),
    ] {
        for mode in ["mapped", "partial", "custom"] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let mut provider = if id == "github" {
                OAuthProvider::github_with_endpoints(
                    "client",
                    "secret",
                    "https://provider.test/authorize",
                    "https://provider.test/token",
                    &format!("{}/github", server.url),
                    &format!("{}/github/emails", server.url),
                )
            } else {
                provider(id)?
            };
            provider.user_info_url = Some(format!("{}/{id}", server.url));
            if id == "google" {
                google.configure(&mut provider);
            }
            provider.map_profile_to_user = Some(Arc::new(Mapper {
                partial: mode == "partial",
                calls: calls.clone(),
            }));
            if mode == "custom" {
                provider.get_user_info = Some(Arc::new(CustomProfile(calls.clone())));
            }
            let config = resolve(id, provider).await?;
            assert!(
                calls
                    .lock()
                    .map_err(|_| "callback log poisoned")?
                    .is_empty()
            );
            let response = handlers::fetch_user_info_for_code(
                config.providers.get(id).ok_or("missing provider")?,
                OAuthUserInfoRequest {
                    access_token: Some("normal-profile-token".into()),
                    id_token: (id == "google").then(|| google.token.clone()),
                    ..Default::default()
                },
                None,
            )
            .await?
            .ok_or("provider returned no profile")?;
            assert_eq!(
                response.user.id,
                if mode == "custom" {
                    "custom-subject"
                } else {
                    subject
                }
            );
            let mut user = response.user.additional_fields;
            user.extend(serde_json::from_value::<serde_json::Map<String, Value>>(json!({"name":response.user.name,"image":response.user.image,"email":response.user.email,"emailVerified":response.user.email_verified}))?);
            let actual =
                json!({"user":user,"calls":*calls.lock().map_err(|_| "callback log poisoned")?});
            assert_eq!(
                Some(&actual),
                fixture
                    .get("profiles")
                    .and_then(|cases| cases.get(format!("{id}-{mode}"))),
                "{id}-{mode}"
            );
        }
    }
    Ok(())
}

struct FailingCallbacks(Arc<Mutex<Vec<&'static str>>>);

#[tokio::test]
async fn google_stored_account_profile_keeps_access_token_userinfo()
-> Result<(), Box<dyn std::error::Error>> {
    let server = ProfileServer::start().await?;
    let mut provider = provider("google")?;
    provider.user_info_url = Some(format!("{}/google", server.url));
    let config = resolve("google", provider).await?;
    let response = handlers::fetch_user_info_from_provider(
        config.providers.get("google").ok_or("missing provider")?,
        OAuthUserInfoRequest {
            access_token: Some("normal-account-info-token".into()),
            ..Default::default()
        },
        None,
    )
    .await?
    .ok_or("provider returned no profile")?;
    assert_eq!(response.user.name.as_deref(), Some("Owner"));
    assert_eq!(
        response.user.email.typed()?.as_deref(),
        Some("owner@example.test")
    );
    assert_eq!(response.user.id, "google-subject");
    Ok(())
}

#[async_trait]
impl OAuthProfileMapper for FailingCallbacks {
    async fn map_profile(&self, _: &Value) -> AuthResult<OAuthProfile> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("callback log poisoned"))?
            .push("map");
        Err(AuthError::config("profile mapper failed"))
    }
}
#[async_trait]
impl OAuthUserInfoHandler for FailingCallbacks {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0
            .lock()
            .map_err(|_| better_auth_core::AuthError::internal("callback log poisoned"))?
            .push("get");
        Err(better_auth_core::AuthError::internal(
            "custom user info failed",
        ))
    }
}
#[tokio::test]
async fn social_profile_callback_errors_propagate_without_running_later_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let server = ProfileServer::start().await?;
    let google = google_fixture().await;
    for mode in ["mapper", "custom"] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callbacks = Arc::new(FailingCallbacks(calls.clone()));
        let mut provider = provider("google")?;
        provider.user_info_url = Some(format!("{}/google", server.url));
        google.configure(&mut provider);
        provider.map_profile_to_user = Some(callbacks.clone());
        if mode == "custom" {
            provider.get_user_info = Some(callbacks);
        }
        let config = resolve("google", provider).await?;
        let error = handlers::fetch_user_info_for_code(
            config.providers.get("google").ok_or("missing provider")?,
            OAuthUserInfoRequest {
                access_token: Some("normal-profile-token".into()),
                id_token: Some(google.token.clone()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("callback must fail");
        assert!(if mode == "mapper" {
            matches!(error, AuthError::Config(_))
        } else {
            matches!(error, AuthError::Internal(_))
        });
        let actual = json!({"message":error.instrumentation_message(),"calls":*calls.lock().map_err(|_| "callback log poisoned")?});
        assert_eq!(
            Some(&actual),
            fixture.get("errors").and_then(|cases| cases.get(mode))
        );
    }
    Ok(())
}
