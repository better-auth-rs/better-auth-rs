#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Contract tests fail immediately on invalid fixture data or a changed provider result."
)]

use super::*;
use serde_json::{Map, Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/social-http-providers-1.7.6.json"
    ))
    .unwrap()
}

fn provider(id: &str) -> OAuthProvider {
    match id {
        "gitlab" => OAuthProvider::gitlab("social-http-client", "secret"),
        "spotify" => OAuthProvider::spotify("social-http-client", "secret"),
        "huggingface" => OAuthProvider::huggingface("social-http-client", "secret"),
        "google" => OAuthProvider::google("social-http-client", "secret"),
        "github" => OAuthProvider::github("social-http-client", "secret"),
        "discord" => OAuthProvider::discord("social-http-client", "secret"),
        _ => {
            assert_eq!(id, "polar");
            OAuthProvider::polar("social-http-client", "secret")
        }
    }
}

async fn resolve(id: &str, config: OAuthProvider) -> resolved::ResolvedOAuthConfig {
    resolved::ResolvedOAuthConfig::new(
        &OAuthConfig {
            providers: [(id.to_owned(), config)].into_iter().collect(),
        },
        &HashMap::new(),
        None,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn authorization_preserves_provider_defaults_append_order_and_pkce() {
    let fixture = fixture();
    for id in ["gitlab", "spotify", "huggingface", "polar"] {
        let expected = &fixture["providers"][id];
        for case in expected["scopeCases"].as_array().unwrap() {
            let mut config = provider(id);
            assert_eq!(config.auth_url, expected["authorizationEndpoint"]);
            assert_eq!(config.token_url, expected["tokenEndpoint"]);
            assert_eq!(json!(config.user_info_url), expected["userinfoEndpoint"]);
            config.scopes = serde_json::from_value(case["options"]["scope"].clone()).unwrap();
            config.prompt = serde_json::from_value(case["options"]["prompt"].clone()).unwrap();
            config.disable_default_scope = case["options"]["disableDefaultScope"]
                .as_bool()
                .unwrap_or(false);
            let request_scopes: Option<Vec<String>> =
                serde_json::from_value(case["requestScopes"].clone()).unwrap();
            let resolved = resolve(id, config).await;
            let url = authorization::build_authorization_url(
                &resolved.providers[id],
                authorization::AuthorizationRequest {
                    callback_url: "https://app.example.test/api/auth/callback/provider",
                    scopes: request_scopes.as_deref(),
                    state: fixture["state"].as_str().unwrap(),
                    code_challenge: fixture["codeChallenge"].as_str().unwrap(),
                    login_hint: None,
                    nonce: None,
                    additional_params: None,
                },
            )
            .unwrap();
            let query: HashMap<_, _> = url::Url::parse(&url)
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect();
            assert_eq!(json!(query.get("scope")), case["scope"]);
            assert_eq!(json!(query.get("prompt")), case["options"]["prompt"]);
            assert_eq!(query["code_challenge_method"], "S256");
            assert_eq!(query["code_challenge"], fixture["codeChallenge"]);
            assert_eq!(query["state"], fixture["state"]);
        }
    }
}

#[tokio::test]
async fn configured_prompt_is_forwarded_only_by_providers_that_support_it() {
    let fixture = fixture();
    for case in fixture["promptCases"].as_array().unwrap() {
        let id = case["provider"].as_str().unwrap();
        let mut config = provider(id);
        config.prompt = Some(case["configured"].as_str().unwrap().into());
        let resolved = resolve(id, config).await;
        let url = authorization::build_authorization_url(
            &resolved.providers[id],
            authorization::AuthorizationRequest {
                callback_url: "https://app.example.test/api/auth/callback/provider",
                scopes: None,
                state: fixture["state"].as_str().unwrap(),
                code_challenge: fixture["codeChallenge"].as_str().unwrap(),
                login_hint: None,
                nonce: None,
                additional_params: None,
            },
        )
        .unwrap();
        let query: HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(json!(query.get("prompt")), case["expected"], "{id}");
    }
    let mut custom = OAuthProvider::custom(
        "client",
        "secret",
        "https://example.test/auth",
        "https://example.test/token",
    );
    custom.prompt = Some("consent".into());
    assert_eq!(custom.social_prompt(), Some("consent"));
    assert_eq!(provider("discord").social_prompt(), Some("none"));
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
    async fn start(profile: Value, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let count = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..count]).to_ascii_lowercase();
            assert!(request.starts_with("get /profile http/1.1"));
            assert!(request.contains("authorization: bearer ordinary-access"));
            events.lock().unwrap().push("http");
            let body = profile.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        Self { url, task }
    }
}

struct Mapper {
    raw: Value,
    patch: Value,
    events: Arc<Mutex<Vec<&'static str>>>,
    started: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(raw, &self.raw);
        self.events.lock().unwrap().push("map:start");
        self.started.notify_one();
        self.resume.notified().await;
        let patch = &self.patch;
        self.events.lock().unwrap().push("map:end");
        Ok(OAuthProfile {
            name: Some(serde_json::from_value(patch["name"].clone())?),
            image: Some(serde_json::from_value(patch["image"].clone())?),
            email_verified: patch["emailVerified"].as_bool(),
            additional_fields: [("locale".into(), patch["locale"].clone())]
                .into_iter()
                .collect(),
            ..Default::default()
        })
    }
}

struct CustomProfile(Value, String, Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl OAuthUserInfoHandler for CustomProfile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        self.2.lock().unwrap().push("custom");
        Ok(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: self.1.clone(),
                email: self.0["email"].as_str().unwrap().into(),
                name: serde_json::from_value(self.0["name"].clone()).unwrap(),
                image: Some(serde_json::from_value(self.0["image"].clone()).unwrap()),
                email_verified: self.0["emailVerified"].as_bool().unwrap(),
                additional_fields: Map::new(),
            },
            data: json!({"id":self.1}),
        })
    }
}

fn public_user(user: OAuthUserInfo) -> Value {
    let mut output = user.additional_fields;
    let _ = output.insert("name".into(), json!(user.name));
    let _ = output.insert("email".into(), json!(user.email));
    let _ = output.insert("emailVerified".into(), json!(user.email_verified));
    if let Some(image) = user.image {
        let _ = output.insert("image".into(), json!(image));
    }
    Value::Object(output)
}

#[tokio::test]
async fn normal_profiles_and_mapper_precedence_match_pinned_provider_results() {
    let fixture = fixture();
    for id in ["gitlab", "spotify", "huggingface", "polar"] {
        let case = &fixture["providers"][id];
        let subject = match &case["profile"][case["subjectField"].as_str().unwrap()] {
            Value::String(id) => id.clone(),
            id => id.to_string(),
        };
        for mode in ["default", "mapped", "custom"] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let started = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let server = ProfileServer::start(case["profile"].clone(), events.clone()).await;
            let mut config = provider(id);
            config.user_info_url = Some(format!("{}/profile", server.url));
            if mode != "default" {
                config.map_profile_to_user = Some(Arc::new(Mapper {
                    raw: case["profile"].clone(),
                    patch: case["mapperPatch"].clone(),
                    events: events.clone(),
                    started: started.clone(),
                    resume: resume.clone(),
                }));
            }
            if mode == "custom" {
                config.get_user_info = Some(Arc::new(CustomProfile(
                    case["customUser"].clone(),
                    subject.clone(),
                    events.clone(),
                )));
            }
            let resolved = resolve(id, config).await;
            let response = tokio::spawn(async move {
                social_profile::fetch_user_info_for_code(
                    &resolved.providers[id],
                    OAuthUserInfoRequest {
                        access_token: Some("ordinary-access".into()),
                        ..Default::default()
                    },
                    None,
                )
                .await
            });
            if mode == "mapped" {
                tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
                    .await
                    .unwrap();
                assert_eq!(*events.lock().unwrap(), ["http", "map:start"]);
                assert!(!response.is_finished());
                resume.notify_one();
            }
            let response = response.await.unwrap().unwrap();
            events.lock().unwrap().push("returned");
            assert_eq!(response.user.id, subject);
            assert_eq!(public_user(response.user), case[format!("{mode}User")]);
            assert_eq!(
                *events.lock().unwrap(),
                match mode {
                    "default" => vec!["http", "returned"],
                    "mapped" => vec!["http", "map:start", "map:end", "returned"],
                    _ => vec!["custom", "returned"],
                }
            );
        }
        let resolved = resolve(id, provider(id)).await;
        let decode = resolved.providers[id].config.map_user_info.unwrap();
        for variant in case["normalProfileCases"].as_array().unwrap() {
            assert_eq!(
                public_user(decode(variant["profile"].clone()).unwrap()),
                variant["user"]
            );
        }
    }
    let case = &fixture["providers"]["gitlab"];
    for rejected in case["rejectedStates"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut profile = case["profile"].as_object().unwrap().clone();
        profile.extend(rejected["patch"].as_object().unwrap().clone());
        let server = ProfileServer::start(profile.into(), events.clone()).await;
        let mut config = provider("gitlab");
        config.user_info_url = Some(format!("{}/profile", server.url));
        config.map_profile_to_user = Some(Arc::new(Mapper {
            raw: case["profile"].clone(),
            patch: case["mapperPatch"].clone(),
            events: events.clone(),
            started: Default::default(),
            resume: Default::default(),
        }));
        let resolved = resolve("gitlab", config).await;
        let result = social_profile::fetch_user_info_for_code(
            &resolved.providers["gitlab"],
            OAuthUserInfoRequest {
                access_token: Some("ordinary-access".into()),
                ..Default::default()
            },
            None,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*events.lock().unwrap(), ["http"]);
    }
}
