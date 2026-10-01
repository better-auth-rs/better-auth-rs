#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Contract tests fail immediately on invalid fixture data or a changed provider result."
)]

use super::*;
use better_auth_core::AuthError;
use serde_json::{Map, Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

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
        "vercel" => OAuthProvider::vercel("social-http-client", "secret"),
        "google" => OAuthProvider::google("social-http-client", "secret"),
        "github" => OAuthProvider::github("social-http-client", "secret"),
        "discord" => OAuthProvider::discord("social-http-client", "secret"),
        "figma" => OAuthProvider::figma("social-http-client", "secret"),
        "dropbox" => OAuthProvider::dropbox("social-http-client", "secret"),
        "kick" => OAuthProvider::kick("social-http-client", "secret"),
        "linkedin" => OAuthProvider::linkedin("social-http-client", "secret"),
        "slack" => OAuthProvider::slack("social-http-client", "secret"),
        "naver" => OAuthProvider::naver("social-http-client", "secret"),
        "linear" => OAuthProvider::linear("social-http-client", "secret"),
        "cloudflare" => OAuthProvider::cloudflare("social-http-client", "secret"),
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
    for id in [
        "gitlab",
        "spotify",
        "huggingface",
        "polar",
        "vercel",
        "figma",
        "dropbox",
        "kick",
        "linkedin",
        "slack",
        "naver",
        "linear",
        "cloudflare",
    ] {
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
            if let Some(access_type) = case["options"]["accessType"].as_str() {
                config
                    .authorization_params
                    .push(("token_access_type".into(), access_type.into()));
            }
            let additional_params: Option<indexmap::IndexMap<String, String>> =
                serde_json::from_value(case["additionalParams"].clone()).unwrap();
            let resolved = resolve(id, config).await;
            let url = authorization::build_authorization_url(
                &resolved.providers[id],
                authorization::AuthorizationRequest {
                    callback_url: "https://app.example.test/api/auth/callback/provider",
                    scopes: request_scopes.as_deref(),
                    state: fixture["state"].as_str().unwrap(),
                    code_challenge: fixture["codeChallenge"].as_str().unwrap(),
                    login_hint: case["loginHint"].as_str(),
                    nonce: None,
                    additional_params: additional_params.as_ref(),
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
            if matches!(id, "linkedin" | "slack" | "naver" | "linear") {
                assert!(!query.contains_key("code_challenge_method"));
                assert!(!query.contains_key("code_challenge"));
            } else {
                assert_eq!(query["code_challenge_method"], "S256");
                assert_eq!(query["code_challenge"], fixture["codeChallenge"]);
            }
            if matches!(id, "slack" | "naver") {
                assert!(!query.contains_key("login_hint"));
            } else {
                assert_eq!(json!(query.get("login_hint")), case["loginHint"]);
            }
            assert_eq!(
                json!(query.get("request_marker")),
                case["additionalParams"]["request_marker"]
            );
            assert_eq!(query["state"], fixture["state"]);
            assert_eq!(
                json!(query.get("token_access_type")),
                case["tokenAccessType"]
            );
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

struct FailedCustomProfile;

#[async_trait]
impl OAuthUserInfoHandler for FailedCustomProfile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        Err(better_auth_core::AuthError::internal(
            "Ordinary custom userinfo failed",
        ))
    }
}

#[tokio::test]
async fn custom_handler_errors_remain_outside_the_default_profile_catch() {
    for id in ["figma", "cloudflare"] {
        let mut config = provider(id);
        config.user_info_url = None;
        config.get_user_info = Some(Arc::new(FailedCustomProfile));
        let resolved = resolve(id, config).await;
        let error = social_profile::fetch_user_info_for_code(
            &resolved.providers[id],
            OAuthUserInfoRequest::default(),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message == "Ordinary custom userinfo failed")
        );
    }
}

#[tokio::test]
async fn figma_authorization_requires_a_nonempty_client_secret() {
    let resolved = resolve("figma", OAuthProvider::figma("client", "")).await;
    let error = authorization::build_authorization_url(
        &resolved.providers["figma"],
        authorization::AuthorizationRequest {
            callback_url: "https://app.example.test/api/auth/callback/figma",
            scopes: None,
            state: "state",
            code_challenge: "challenge",
            login_hint: None,
            nonce: None,
            additional_params: None,
        },
    )
    .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "CLIENT_ID_AND_SECRET_REQUIRED")
    );
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
    async fn start(
        profile: Value,
        events: Arc<Mutex<Vec<&'static str>>>,
        method: &str,
        expected_body: Option<Value>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let method = method.to_ascii_lowercase();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut request = String::new();
            loop {
                let mut line = String::new();
                assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let request = request.to_ascii_lowercase();
            assert!(request.starts_with(&format!("{method} /profile http/1.1")));
            assert!(request.contains("authorization: bearer ordinary-access"));
            let length = request
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map(|length| length.parse::<usize>().unwrap())
                .unwrap_or(0);
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            if let Some(expected) = expected_body {
                assert!(request.contains("content-type: application/json"));
                assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);
            } else {
                assert!(body.is_empty());
            }
            events.lock().unwrap().push("http");
            let body = profile.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .unwrap();
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
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.2.lock().unwrap().push("custom");
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: self.1.clone(),
                email: Some(self.0["email"].as_str().unwrap().into()).into(),
                name: serde_json::from_value(self.0["name"].clone()).unwrap(),
                image: Some(serde_json::from_value(self.0["image"].clone()).unwrap()),
                email_verified: self.0["emailVerified"].as_bool().unwrap(),
                additional_fields: Map::new(),
            },
            data: json!({"id":self.1}),
        }))
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
    for id in [
        "gitlab",
        "spotify",
        "huggingface",
        "polar",
        "vercel",
        "figma",
        "dropbox",
        "kick",
        "linkedin",
        "slack",
        "naver",
        "linear",
        "cloudflare",
    ] {
        let case = &fixture["providers"][id];
        let profile_fields = if id == "naver" {
            &case["profile"]["response"]
        } else {
            &case["profile"]
        };
        let subject = match &profile_fields[case["subjectField"].as_str().unwrap()] {
            Value::String(id) => id.clone(),
            id => id.to_string(),
        };
        for mode in ["default", "mapped", "custom"] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let started = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let profile = if id == "kick" {
                json!({"data": [case["profile"]]})
            } else if id == "linear" {
                json!({"data": {"viewer": case["profile"]}})
            } else if id == "cloudflare" {
                json!({"success": true, "result": case["profile"]})
            } else {
                case["profile"].clone()
            };
            let server = ProfileServer::start(
                profile,
                events.clone(),
                case["profileMethod"].as_str().unwrap_or("GET"),
                case.get("profileBody").cloned(),
            )
            .await;
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
            let response = response.await.unwrap().unwrap().unwrap();
            events.lock().unwrap().push("returned");
            if mode != "custom" {
                assert_eq!(response.data, case["profile"]);
            }
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
        let config = &resolved.providers[id].config;
        for variant in case["normalProfileCases"].as_array().unwrap() {
            assert_eq!(
                public_user(
                    config
                        .decode_profile(variant["profile"].clone())
                        .unwrap()
                        .unwrap()
                ),
                variant["user"]
            );
        }
    }
    let case = &fixture["providers"]["gitlab"];
    for rejected in case["rejectedStates"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut profile = case["profile"].as_object().unwrap().clone();
        profile.extend(rejected["patch"].as_object().unwrap().clone());
        let server = ProfileServer::start(profile.into(), events.clone(), "GET", None).await;
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
        assert!(matches!(result, Ok(None)));
        assert_eq!(*events.lock().unwrap(), ["http"]);
    }
}

#[tokio::test]
async fn cloudflare_api_failures_return_no_profile_before_mapping() {
    let fixture = fixture();
    let case = &fixture["providers"]["cloudflare"];
    for rejected in case["rejectedResponses"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server =
            ProfileServer::start(rejected["response"].clone(), events.clone(), "GET", None).await;
        let mut config = provider("cloudflare");
        config.user_info_url = Some(format!("{}/profile", server.url));
        config.map_profile_to_user = Some(Arc::new(Mapper {
            raw: case["profile"].clone(),
            patch: case["mapperPatch"].clone(),
            events: events.clone(),
            started: Default::default(),
            resume: Default::default(),
        }));
        let resolved = resolve("cloudflare", config).await;
        let result = social_profile::fetch_user_info_for_code(
            &resolved.providers["cloudflare"],
            OAuthUserInfoRequest {
                access_token: Some("ordinary-access".into()),
                ..Default::default()
            },
            None,
        )
        .await;
        assert!(matches!(result, Ok(None)));
        assert_eq!(*events.lock().unwrap(), ["http"]);
    }
}

#[tokio::test]
async fn linear_missing_viewer_returns_no_profile_before_mapping() {
    let fixture = fixture();
    let case = &fixture["providers"]["linear"];
    for profile in case["missingViewerResponses"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = ProfileServer::start(
            profile.clone(),
            events.clone(),
            "POST",
            Some(case["profileBody"].clone()),
        )
        .await;
        let mut config = provider("linear");
        config.user_info_url = Some(format!("{}/profile", server.url));
        let resume = Arc::new(tokio::sync::Notify::new());
        resume.notify_one();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            raw: case["profile"].clone(),
            patch: case["mapperPatch"].clone(),
            events: events.clone(),
            started: Default::default(),
            resume,
        }));
        let resolved = resolve("linear", config).await;
        let result = social_profile::fetch_user_info_for_code(
            &resolved.providers["linear"],
            OAuthUserInfoRequest {
                access_token: Some("ordinary-access".into()),
                ..Default::default()
            },
            None,
        )
        .await;
        assert!(matches!(result, Ok(None)));
        assert_eq!(*events.lock().unwrap(), ["http"]);
    }
}

struct FailedCloudflareMapper;

#[async_trait]
impl OAuthProfileMapper for FailedCloudflareMapper {
    async fn map_profile(&self, _: &Value) -> AuthResult<OAuthProfile> {
        Err(AuthError::internal("Ordinary Cloudflare mapper failed"))
    }
}

#[tokio::test]
async fn cloudflare_mapper_errors_propagate() {
    let profile = fixture()["providers"]["cloudflare"]["profile"].clone();
    let events = Arc::new(Mutex::new(Vec::new()));
    let server = ProfileServer::start(
        json!({"success": true, "result": profile}),
        events.clone(),
        "GET",
        None,
    )
    .await;
    let mut config = provider("cloudflare");
    config.user_info_url = Some(format!("{}/profile", server.url));
    config.map_profile_to_user = Some(Arc::new(FailedCloudflareMapper));
    let resolved = resolve("cloudflare", config).await;
    let error = social_profile::fetch_user_info_for_code(
        &resolved.providers["cloudflare"],
        OAuthUserInfoRequest {
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "Ordinary Cloudflare mapper failed")
    );
    assert_eq!(*events.lock().unwrap(), ["http"]);
}

#[tokio::test]
async fn cloudflare_ignores_request_parameters_and_retains_configured_url_options() {
    let fixture = fixture();
    let case = &fixture["providers"]["cloudflare"]["requestParameters"];
    let mut config = provider("cloudflare");
    config.auth_url = case["options"]["authorizationEndpoint"]
        .as_str()
        .unwrap()
        .into();
    config.redirect_uri = Some(case["options"]["redirectURI"].as_str().unwrap().into());
    let resolved = resolve("cloudflare", config).await;
    let input = &case["input"];
    let additional_params = serde_json::from_value(input["additionalParams"].clone()).unwrap();
    let url = authorization::build_authorization_url(
        &resolved.providers["cloudflare"],
        authorization::AuthorizationRequest {
            callback_url: input["redirectURI"].as_str().unwrap(),
            scopes: None,
            state: input["state"].as_str().unwrap(),
            code_challenge: fixture["codeChallenge"].as_str().unwrap(),
            login_hint: input["loginHint"].as_str(),
            nonce: input["idTokenNonce"].as_str(),
            additional_params: Some(&additional_params),
        },
    )
    .unwrap();
    let query: HashMap<_, _> = url::Url::parse(&url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(json!(query), case["authorization"]);
}
