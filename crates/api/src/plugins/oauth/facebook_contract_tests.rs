#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Contract tests fail immediately when a captured fixture or provider result changes."
)]

use super::*;
use base64::Engine;
use better_auth_core::{AuthError, SchemaValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;

type Events = Arc<Mutex<Vec<&'static str>>>;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/facebook-1.7.6.json"
    )))
    .unwrap()
}

fn provider(fixture: &Value, fields: &Value, local_url: Option<&str>) -> OAuthProvider {
    let metadata = &fixture["metadata"];
    let options = FacebookOptions {
        fields: fields
            .get("fields")
            .map(|value| serde_json::from_value(value.clone()).unwrap())
            .unwrap_or_default(),
        additional_client_ids: metadata["clientIds"]
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
            .map(|value| value.as_str().unwrap().to_owned())
            .collect(),
        debug_token_url: local_url.map(|url| format!("{url}/debug_token")),
        ..Default::default()
    };
    let mut provider = OAuthProvider::facebook(
        metadata["clientId"].as_str().unwrap(),
        metadata["clientSecret"].as_str().unwrap(),
        options,
    );
    if let Some(url) = local_url {
        provider.token_url = format!("{url}/v24.0/oauth/access_token");
        provider.user_info_url = Some(format!("{url}/me"));
    }
    provider
}

fn resolved(config: OAuthProvider) -> resolved::ResolvedProvider {
    resolved::ResolvedProvider {
        config,
        generic: None,
    }
}

#[test]
fn scopes_login_hint_config_id_and_no_pkce_match_captured_urls() {
    let fixture = fixture();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
        fixture["metadata"]["codeVerifier"]
            .as_str()
            .unwrap()
            .as_bytes(),
    ));
    let config = provider(&fixture, &Value::Null, None);
    assert_eq!(
        config.auth_url,
        fixture["metadata"]["authorizationEndpoint"]
    );
    assert_eq!(config.token_url, fixture["metadata"]["tokenEndpoint"]);
    assert_eq!(
        json!(config.user_info_url),
        fixture["metadata"]["profileEndpoint"]
    );
    for sample in fixture["scopeCases"].as_array().unwrap() {
        let options = &sample["options"];
        let mut config = provider(&fixture, options, None);
        if let Some(config_id) = options["configId"].as_str() {
            config
                .authorization_params
                .push(("config_id".into(), config_id.into()));
        }
        config.scopes = options
            .get("scope")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        config.disable_default_scope = options["disableDefaultScope"].as_bool().unwrap_or(false);
        config.prompt = options["prompt"].as_str().map(str::to_owned);
        let input = &sample["input"];
        let scopes: Option<Vec<String>> = input
            .get("scopes")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        let additional_params: Option<indexmap::IndexMap<String, String>> = input
            .get("additionalParams")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        let url = authorization::build_authorization_url(
            &resolved(config),
            authorization::AuthorizationRequest {
                callback_url: input["redirectURI"].as_str().unwrap(),
                scopes: scopes.as_deref(),
                state: input["state"].as_str().unwrap(),
                code_challenge: &challenge,
                login_hint: input["loginHint"].as_str(),
                nonce: input["idTokenNonce"].as_str(),
                additional_params: additional_params.as_ref(),
            },
        )
        .unwrap();
        assert_eq!(url, sample["url"], "{}", sample["name"]);
    }
}

pub(super) struct Server {
    pub(super) url: String,
    pub(super) requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub(super) async fn start(fixture: &Value, sample: &Value, events: Events) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let grants = fixture["grants"].clone();
        let sample = sample.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                let _ = socket.read_line(&mut line).await.unwrap();
                let mut headers = HashMap::new();
                loop {
                    let mut header = String::new();
                    assert_ne!(socket.read_line(&mut header).await.unwrap(), 0);
                    if header == "\r\n" {
                        break;
                    }
                    let (key, value) = header.split_once(':').unwrap();
                    let _ = headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length = headers
                    .get("content-length")
                    .map(|value| value.parse::<usize>().unwrap())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                let _ = socket.read_exact(&mut body).await.unwrap();
                let body = String::from_utf8(body).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                captured.lock().unwrap().push(json!({
                    "url": format!("https://graph.facebook.com{path}"), "method": method,
                    "authorization": headers.get("authorization"), "contentType": headers.get("content-type"),
                    "accept": headers.get("accept"), "body": body,
                }));
                let (data, status, event) = match path.split('?').next().unwrap() {
                    "/v24.0/oauth/access_token" => {
                        let name = if body.contains("grant_type=refresh_token") {
                            "refresh"
                        } else {
                            "code"
                        };
                        let grant = grants
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|grant| grant["name"] == name)
                            .unwrap();
                        (grant["rawResponse"].clone(), 200, name)
                    }
                    "/debug_token" => (
                        sample["debugResponse"].clone(),
                        sample["debugStatus"].as_u64().unwrap(),
                        "debug",
                    ),
                    _ => {
                        assert_eq!(path.split('?').next(), Some("/me"));
                        (
                            sample["profile"].clone(),
                            sample["profileStatus"].as_u64().unwrap(),
                            "profile",
                        )
                    }
                };
                events.lock().unwrap().push(event);
                let body = data.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    pub(super) fn config(&self, fixture: &Value, sample: &Value) -> OAuthProvider {
        provider(fixture, &sample["options"], Some(&self.url))
    }
}

#[tokio::test]
async fn code_and_refresh_match_captured_post_requests_and_token_fields() {
    let fixture = fixture();
    let events = Arc::new(Mutex::new(Vec::new()));
    let server = Server::start(&fixture, &fixture["profileCases"][0], events.clone()).await;
    let provider = resolved(server.config(&fixture, &Value::Null));
    for sample in fixture["grants"].as_array().unwrap() {
        let tokens = if sample["name"] == "code" {
            let input = &sample["input"];
            provider_tokens::validate_authorization_code_via_provider(
                &provider,
                input["code"].as_str().unwrap(),
                input["redirectURI"].as_str().unwrap(),
                input["codeVerifier"].as_str(),
                input["deviceId"].as_str(),
            )
            .await
            .unwrap()
        } else {
            provider_tokens::refresh_tokens_via_provider(
                &provider,
                sample["input"].as_str().unwrap(),
                &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
            )
            .await
            .unwrap()
        };
        let expected = &sample["response"];
        assert_eq!(json!(tokens.access_token), expected["accessToken"]);
        assert_eq!(json!(tokens.refresh_token), expected["refreshToken"]);
        assert_eq!(json!(tokens.token_type), expected["tokenType"]);
        assert_eq!(json!(tokens.scopes), expected["scopes"]);
        assert_eq!(tokens.raw.as_ref(), expected.get("raw"));
        assert!(tokens.id_token.is_none());
        assert!(tokens.access_token_expires_at.is_none());
        assert!(tokens.refresh_token_expires_at.is_none());
        assert_eq!(
            json!(std::mem::take(&mut *server.requests.lock().unwrap())),
            sample["requests"]
        );
        assert_eq!(
            json!(std::mem::take(&mut *events.lock().unwrap())),
            sample["events"]
        );
    }
}

async fn fetch(config: OAuthProvider, input: Value) -> AuthResult<Option<OAuthUserInfoResponse>> {
    social_profile::fetch_user_info_for_code(
        &resolved(config),
        OAuthUserInfoRequest {
            access_token: input["accessToken"].as_str().map(str::to_owned),
            ..Default::default()
        },
        None,
    )
    .await
}

fn public_response(response: Option<OAuthUserInfoResponse>) -> Value {
    response.map_or(Value::Null, |response| {
        json!({
            "user": types::AccountInfoUser {
                id: None, name: response.user.name, email: response.user.email, image: response.user.image,
                email_verified: response.user.email_verified, additional_fields: response.user.additional_fields,
            },
            "data": response.data,
        })
    })
}

struct Mapper {
    events: Events,
    seen: Arc<Mutex<Vec<Value>>>,
    mapped: OAuthProfile,
    barrier: Option<(Arc<Notify>, Arc<Notify>)>,
    error: Option<String>,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.seen.lock().unwrap().push(profile.clone());
        if let Some(message) = &self.error {
            self.events.lock().unwrap().push("mapper");
            return Err(AuthError::internal(message.clone()));
        }
        self.events.lock().unwrap().push("map:start");
        if let Some((started, resume)) = &self.barrier {
            started.notify_one();
            resume.notified().await;
        }
        self.events.lock().unwrap().push("map:end");
        Ok(self.mapped.clone())
    }
}

fn mapper_fields(sample: &Value) -> OAuthProfile {
    let patch = sample["mapperPatch"].as_object().unwrap();
    let email = if sample["mapperEmailMode"] == "undefined" {
        Some(SchemaValue::Undefined)
    } else {
        patch.get("email").map(|value| {
            SchemaValue::from(serde_json::from_value::<Option<String>>(value.clone()).unwrap())
        })
    };
    OAuthProfile {
        email,
        name: patch
            .get("name")
            .map(|value| serde_json::from_value(value.clone()).unwrap()),
        image: patch
            .get("image")
            .map(|value| serde_json::from_value(value.clone()).unwrap()),
        email_verified: patch.get("emailVerified").map(|value| {
            SchemaValue::from(serde_json::from_value::<Option<bool>>(value.clone()).unwrap())
        }),
        additional_fields: patch
            .iter()
            .filter(|(key, _)| {
                !matches!(key.as_str(), "name" | "email" | "image" | "emailVerified")
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

#[tokio::test]
async fn fourteen_graph_profiles_match_capture_and_await_the_mapper() {
    let fixture = fixture();
    for sample in fixture["profileCases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|sample| sample["source"] == "graph")
    {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(&fixture, sample, events.clone()).await;
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let barrier = sample["name"] == "mapped display";
        let mut config = server.config(&fixture, sample);
        config.map_profile_to_user = Some(Arc::new(Mapper {
            events: events.clone(),
            seen: seen.clone(),
            mapped: mapper_fields(sample),
            error: None,
            barrier: barrier.then(|| (started.clone(), resume.clone())),
        }));
        let mut pending = tokio::spawn(fetch(config, sample["input"].clone()));
        if barrier {
            let reached_mapper = tokio::select! {
                () = started.notified() => true,
                _ = &mut pending => false,
            };
            assert!(reached_mapper, "Profile returned before the mapper barrier");
            assert!(!pending.is_finished());
            assert_eq!(*events.lock().unwrap(), ["debug", "profile", "map:start"]);
            assert_eq!(json!(*server.requests.lock().unwrap()), sample["requests"]);
            resume.notify_one();
        }
        let response = pending.await.unwrap().unwrap();
        events.lock().unwrap().push("returned");
        assert_eq!(
            public_response(response),
            sample["result"],
            "{}",
            sample["name"]
        );
        assert_eq!(
            json!(*server.requests.lock().unwrap()),
            sample["requests"],
            "{}",
            sample["name"]
        );
        assert_eq!(
            json!(*events.lock().unwrap()),
            sample["events"],
            "{}",
            sample["name"]
        );
        let seen = seen.lock().unwrap();
        assert_eq!(json!(seen.len()), sample["mapperCalls"]);
        assert_eq!(seen.first(), sample.get("mapperProfile"));
    }
}

struct Custom {
    mode: String,
    response: OAuthUserInfoResponse,
    events: Events,
    error: String,
}

#[async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.events.lock().unwrap().push("custom");
        match self.mode.as_str() {
            "custom error" => Err(AuthError::internal(self.error.clone())),
            "custom null" => Ok(None),
            _ => Ok(Some(self.response.clone())),
        }
    }
}

#[tokio::test]
async fn graph_failures_and_custom_results_match_the_captured_callback_boundary() {
    let fixture = fixture();
    let custom = fixture["specialCases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["mode"] == "custom success")
        .unwrap();
    for sample in fixture["specialCases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|sample| sample["mode"] != "limited mapper error")
    {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(&fixture, sample, events.clone()).await;
        let mut config = server.config(&fixture, sample);
        let mode = sample["mode"].as_str().unwrap();
        let error = format!("Ordinary Facebook {mode}");
        config.map_profile_to_user = Some(Arc::new(Mapper {
            events: events.clone(),
            seen: seen.clone(),
            mapped: Default::default(),
            barrier: None,
            error: Some(error.clone()),
        }));
        if mode.starts_with("custom") {
            let user = &custom["result"]["user"];
            config.get_user_info = Some(Arc::new(Custom {
                mode: mode.into(),
                events: events.clone(),
                error: error.clone(),
                response: OAuthUserInfoResponse {
                    user: OAuthUserInfo {
                        id: custom["result"]["data"]["id"].as_str().unwrap().into(),
                        name: serde_json::from_value(user["name"].clone()).unwrap(),
                        email: serde_json::from_value::<Option<String>>(user["email"].clone())
                            .unwrap()
                            .into(),
                        image: user
                            .get("image")
                            .map(|value| serde_json::from_value(value.clone()).unwrap()),
                        email_verified: Some(user["emailVerified"].as_bool().unwrap()).into(),
                        additional_fields: Default::default(),
                    },
                    data: custom["result"]["data"].clone(),
                },
            }));
        }
        let response = fetch(config, sample["input"].clone()).await;
        if sample.get("error").is_some() {
            assert!(
                matches!(response.unwrap_err(), AuthError::Internal(message) if message == error)
            );
            events.lock().unwrap().push("rejected");
        } else {
            assert_eq!(
                public_response(response.unwrap()),
                sample["result"],
                "{mode}"
            );
            events.lock().unwrap().push("returned");
        }
        assert_eq!(json!(*events.lock().unwrap()), sample["events"], "{mode}");
        assert_eq!(
            json!(*server.requests.lock().unwrap()),
            sample["requests"],
            "{mode}"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(json!(seen.len()), sample["mapperCalls"], "{mode}");
        assert_eq!(json!(*seen), sample["mapperProfiles"], "{mode}");
    }
}
