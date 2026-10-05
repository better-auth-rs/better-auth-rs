#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Contract tests fail immediately when a captured fixture or provider result changes."
)]

use super::*;
use better_auth_core::{AuthError, SchemaValue};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/wechat-1.7.6.json"
    )))
    .unwrap()
}

fn provider() -> OAuthProvider {
    OAuthProvider::wechat("ordinary-client", "ordinary-secret")
}

fn resolved(config: OAuthProvider) -> resolved::ResolvedProvider {
    resolved::ResolvedProvider {
        config,
        generic: None,
    }
}

#[test]
fn authorization_matches_captured_scopes_language_redirect_and_fixed_protocol() {
    let fixture = fixture();
    let config = provider();
    assert_eq!(
        config.auth_url,
        fixture["metadata"]["authorizationEndpoint"]
    );
    assert_eq!(config.token_url, fixture["metadata"]["tokenEndpoint"]);
    assert_eq!(
        json!(config.user_info_url),
        fixture["metadata"]["profileEndpoint"]
    );
    assert_eq!(
        json!(config.wechat_refresh_url()),
        fixture["metadata"]["refreshEndpoint"]
    );
    for sample in fixture["scopeCases"].as_array().unwrap() {
        let mut config = provider();
        let options = &sample["options"];
        config.scopes = options
            .get("scope")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        config.disable_default_scope = options["disableDefaultScope"].as_bool().unwrap_or(false);
        config.redirect_uri = options["redirectURI"].as_str().map(str::to_owned);
        config.prompt = options["prompt"].as_str().map(str::to_owned);
        if let Some(lang) = options["lang"].as_str() {
            config
                .authorization_params
                .push(("lang".into(), lang.into()));
        }
        let input = &sample["input"];
        let scopes: Option<Vec<String>> = input
            .get("scopes")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        let params = serde_json::from_value(input["additionalParams"].clone()).unwrap();
        let url = authorization::build_authorization_url(
            &resolved(config),
            authorization::AuthorizationRequest {
                callback_url: input["redirectURI"].as_str().unwrap(),
                scopes: scopes.as_deref(),
                state: input["state"].as_str().unwrap(),
                code_challenge: "ordinary-challenge",
                login_hint: input["loginHint"].as_str(),
                nonce: input["nonce"].as_str(),
                additional_params: Some(&params),
            },
        )
        .unwrap();
        assert_eq!(url, sample["url"], "{}", sample["name"]);
    }
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(data: Value, status: u64, events: Arc<Mutex<Vec<String>>>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
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
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                captured.lock().unwrap().push(json!({
                    "url": format!("https://api.weixin.qq.com{path}"), "method": method,
                    "authorization": headers.get("authorization"), "contentType": headers.get("content-type"),
                    "accept": headers.get("accept"), "body": String::from_utf8(body).unwrap(),
                }));
                events.lock().unwrap().push(
                    if path.starts_with("/sns/userinfo?") {
                        "profile"
                    } else if path.starts_with("/sns/oauth2/refresh_token?") {
                        "refresh"
                    } else {
                        "code"
                    }
                    .into(),
                );
                let body = data.to_string();
                socket.get_mut().write_all(format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                ).as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn config(&self) -> OAuthProvider {
        OAuthProvider::wechat_with_endpoints(
            "ordinary-client",
            "ordinary-secret",
            &format!("{}/authorize", self.url),
            &format!("{}/sns/oauth2/access_token", self.url),
            &format!("{}/sns/oauth2/refresh_token", self.url),
            &format!("{}/sns/userinfo", self.url),
        )
    }
}

async fn grant(config: OAuthProvider, name: &str) -> AuthResult<OAuthTokenSet> {
    if name == "code" {
        provider_tokens::validate_authorization_code_via_provider(
            &resolved(config),
            "ordinary-code",
            "https://app.example/api/auth/callback/wechat",
            Some("ordinary-verifier"),
            Some("ordinary-device"),
        )
        .await
    } else {
        provider_tokens::refresh_tokens_via_provider(
            &resolved(config),
            "ordinary-refresh",
            &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
        )
        .await
    }
}

#[tokio::test]
async fn grants_match_captured_get_requests_and_normalized_tokens() {
    let fixture = fixture();
    for sample in fixture["grants"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(sample["rawResponse"].clone(), 200, events.clone()).await;
        let before = Utc::now();
        let name = sample["name"].as_str().unwrap();
        let result = grant(server.config(), name).await.unwrap();
        let after = Utc::now();
        let expected = &sample["response"];
        assert_eq!(json!(result.token_type), expected["tokenType"]);
        assert_eq!(json!(result.access_token), expected["accessToken"]);
        assert_eq!(json!(result.refresh_token), expected["refreshToken"]);
        assert_eq!(json!(result.scopes), expected["scopes"]);
        let expires = result.access_token_expires_at.unwrap();
        let duration = Duration::seconds(sample["rawResponse"]["expires_in"].as_i64().unwrap());
        assert!(expires >= before + duration && expires <= after + duration);
        assert!(result.refresh_token_expires_at.is_none());
        assert!(result.id_token.is_none());
        if name == "code" {
            let raw = result.raw.unwrap();
            assert_eq!(raw["openid"], expected["openid"]);
            assert_eq!(raw["unionid"], expected["unionid"]);
        } else {
            assert!(result.raw.is_none());
        }
        assert_eq!(json!(*server.requests.lock().unwrap()), sample["requests"]);
        assert_eq!(json!(*events.lock().unwrap()), sample["events"]);
    }
}

#[tokio::test]
async fn grant_application_errors_preserve_messages_and_http_503_remains_an_error() {
    let fixture = fixture();
    for sample in fixture["grantFailures"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(
            sample["rawResponse"].clone(),
            sample["status"].as_u64().unwrap(),
            events.clone(),
        )
        .await;
        let error = grant(server.config(), sample["grant"].as_str().unwrap())
            .await
            .unwrap_err();
        let AuthError::Internal(message) = error else {
            panic!("Expected the ordinary Internal error boundary");
        };
        if sample["mode"] == "application error" {
            assert_eq!(message, sample["error"]["message"]);
        } else {
            assert!(message.contains("503"));
        }
        assert!(!message.contains("ordinary-secret"));
        assert_eq!(json!(*server.requests.lock().unwrap()), sample["requests"]);
        assert_eq!(json!(*events.lock().unwrap()), sample["events"]);
    }
}

struct Mapper {
    sample: Value,
    events: Arc<Mutex<Vec<String>>>,
    seen: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.events.lock().unwrap().push("mapper".into());
        self.seen.lock().unwrap().push(profile.clone());
        if self.sample.get("mode").is_some() {
            return Err(AuthError::internal("Ordinary callback failure"));
        }
        let patch = &self.sample["mapperPatch"];
        Ok(OAuthProfile {
            email: if self.sample["mapperEmailMode"] == "undefined" {
                Some(SchemaValue::Undefined)
            } else {
                patch
                    .get("email")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .unwrap()
            },
            name: patch
                .get("name")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .unwrap(),
            ..Default::default()
        })
    }
}

fn public_response(response: Option<OAuthUserInfoResponse>) -> Value {
    response.map_or(Value::Null, |response| json!({
        "user": types::AccountInfoUser { id: None, name: response.user.name, email: response.user.email,
            image: response.user.image, email_verified: response.user.email_verified,
            additional_fields: response.user.additional_fields }, "data": response.data,
    }))
}

async fn fetch(config: OAuthProvider, token: &Value) -> AuthResult<Option<OAuthUserInfoResponse>> {
    social_profile::fetch_user_info_for_code(
        &resolved(config),
        OAuthUserInfoRequest {
            access_token: token["accessToken"].as_str().map(str::to_owned),
            raw: Some(token.clone()),
            ..Default::default()
        },
        None,
    )
    .await
}

#[tokio::test]
async fn profiles_match_captured_mapper_values_order_and_missing_profile_results() {
    let fixture = fixture();
    for sample in fixture["profileCases"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(
            sample["profile"].clone(),
            sample["status"].as_u64().unwrap(),
            events.clone(),
        )
        .await;
        let mut config = server.config();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            sample: sample.clone(),
            events: events.clone(),
            seen: seen.clone(),
        }));
        let result = fetch(config, &sample["token"]).await.unwrap();
        events.lock().unwrap().push("returned".into());
        assert_eq!(
            public_response(result),
            sample["result"],
            "{}",
            sample["name"]
        );
        assert_eq!(json!(*server.requests.lock().unwrap()), sample["requests"]);
        assert_eq!(json!(*events.lock().unwrap()), sample["events"]);
        assert_eq!(json!(seen.lock().unwrap().len()), sample["mapperCalls"]);
        assert_eq!(seen.lock().unwrap().first(), sample.get("mapperProfile"));
    }
}

struct Custom {
    mode: String,
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.events.lock().unwrap().push("custom".into());
        match self.mode.as_str() {
            "custom null" => Ok(None),
            "custom error" => Err(AuthError::internal("Ordinary callback failure")),
            "custom API error" => Err(AuthError::Upstream {
                status: 429,
                code: "ORDINARY_CALLBACK_LIMIT",
                message: "Ordinary callback limit",
            }),
            _ => Ok(Some(OAuthUserInfoResponse {
                user: OAuthUserInfo {
                    id: "ordinary-unionid".into(),
                    name: Some("Custom User".into()).into(),
                    email: Some("custom@example.com".into()).into(),
                    email_verified: Some(false).into(),
                    image: None,
                    additional_fields: Default::default(),
                },
                data: json!({"source":"custom"}),
            })),
        }
    }
}

#[async_trait]
impl OAuthRefreshTokenHandler for Custom {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String> {
        self.events
            .lock()
            .unwrap()
            .push(format!("custom:{refresh_token}"));
        Ok(OAuthTokenSet {
            access_token: Some("custom-access".into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn custom_handlers_keep_priority_and_original_error_contracts() {
    let fixture = fixture();
    for sample in fixture["specialCases"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(
            fixture["profileCases"][0]["profile"].clone(),
            200,
            events.clone(),
        )
        .await;
        let mut config = server.config();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            sample: sample.clone(),
            events: events.clone(),
            seen: seen.clone(),
        }));
        let mode = sample["mode"].as_str().unwrap();
        let handler = Arc::new(Custom {
            mode: mode.into(),
            events: events.clone(),
        });
        if mode == "refresh custom" {
            config.refresh_access_token = Some(handler);
            let result = grant(config, "refresh").await.unwrap();
            assert_eq!(json!(result.access_token), sample["result"]["accessToken"]);
        } else {
            if mode.starts_with("custom") {
                config.get_user_info = Some(handler);
            }
            let result = fetch(config, &fixture["profileCases"][0]["token"]).await;
            if sample.get("error").is_some() {
                if mode == "custom API error" {
                    assert!(matches!(
                        result.unwrap_err(),
                        AuthError::Upstream {
                            status: 429,
                            code: "ORDINARY_CALLBACK_LIMIT",
                            message: "Ordinary callback limit"
                        }
                    ));
                } else {
                    assert!(
                        matches!(result.unwrap_err(), AuthError::Internal(message) if message == sample["error"]["message"])
                    );
                }
            } else {
                let result = result.unwrap();
                let include_id = result.as_ref().map(|response| response.user.id.clone());
                let mut actual = public_response(result);
                if let Some(id) = include_id {
                    actual["user"]["id"] = id.into();
                }
                assert_eq!(actual, sample["result"]);
            }
        }
        assert_eq!(json!(*events.lock().unwrap()), sample["events"]);
        assert_eq!(json!(*server.requests.lock().unwrap()), sample["requests"]);
    }
}
