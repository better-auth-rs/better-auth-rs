#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Contract tests fail immediately when a local fixture or provider result changes."
)]

use super::*;
use better_auth_core::AuthError;
use serde_json::{Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

const CALLBACK: &str = "http://app.example.test/api/auth/callback/salesforce";
const PICTURE: &str = "https://images.example.test/salesforce.png";
const THUMBNAIL: &str = "https://images.example.test/salesforce-small.png";

fn profile() -> Value {
    json!({
        "sub": "https://login.salesforce.com/id/ordinary-org/salesforce-owner",
        "user_id": "salesforce-owner", "organization_id": "ordinary-org",
        "name": "Salesforce Owner", "email": "salesforce-owner@example.test", "email_verified": true,
        "photos": {"picture": PICTURE, "thumbnail": THUMBNAIL}
    })
}

fn provider() -> OAuthProvider {
    OAuthProvider::salesforce("ordinary-client", "ordinary-client-secret")
}

fn resolved(config: OAuthProvider) -> resolved::ResolvedProvider {
    resolved::ResolvedProvider {
        config,
        generic: None,
    }
}

fn authorization(config: OAuthProvider, scopes: &[String], challenge: &str) -> AuthResult<String> {
    authorization::build_authorization_url(
        &resolved(config),
        authorization::AuthorizationRequest {
            callback_url: CALLBACK,
            scopes: Some(scopes),
            state: "ordinary-state",
            code_challenge: challenge,
            login_hint: Some("ordinary@example.test"),
            nonce: None,
            additional_params: Some(&[("request_marker".into(), "ordinary".into())].into()),
        },
    )
}

#[test]
fn constructor_endpoints_scopes_pkce_and_redirect_match_pinned_salesforce() {
    let config = provider();
    assert_eq!(
        config.auth_url,
        "https://login.salesforce.com/services/oauth2/authorize"
    );
    assert_eq!(
        config.token_url,
        "https://login.salesforce.com/services/oauth2/token"
    );
    assert_eq!(
        config.user_info_url.as_deref(),
        Some("https://login.salesforce.com/services/oauth2/userinfo")
    );
    assert!(config.scopes.is_none());
    assert!(!config.account_info_includes_id());
    for host in [
        "login.salesforce.com",
        "test.salesforce.com",
        "ordinary.my.salesforce.com",
    ] {
        for (disabled, configured, requested, scope) in [
            (false, vec![], vec![], Some("openid email profile")),
            (
                false,
                vec!["api", "email"],
                vec!["refresh_token", "api"],
                Some("openid email profile api email refresh_token api"),
            ),
            (
                true,
                vec!["api"],
                vec!["refresh_token"],
                Some("api refresh_token"),
            ),
            (true, vec![], vec![], None),
        ] {
            let mut config = provider();
            config.auth_url = format!("https://{host}/services/oauth2/authorize");
            config.disable_default_scope = disabled;
            config.scopes = Some(configured.into_iter().map(str::to_owned).collect());
            config.prompt = Some("consent".into());
            config.redirect_uri = Some("http://app.example.test/configured-callback".into());
            let request: Vec<String> = requested.into_iter().map(str::to_owned).collect();
            let url =
                url::Url::parse(&authorization(config, &request, "ordinary-challenge").unwrap())
                    .unwrap();
            assert_eq!(url.host_str(), Some(host));
            let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
            let mut expected = json!({
                "response_type":"code", "client_id":"ordinary-client", "state":"ordinary-state",
                "redirect_uri":"http://app.example.test/configured-callback", "code_challenge_method":"S256",
                "code_challenge":"ordinary-challenge", "request_marker":"ordinary"
            });
            if let Some(scope) = scope {
                expected["scope"] = json!(scope);
            }
            assert_eq!(json!(query), expected);
        }
    }
}

#[test]
fn authorization_requires_both_credentials_and_a_pkce_challenge() {
    for (client, secret) in [("", "ordinary-client-secret"), ("ordinary-client", "")] {
        let error =
            authorization(OAuthProvider::salesforce(client, secret), &[], "challenge").unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message == "CLIENT_ID_AND_SECRET_REQUIRED")
        );
    }
    let error = authorization(provider(), &[], "").unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "codeVerifier is required for Salesforce")
    );
}

#[derive(Debug)]
struct Request {
    line: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(profile: Value, status: u16, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
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
                let body = String::from_utf8(body).unwrap();
                let token = line.starts_with("POST /token ");
                let refresh = body.contains("grant_type=refresh_token");
                captured.lock().unwrap().push(Request {
                    line,
                    headers,
                    body,
                });
                events
                    .lock()
                    .unwrap()
                    .push(if token { "token" } else { "http" });
                let (body, status) = if token {
                    (
                        json!({"access_token":if refresh {"rotated-access"} else {"ordinary-access"},
                        "refresh_token":if refresh {"rotated-refresh"} else {"ordinary-refresh"},
                        "token_type":"Bearer", "scope":if refresh {"refreshed-scope"} else {"ordinary-scope"}}),
                        200,
                    )
                } else {
                    (profile.clone(), status)
                };
                let body = body.to_string();
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

    fn config(&self) -> OAuthProvider {
        let mut config = provider();
        config.token_url = format!("{}/token", self.url);
        config.user_info_url = Some(format!("{}/profile", self.url));
        config
    }
}

async fn fetch(config: OAuthProvider) -> AuthResult<Option<OAuthUserInfoResponse>> {
    social_profile::fetch_user_info_for_code(
        &resolved(config),
        OAuthUserInfoRequest {
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        },
        None,
    )
    .await
}

fn public_user(user: OAuthUserInfo) -> Value {
    serde_json::to_value(types::AccountInfoUser {
        id: None,
        name: user.name,
        email: user.email,
        image: user.image,
        email_verified: user.email_verified,
        additional_fields: user.additional_fields,
    })
    .unwrap()
}

#[tokio::test]
async fn code_and_refresh_use_client_secret_post_and_keep_original_parameters() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let server = Server::start(profile(), 200, events.clone()).await;
    let mut config = server.config();
    config.redirect_uri = Some("http://app.example.test/configured-callback".into());
    let provider = resolved(config);
    let code = provider_tokens::validate_authorization_code_via_provider(
        &provider,
        "ordinary-code",
        CALLBACK,
        Some("ordinary-verifier"),
        None,
    )
    .await
    .unwrap();
    let refresh = provider_tokens::refresh_tokens_via_provider(
        &provider,
        "ordinary-refresh",
        &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
    )
    .await
    .unwrap();
    assert_eq!(code.access_token.as_deref(), Some("ordinary-access"));
    assert_eq!(code.scopes, ["ordinary-scope"]);
    assert_eq!(refresh.access_token.as_deref(), Some("rotated-access"));
    assert_eq!(refresh.refresh_token.as_deref(), Some("rotated-refresh"));
    assert_eq!(refresh.scopes, ["refreshed-scope"]);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(request.line, "POST /token HTTP/1.1\r\n");
        assert!(!request.headers.contains_key("authorization"));
        assert_eq!(
            request.headers["content-type"],
            "application/x-www-form-urlencoded"
        );
    }
    let form = |index: usize| {
        json!(
            url::form_urlencoded::parse(requests[index].body.as_bytes())
                .into_owned()
                .collect::<HashMap<_, _>>()
        )
    };
    assert_eq!(
        form(0),
        json!({"grant_type":"authorization_code", "code":"ordinary-code", "code_verifier":"ordinary-verifier", "redirect_uri":"http://app.example.test/configured-callback", "client_id":"ordinary-client", "client_secret":"ordinary-client-secret"})
    );
    assert_eq!(
        form(1),
        json!({"grant_type":"refresh_token", "refresh_token":"ordinary-refresh", "client_id":"ordinary-client", "client_secret":"ordinary-client-secret"})
    );
    assert_eq!(*events.lock().unwrap(), ["token", "token"]);
}

#[tokio::test]
async fn normal_http_profiles_preserve_photo_fallback_and_nullable_email() {
    for (photos, email, image, verified) in [
        (
            Some(json!({"picture":PICTURE,"thumbnail":THUMBNAIL})),
            Some(json!("salesforce-owner@example.test")),
            Some(json!(PICTURE)),
            Some(json!(true)),
        ),
        (
            Some(json!({"picture":"","thumbnail":THUMBNAIL})),
            Some(Value::Null),
            Some(json!(THUMBNAIL)),
            None,
        ),
        (
            Some(json!({"picture":null,"thumbnail":THUMBNAIL})),
            None,
            Some(json!(THUMBNAIL)),
            Some(Value::Null),
        ),
        (
            None,
            Some(json!("salesforce-owner@example.test")),
            None,
            Some(json!(false)),
        ),
        (
            Some(json!({})),
            Some(json!("salesforce-owner@example.test")),
            None,
            None,
        ),
        (
            Some(json!({"thumbnail":null})),
            Some(json!("salesforce-owner@example.test")),
            Some(Value::Null),
            None,
        ),
        (
            Some(json!({"thumbnail":""})),
            Some(json!("salesforce-owner@example.test")),
            Some(json!("")),
            None,
        ),
    ] {
        let mut raw = profile();
        for (field, value) in [
            ("photos", photos),
            ("email", email.clone()),
            ("email_verified", verified.clone()),
        ] {
            let _ = raw.as_object_mut().unwrap().remove(field);
            if let Some(value) = value {
                raw[field] = value;
            }
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(raw.clone(), 200, events.clone()).await;
        let response = fetch(server.config()).await.unwrap().unwrap();
        let mut expected = json!({"name":"Salesforce Owner","emailVerified":verified.and_then(|value|value.as_bool()).unwrap_or(false)});
        if let Some(email) = email {
            expected["email"] = email;
        }
        if let Some(image) = image {
            expected["image"] = image;
        }
        assert_eq!(response.user.id, "salesforce-owner");
        assert_eq!(response.data, raw);
        assert_eq!(public_user(response.user), expected);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].line, "GET /profile HTTP/1.1\r\n");
        assert_eq!(
            requests[0].headers["authorization"],
            "Bearer ordinary-access"
        );
        assert!(requests[0].body.is_empty());
        assert_eq!(*events.lock().unwrap(), ["http"]);
    }
}

struct Mapper {
    events: Arc<Mutex<Vec<&'static str>>>,
    barrier: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(raw, &profile());
        self.events.lock().unwrap().push("map:start");
        let Some((started, resume)) = &self.barrier else {
            return Err(AuthError::internal("Ordinary Salesforce mapper failed"));
        };
        started.notify_one();
        resume.notified().await;
        self.events.lock().unwrap().push("map:end");
        Ok(OAuthProfile {
            name: Some(Some("Mapped Salesforce Owner".into())),
            email: Some(None.into()),
            image: Some(None),
            email_verified: Some(false),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn raw_profile_mapper_is_awaited_and_overrides_default_fields() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let server = Server::start(profile(), 200, events.clone()).await;
    let started = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let mut config = server.config();
    config.map_profile_to_user = Some(Arc::new(Mapper {
        events: events.clone(),
        barrier: Some((started.clone(), resume.clone())),
    }));
    let response = tokio::spawn(fetch(config));
    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    assert_eq!(*events.lock().unwrap(), ["http", "map:start"]);
    assert!(!response.is_finished());
    resume.notify_one();
    let response = response.await.unwrap().unwrap().unwrap();
    events.lock().unwrap().push("returned");
    assert_eq!(response.data, profile());
    assert_eq!(
        public_user(response.user),
        json!({"name":"Mapped Salesforce Owner","email":null,"image":null,"emailVerified":false})
    );
    assert_eq!(
        *events.lock().unwrap(),
        ["http", "map:start", "map:end", "returned"]
    );
}

struct Custom {
    mode: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.events.lock().unwrap().push("custom");
        match self.mode {
            "error" => Err(AuthError::internal(
                "Ordinary custom Salesforce profile failed",
            )),
            "null" => Ok(None),
            _ => Ok(Some(OAuthUserInfoResponse {
                user: provider().decode_profile(profile())?.unwrap(),
                data: profile(),
            })),
        }
    }
}

#[tokio::test]
async fn default_failures_return_none_while_custom_results_bypass_http_mapper_and_catch() {
    for mode in ["http503", "mapper", "success", "null", "error"] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(
            profile(),
            if mode == "http503" { 503 } else { 200 },
            events.clone(),
        )
        .await;
        let mut config = server.config();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            events: events.clone(),
            barrier: None,
        }));
        if !matches!(mode, "http503" | "mapper") {
            config.get_user_info = Some(Arc::new(Custom {
                mode,
                events: events.clone(),
            }));
        }
        let response = fetch(config).await;
        match mode {
            "error" => assert!(
                matches!(response.unwrap_err(), AuthError::Internal(message) if message == "Ordinary custom Salesforce profile failed")
            ),
            "success" => assert_eq!(response.unwrap().unwrap().data, profile()),
            _ => assert!(response.unwrap().is_none()),
        }
        let expected = match mode {
            "http503" => vec!["http"],
            "mapper" => vec!["http", "map:start"],
            _ => vec!["custom"],
        };
        assert_eq!(*events.lock().unwrap(), expected);
        assert_eq!(
            server.requests.lock().unwrap().len(),
            usize::from(matches!(mode, "http503" | "mapper"))
        );
    }
}
