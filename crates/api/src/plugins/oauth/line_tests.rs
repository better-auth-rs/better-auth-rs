use super::*;
use crate::plugins::{oauth::*, test_helpers};
use better_auth_core::{AuthPlugin, AuthRequest, AuthUser, HttpMethod, wire::UserView};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;
use std::{collections::HashMap, sync::Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &[u8] = b"ordinary-line-fixture-secret-012345";
const CLIENT_ID: &str = "1234567891";

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/line-1.7.6.json"
    ))
    .unwrap()
}

fn token(input: &Value, nonce: Option<&str>) -> String {
    let mut claims = input.clone();
    let now = chrono::Utc::now().timestamp();
    claims.as_object_mut().unwrap().extend([
        ("iss".into(), json!("https://access.line.me")),
        ("aud".into(), json!(CLIENT_ID)),
        ("iat".into(), json!(now)),
        ("exp".into(), json!(now + 3600)),
    ]);
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(input: &Value) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let input = input.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let logged = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break end + 4;
                    }
                    let mut chunk = [0; 4096];
                    let size = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(size, 0);
                    bytes.extend_from_slice(&chunk[..size]);
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let content_length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + content_length {
                    let mut chunk = [0; 4096];
                    let size = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(size, 0);
                    bytes.extend_from_slice(&chunk[..size]);
                }
                let path = headers.split_whitespace().nth(1).unwrap();
                let body = match path {
                    "/token" => {
                        assert!(headers.starts_with("POST /token "));
                        logged.lock().unwrap().push(json!({"path":path}));
                        json!({
                            "id_token": token(&input["claims"], None),
                            "access_token": "ordinary-access",
                            "refresh_token": "ordinary-refresh",
                            "token_type": "Bearer"
                        })
                    }
                    "/verify" => {
                        assert!(headers.starts_with("POST /verify "));
                        assert!(
                            headers
                                .to_lowercase()
                                .contains("content-type: application/x-www-form-urlencoded\r\n")
                        );
                        let form: HashMap<String, String> = url::form_urlencoded::parse(
                            &bytes[header_end..header_end + content_length],
                        )
                        .into_owned()
                        .collect();
                        assert_eq!(form["client_id"], CLIENT_ID);
                        let mut validation = Validation::new(Algorithm::HS256);
                        validation.set_issuer(&["https://access.line.me"]);
                        validation.set_audience(&[CLIENT_ID]);
                        let verified = jsonwebtoken::decode::<Value>(
                            &form["id_token"],
                            &DecodingKey::from_secret(SECRET),
                            &validation,
                        )
                        .unwrap()
                        .claims;
                        if let Some(nonce) = form.get("nonce") {
                            assert_eq!(verified["nonce"], *nonce);
                        }
                        logged.lock().unwrap().push(json!({"path":path,"clientId":form["client_id"],"nonce":form.get("nonce")}));
                        verified
                    }
                    "/userinfo" => {
                        assert!(headers.starts_with("GET /userinfo "));
                        assert!(
                            headers
                                .to_lowercase()
                                .contains("authorization: bearer ordinary-access\r\n")
                        );
                        logged.lock().unwrap().push(json!({"path":path}));
                        input["userinfo"].clone()
                    }
                    _ => panic!("Unexpected LINE fixture request: {path}"),
                };
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn config(&self) -> GenericOAuthConfig {
        let mut provider =
            GenericOAuthConfig::line("1234567890", std::str::from_utf8(SECRET).unwrap());
        provider.client_id = CLIENT_ID.into();
        provider.user_info_url = Some(format!("{}/userinfo", self.url));
        provider.get_user_info = Some(Arc::new(LineProfile {
            verify_url: format!("{}/verify", self.url),
        }));
        provider
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct TokenHandler(OAuthTokenSet);
#[async_trait]
impl OAuthTokenHandler for TokenHandler {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        Ok(self.0.clone())
    }
}

struct Observer {
    inner: Arc<dyn GenericOAuthUserInfoHandler>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
#[async_trait]
impl GenericOAuthUserInfoHandler for Observer {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        panic!("LINE must receive resolved context");
    }
    async fn get_user_info_with_context(
        &self,
        tokens: &OAuthUserInfoRequest,
        context: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<Option<Value>> {
        assert_eq!(context.client_id(), CLIENT_ID);
        assert!(context.expected_nonce().is_none());
        assert!(context.verified_claims().is_none());
        self.calls.lock().unwrap().push("get");
        self.inner.get_user_info_with_context(tokens, context).await
    }
}

struct Mapper {
    calls: Arc<Mutex<Vec<&'static str>>>,
    expected: Value,
    email: Option<String>,
}
#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.calls.lock().unwrap().push("map");
        assert_eq!(*profile, self.expected);
        Ok(OAuthProfile {
            name: Some(
                Some(format!(
                    "Mapped {}",
                    profile["name"].as_str().unwrap_or("User")
                ))
                .into(),
            ),
            email: self.email.clone().map(|email| Some(email).into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn line_code_login_uses_verified_claims_and_matches_pinned_profiles() {
    let expected = fixture();
    let defaults = GenericOAuthConfig::line("1234567890", std::str::from_utf8(SECRET).unwrap());
    assert_eq!(
        json!({"providerId":"line","authorizationUrl":defaults.authorization_url,"tokenUrl":defaults.token_url,"userInfoUrl":defaults.user_info_url,"scopes":defaults.scopes}),
        expected["config"]
    );
    for case in expected["results"].as_array().unwrap() {
        let input = &case["input"];
        let server = Server::start(input).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut provider = server.config();
        provider.get_user_info = Some(Arc::new(Observer {
            inner: provider.get_user_info.take().unwrap(),
            calls: calls.clone(),
        }));
        provider.get_token = Some(Arc::new(TokenHandler(OAuthTokenSet {
            id_token: input.get("claims").map(|claims| token(claims, None)),
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        })));
        provider.map_profile_to_user = Some(Arc::new(Mapper {
            calls: calls.clone(),
            expected: case["profile"].clone(),
            email: input["mappedEmail"].as_str().map(str::to_owned),
        }));
        let plugin = OAuthPlugin::new().add_generic_provider("line-jp", provider);
        let mut config = test_helpers::create_test_config();
        config.account.skip_state_cookie_check = true;
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        start.body = Some(serde_json::to_vec(&json!({"provider":"line-jp","callbackURL":"http://localhost:3000/welcome","disableRedirect":true})).unwrap());
        let response = plugin.on_request(&start, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["scope"], "openid profile email");
        assert!(!params.contains_key("nonce"));
        let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/line-jp");
        callback.query = Some(json!({"code":"ordinary-code","state":params["state"]}));
        let response = plugin.on_request(&callback, &ctx).await.unwrap().unwrap();
        assert_eq!(json!(response.status), case["status"]);
        assert_eq!(
            response.headers.get("Location").map(String::as_str),
            Some("http://localhost:3000/welcome")
        );
        assert_eq!(json!(*calls.lock().unwrap()), case["calls"]);
        let expected_requests = if input.get("claims").is_some() {
            json!([{"path":"/verify","clientId":CLIENT_ID,"nonce":null}])
        } else {
            json!([{"path":"/userinfo"}])
        };
        assert_eq!(json!(*server.requests.lock().unwrap()), expected_requests);
        let user = ctx
            .database
            .get_user_by_email(case["user"]["email"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        let user_id = user.id().display_string().unwrap();
        let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            ctx.session_manager()
                .list_user_sessions(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let view = serde_json::to_value(UserView::from(&user)).unwrap();
        assert_eq!(
            json!({"name":view["name"],"email":view["email"],"image":view["image"],"emailVerified":view["emailVerified"],"accountSubject":accounts[0].account_id}),
            case["user"]
        );
    }
}

#[tokio::test]
async fn line_profile_context_forwards_the_expected_nonce_with_form_encoding() {
    let case = &fixture()["results"][0];
    let server = Server::start(&case["input"]).await;
    let config = server.config();
    let handler = config.get_user_info.as_ref().unwrap();
    let nonce = "ordinary +/&=nonce";
    let request = OAuthUserInfoRequest {
        id_token: Some(token(&case["input"]["claims"], Some(nonce))),
        ..Default::default()
    };
    let result = handler
        .get_user_info_with_context(
            &request,
            GenericOAuthProfileContext::new(&config, Some(nonce), None),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, case["profile"]);
    assert_eq!(
        json!(*server.requests.lock().unwrap()),
        json!([{"path":"/verify","clientId":CLIENT_ID,"nonce":nonce}])
    );
}

fn social_fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/social-line-1.7.6.json"
    );
    serde_json::from_str(
        &std::fs::read_to_string(path)
            .expect("Capture the pinned Social LINE fixture before running its contract tests"),
    )
    .unwrap()
}

async fn social_provider(server: &Server) -> super::super::resolved::ResolvedOAuthConfig {
    let mut provider = OAuthProvider::line(CLIENT_ID, std::str::from_utf8(SECRET).unwrap());
    provider.token_url = format!("{}/token", server.url);
    provider.user_info_url = Some(format!("{}/userinfo", server.url));
    provider.set_line_verify_url(format!("{}/verify", server.url));
    super::super::resolved::ResolvedOAuthConfig::new(
        &OAuthConfig {
            providers: [("line".into(), provider)].into_iter().collect(),
        },
        &HashMap::new(),
        None,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn social_line_configuration_and_profiles_match_pinned_capture() {
    let expected = social_fixture();
    for case in expected["authorization"].as_array().unwrap() {
        let mut config = OAuthProvider::line(CLIENT_ID, std::str::from_utf8(SECRET).unwrap());
        config.scopes = case["options"]
            .get("scope")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        config.disable_default_scope = case["options"]["disableDefaultScope"]
            .as_bool()
            .unwrap_or(false);
        config.prompt = case["options"]
            .get("prompt")
            .map(|value| value.as_str().unwrap().into());
        let request_scopes: Option<Vec<String>> = case
            .get("requestScopes")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        let resolved = super::super::resolved::ResolvedOAuthConfig::new(
            &OAuthConfig {
                providers: [("line".into(), config)].into_iter().collect(),
            },
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let actual = super::super::authorization::build_authorization_url(
            &resolved.providers["line"],
            super::super::authorization::AuthorizationRequest {
                callback_url: expected["callbackURL"].as_str().unwrap(),
                scopes: request_scopes.as_deref(),
                state: "ordinary-state",
                code_challenge: expected["codeChallenge"].as_str().unwrap(),
                login_hint: case.get("loginHint").and_then(Value::as_str),
                nonce: Some("ordinary-nonce"),
                additional_params: None,
            },
        )
        .unwrap();
        assert_eq!(actual, case["url"].as_str().unwrap());
    }
    for case in expected["profiles"].as_array().unwrap() {
        let profile = &case["profile"];
        let server = Server::start(&json!({"userinfo":profile})).await;
        let resolved = social_provider(&server).await;
        let tokens = OAuthUserInfoRequest {
            id_token: (case["source"] == "token").then(|| {
                jsonwebtoken::encode(
                    &Header::new(Algorithm::HS256),
                    profile,
                    &EncodingKey::from_secret(SECRET),
                )
                .unwrap()
            }),
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        };
        let response = super::super::handlers::fetch_user_info_from_provider(
            &resolved.providers["line"],
            tokens,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        let user = response.user;
        let view = super::super::types::AccountInfoUser {
            id: None,
            name: user.name,
            email: user.email,
            image: user.image,
            email_verified: user.email_verified,
            additional_fields: user.additional_fields,
        };
        assert_eq!(serde_json::to_value(view).unwrap(), case["result"]["user"]);
        assert_eq!(response.data, case["result"]["data"]);
        assert_eq!(
            json!(*server.requests.lock().unwrap()),
            if case["source"] == "token" {
                json!([])
            } else {
                json!([{"path":"/userinfo"}])
            }
        );
    }
}

#[tokio::test]
async fn social_line_ordinary_direct_and_code_login_persist_the_profile() {
    let expected = social_fixture();
    let claims = expected["profiles"][0]["profile"].clone();
    for direct in [true, false] {
        let server = Server::start(&json!({"claims":claims,"userinfo":claims})).await;
        let mut resolved = social_provider(&server).await;
        let provider = resolved.providers.remove("line").unwrap().config;
        let plugin = OAuthPlugin::new().add_provider("line", provider);
        let mut config = test_helpers::create_test_config();
        config.account.skip_state_cookie_check = true;
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        let mut body = json!({"provider":"line","callbackURL":"http://localhost:3000/welcome","disableRedirect":true});
        if direct {
            body["idToken"] =
                json!({"token":token(&claims, Some("ordinary-nonce")),"nonce":"ordinary-nonce"});
        }
        start.body = Some(serde_json::to_vec(&body).unwrap());
        let response = plugin.on_request(&start, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        if !direct {
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
            let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
            let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/line");
            callback.query = Some(json!({"code":"ordinary-code","state":params["state"]}));
            let response = plugin.on_request(&callback, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome")
            );
        }
        assert_eq!(
            json!(*server.requests.lock().unwrap()),
            if direct {
                json!([{"path":"/verify","clientId":CLIENT_ID,"nonce":"ordinary-nonce"}])
            } else {
                json!([{"path":"/token"}])
            }
        );
        let user = ctx
            .database
            .get_user_by_email(claims["email"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        let user_id = user.id().display_string().unwrap();
        let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(json!(accounts[0].account_id), claims["sub"]);
        assert_eq!(
            ctx.session_manager()
                .list_user_sessions(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let view = serde_json::to_value(UserView::from(&user)).unwrap();
        assert_eq!(view["name"], claims["name"]);
        assert_eq!(view["image"], claims["picture"]);
        assert_eq!(view["emailVerified"], false);
    }
}

struct SocialMapper(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl OAuthProfileMapper for SocialMapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.0.lock().unwrap().push(profile.clone());
        Ok(OAuthProfile {
            name: Some(Some("Mapped LINE Reader".into()).into()),
            image: Some(None),
            email_verified: Some(Some(true).into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn social_line_mapper_matches_pinned_input_and_result() {
    let expected = social_fixture();
    let server = Server::start(&json!({"userinfo": expected["profiles"][0]["profile"]})).await;
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let mut resolved = social_provider(&server).await;
    resolved
        .providers
        .get_mut("line")
        .unwrap()
        .config
        .map_profile_to_user = Some(Arc::new(SocialMapper(inputs.clone())));
    let response = super::super::handlers::fetch_user_info_from_provider(
        &resolved.providers["line"],
        OAuthUserInfoRequest {
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let user = response.user;
    let view = super::super::types::AccountInfoUser {
        id: None,
        name: user.name,
        email: user.email,
        image: user.image,
        email_verified: user.email_verified,
        additional_fields: user.additional_fields,
    };
    assert_eq!(json!(*inputs.lock().unwrap()), expected["mapperInputs"]);
    assert_eq!(
        json!({"user": view, "data": response.data}),
        expected["mappedResult"]
    );
}
