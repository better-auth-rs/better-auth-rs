#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Ordinary contract fixtures fail immediately on invalid setup or changed output."
)]

use super::*;
use better_auth_core::{AuthError, SchemaValue};
use serde_json::{Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/paypal-1.7.6.json"
    ))
    .unwrap()
}
fn configured(options: &Value) -> OAuthProvider {
    let fixture = fixture();
    let metadata = &fixture["metadata"];
    let client = options["clientId"]
        .as_str()
        .unwrap_or(metadata["clientId"].as_str().unwrap());
    let secret = options["clientSecret"]
        .as_str()
        .unwrap_or(metadata["clientSecret"].as_str().unwrap());
    let mut config = if options["environment"] == "live" {
        OAuthProvider::paypal_live(client, secret)
    } else {
        OAuthProvider::paypal(client, secret)
    };
    config.scopes = options
        .get("scope")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .unwrap();
    config.disable_default_scope = options["disableDefaultScope"].as_bool().unwrap_or(false);
    config.prompt = options["prompt"].as_str().map(str::to_owned);
    config.redirect_uri = options["redirectURI"].as_str().map(str::to_owned);
    config
}
fn resolved(config: OAuthProvider) -> resolved::ResolvedProvider {
    resolved::ResolvedProvider {
        config: config.resolve(),
        generic: None,
    }
}
fn public_response(response: OAuthUserInfoResponse) -> Value {
    json!({"user": types::AccountInfoUser { id: None, name: response.user.name, email: response.user.email, image: response.user.image, email_verified: response.user.email_verified, additional_fields: response.user.additional_fields }, "data": response.data})
}

#[test]
fn paypal_authorization_matches_every_captured_url_and_credential_error() {
    use base64::Engine;
    use sha2::Digest;
    let fixture = fixture();
    for sample in fixture["scopeCases"].as_array().unwrap() {
        let input = &sample["input"];
        let scopes: Option<Vec<String>> = input
            .get("scopes")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .unwrap();
        let extra: Option<indexmap::IndexMap<String, String>> = input
            .get("additionalParams")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .unwrap();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            sha2::Sha256::digest(input["codeVerifier"].as_str().unwrap()),
        );
        let url = authorization::build_authorization_url(
            &resolved(configured(&sample["options"])),
            authorization::AuthorizationRequest {
                callback_url: input["redirectURI"].as_str().unwrap(),
                scopes: scopes.as_deref(),
                state: input["state"].as_str().unwrap(),
                code_challenge: &challenge,
                login_hint: input["loginHint"].as_str(),
                nonce: input["idTokenNonce"].as_str(),
                additional_params: extra.as_ref(),
            },
        )
        .unwrap();
        assert_eq!(url, sample["url"].as_str().unwrap(), "{}", sample["name"]);
    }
    for sample in fixture["configErrors"].as_array().unwrap() {
        let error = authorization::build_authorization_url(
            &resolved(configured(&sample["options"])),
            authorization::AuthorizationRequest {
                callback_url: fixture["metadata"]["redirectURI"].as_str().unwrap(),
                scopes: None,
                state: "ordinary-state",
                code_challenge: "challenge",
                login_hint: None,
                nonce: None,
                additional_params: None,
            },
        )
        .unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message == sample["error"].as_str().unwrap())
        );
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
    async fn start(profile: Value, status: u16, events: Arc<Mutex<Vec<String>>>) -> Self {
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
                let mut body = vec![
                    0;
                    headers
                        .get("content-length")
                        .map(|v| v.parse::<usize>().unwrap())
                        .unwrap_or(0)
                ];
                let _ = socket.read_exact(&mut body).await.unwrap();
                let body = String::from_utf8(body).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                let token = path == "/v1/oauth2/token";
                let refresh = body.contains("grant_type=refresh_token");
                captured.lock().unwrap().push(json!({"path":path,"method":method,"authorization":headers.get("authorization"),"contentType":headers.get("content-type"),"accept":headers.get("accept"),"body":body}));
                events.lock().unwrap().push(
                    if token {
                        if refresh { "refresh" } else { "code" }
                    } else {
                        "profile"
                    }
                    .into(),
                );
                let data = if token {
                    fixture()[if refresh {
                        "refreshResponse"
                    } else {
                        "codeResponse"
                    }]
                    .clone()
                } else {
                    profile.clone()
                };
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
    fn config(&self) -> OAuthProvider {
        let mut config = configured(&json!({}));
        config.token_url = format!("{}/v1/oauth2/token", self.url);
        config.user_info_url = Some(format!("{}/v1/identity/oauth2/userinfo", self.url));
        config
    }
}

fn token_value(tokens: OAuthTokenSet) -> Value {
    let mut value = json!({"scopes":tokens.scopes});
    for (key, field) in [
        ("tokenType", tokens.token_type),
        ("accessToken", tokens.access_token),
        ("refreshToken", tokens.refresh_token),
        ("idToken", tokens.id_token),
    ] {
        if let Some(field) = field {
            value[key] = json!(field);
        }
    }
    if let Some(raw) = tokens.raw {
        value["raw"] = raw;
    }
    value
}

#[tokio::test]
async fn paypal_grants_match_basic_requests_results_and_default_error_mapping() {
    let fixture = fixture();
    for sample in fixture["grants"].as_array().unwrap() {
        let server = Server::start(
            Value::Null,
            sample["status"].as_u64().unwrap() as u16,
            Default::default(),
        )
        .await;
        let provider = resolved(server.config());
        let result = if sample["grant"] == "code" {
            provider_tokens::validate_authorization_code_via_provider(
                &provider,
                "ordinary-code",
                fixture["metadata"]["redirectURI"].as_str().unwrap(),
                Some(fixture["metadata"]["codeVerifier"].as_str().unwrap()),
                Some("ignored-device"),
            )
            .await
        } else {
            provider_tokens::refresh_tokens_via_provider(
                &provider,
                "ordinary-refresh",
                &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
            )
            .await
        };
        assert_eq!(
            *server.requests.lock().unwrap(),
            sample["requests"].as_array().unwrap().clone()
        );
        if sample["status"] == 200 {
            assert_eq!(token_value(result.unwrap()), sample["result"]);
        } else {
            assert!(
                matches!(result,Err(AuthError::Internal(message)) if message==sample["error"].as_str().unwrap())
            );
        }
    }
}

struct Mapper {
    patch: Value,
    seen: Arc<Mutex<Vec<Value>>>,
    events: Arc<Mutex<Vec<String>>>,
    error: Option<String>,
}
#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.seen.lock().unwrap().push(profile.clone());
        self.events.lock().unwrap().push("mapper".into());
        tokio::task::yield_now().await;
        if let Some(error) = &self.error {
            return Err(AuthError::internal(error.clone()));
        }
        let mut extra = self.patch.as_object().cloned().unwrap_or_default();
        for key in ["name", "email", "image", "emailVerified"] {
            let _ = extra.remove(key);
        }
        Ok(OAuthProfile {
            name: self
                .patch
                .get("name")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email: self
                .patch
                .get("email")
                .cloned()
                .map(|v| SchemaValue::from_json(Some(v))),
            image: self
                .patch
                .get("image")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email_verified: self
                .patch
                .get("emailVerified")
                .cloned()
                .map(|v| SchemaValue::from_json(Some(v))),
            additional_fields: extra,
            ..Default::default()
        })
    }
}
struct Verifier {
    verifier: oidc::OidcVerifier,
    events: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl OAuthIdTokenVerifier for Verifier {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String> {
        self.events.lock().unwrap().push("verify".into());
        self.verifier
            .verify(token, nonce)
            .await
            .map(|_| true)
            .map_err(|error| error.to_string())
    }
}
async fn signing_fixture(
    events: Arc<Mutex<Vec<String>>>,
) -> (google_test_support::GoogleFixture, Arc<Verifier>) {
    let data = fixture();
    let issuer = "https://ordinary-verifier.example.test";
    let signed = google_test_support::GoogleFixture::start(
        json!({"iss":issuer,"aud":data["metadata"]["clientId"],"sub":data["profile"]["sub"]}),
    )
    .await;
    let verifier = Arc::new(Verifier {
        verifier: oidc::OidcVerifier::with_policy(
            format!("{}/jwks", signed.url).parse().unwrap(),
            issuer.into(),
            vec![data["metadata"]["clientId"].as_str().unwrap().into()],
            Some(vec![json!("RS256")]),
            None,
        )
        .unwrap(),
        events,
    });
    (signed, verifier)
}

#[tokio::test]
async fn paypal_profiles_preserve_http_data_mapping_and_optional_verified_token() {
    let fixture = fixture();
    for sample in fixture["profileCases"].as_array().unwrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(
            sample["profile"].clone(),
            sample["status"].as_u64().unwrap_or(200) as u16,
            events.clone(),
        )
        .await;
        let mut config = server.config();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            patch: sample["patch"].clone(),
            seen: seen.clone(),
            events: events.clone(),
            error: None,
        }));
        let signed = if sample["idToken"] == true {
            let (signed, verifier) = signing_fixture(events.clone()).await;
            config.verify_id_token = Some(verifier);
            Some(signed)
        } else {
            None
        };
        let result = social_profile::fetch_user_info_for_code(
            &resolved(config),
            OAuthUserInfoRequest {
                access_token: (sample["missingAccess"] != true).then(|| "ordinary-access".into()),
                id_token: signed.as_ref().map(|s| s.token.clone()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            result.map(public_response).unwrap_or(Value::Null),
            sample["result"],
            "{}",
            sample["name"]
        );
        assert_eq!(
            *server.requests.lock().unwrap(),
            sample["requests"].as_array().unwrap().clone()
        );
        assert_eq!(
            *seen.lock().unwrap(),
            sample
                .get("mapperProfile")
                .cloned()
                .into_iter()
                .collect::<Vec<_>>()
        );
        if signed.is_some() {
            assert_eq!(*events.lock().unwrap(), ["profile", "verify", "mapper"]);
        }
    }
}

#[tokio::test]
async fn paypal_explicit_verifier_runs_once_for_direct_and_stored_profile_reads() {
    for entry in ["direct", "account"] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(fixture()["profile"].clone(), 200, events.clone()).await;
        let (signed, verifier) = signing_fixture(events.clone()).await;
        let mut config = server.config();
        config.verify_id_token = Some(verifier);
        let provider = resolved(config);
        let request = OAuthUserInfoRequest {
            access_token: Some("ordinary-access".into()),
            id_token: Some(signed.token.clone()),
            ..Default::default()
        };
        let result = if entry == "direct" {
            let verified = id_token::verify(
                &provider,
                &types::OAuthIdTokenRequest {
                    token: signed.token.clone(),
                    nonce: None,
                    access_token: Some("ordinary-access".into()),
                    refresh_token: None,
                    user: None,
                },
            )
            .await
            .unwrap();
            social_profile::fetch_user_info_with_claims(&provider, request, None, verified).await
        } else {
            social_profile::fetch_user_info_from_provider(&provider, request, None).await
        }
        .unwrap()
        .unwrap();
        assert_eq!(
            public_response(result),
            fixture()["profileCases"][0]["result"]
        );
        assert_eq!(
            *events.lock().unwrap(),
            if entry == "direct" {
                vec!["verify", "profile"]
            } else {
                vec!["profile", "verify"]
            }
        );
    }
}

#[tokio::test]
async fn paypal_optional_token_requires_the_explicit_application_verifier() {
    let server = Server::start(fixture()["profile"].clone(), 200, Default::default()).await;
    let (signed, _) = signing_fixture(Default::default()).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut config = server.config();
    config.map_profile_to_user = Some(Arc::new(Mapper {
        patch: Value::Null,
        seen: seen.clone(),
        events: Default::default(),
        error: None,
    }));
    let response = social_profile::fetch_user_info_for_code(
        &resolved(config),
        OAuthUserInfoRequest {
            access_token: Some("ordinary-access".into()),
            id_token: Some(signed.token.clone()),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    assert!(response.is_none());
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

struct Custom(String);
#[async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        if self.0.ends_with("error") {
            return Err(AuthError::internal(format!("Ordinary PayPal {}", self.0)));
        }
        if self.0.ends_with("null") {
            return Ok(None);
        }
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "paypal-owner".into(),
                name: Some("Custom Owner".into()),
                email: Some("custom-paypal@example.test".into()).into(),
                image: None,
                email_verified: Default::default(),
                additional_fields: Default::default(),
            },
            data: fixture()["profile"].clone(),
        }))
    }
}
#[async_trait]
impl OAuthRefreshTokenHandler for Custom {
    async fn refresh_access_token(&self, _token: &str) -> Result<OAuthTokenSet, String> {
        if self.0.ends_with("error") {
            return Err(format!("Ordinary PayPal {}", self.0));
        }
        Ok(OAuthTokenSet {
            access_token: Some("custom-access".into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn paypal_default_mapper_catch_and_custom_callbacks_keep_distinct_errors() {
    for sample in fixture()["specialCases"].as_array().unwrap() {
        let mode = sample["mode"].as_str().unwrap();
        let events = Default::default();
        let server = Server::start(fixture()["profile"].clone(), 200, events).await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = server.config();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            patch: Value::Null,
            seen: seen.clone(),
            events: Default::default(),
            error: Some(format!("Ordinary PayPal {mode}")),
        }));
        let result = if mode.starts_with("custom refresh") {
            config.refresh_access_token = Some(Arc::new(Custom(mode.into())));
            provider_tokens::refresh_tokens_via_provider(
                &resolved(config),
                "ordinary-refresh",
                &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
            )
            .await
            .map(token_value)
        } else {
            if mode.starts_with("custom") {
                config.get_user_info = Some(Arc::new(Custom(mode.into())));
            }
            social_profile::fetch_user_info_for_code(
                &resolved(config),
                OAuthUserInfoRequest {
                    access_token: Some("ordinary-access".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .map(|result| result.map(public_response).unwrap_or(Value::Null))
        };
        if let Some(error) = sample.get("error") {
            assert!(
                matches!(result,Err(AuthError::Internal(message)) if message==error["message"].as_str().unwrap())
            );
        } else {
            assert_eq!(result.unwrap(), sample["result"]);
        }
        assert_eq!(
            *server.requests.lock().unwrap(),
            sample["requests"].as_array().unwrap().clone()
        );
        assert_eq!(
            seen.lock().unwrap().len(),
            usize::from(mode == "mapper error")
        );
    }
}
