#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Integration fixtures fail immediately on invalid setup or changed protocol fields."
)]

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::plugins::oauth::{
    OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider, TokenEndpointAuth,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{AuthResult, HttpMethod, SchemaValue, UpdateAccount};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct ProviderState {
    profile: Value,
    profile_body: Option<Value>,
    events: Arc<Mutex<Vec<String>>>,
    token_requests: Arc<Mutex<Vec<TokenRequest>>>,
}

#[derive(Clone)]
struct TokenRequest {
    headers: HeaderMap,
    form: HashMap<String, String>,
}

async fn token(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    body: String,
) -> Json<Value> {
    state.events.lock().unwrap().push("token".into());
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let refresh = form
        .get("grant_type")
        .is_some_and(|value| value == "refresh_token");
    state
        .token_requests
        .lock()
        .unwrap()
        .push(TokenRequest { headers, form });
    if refresh {
        return Json(
            json!({"access_token":"refreshed-access","refresh_token":"rotated-refresh","expires_in":3600,"scope":"refreshed-scope","token_type":"Bearer"}),
        );
    }
    Json(
        json!({"access_token":"ordinary-access","refresh_token":"ordinary-refresh","expires_in":3600,"scope":"ordinary-scope","token_type":"Bearer"}),
    )
}

async fn profile(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    body: String,
) -> Json<Value> {
    assert_eq!(headers["authorization"], "Bearer ordinary-access");
    if let Some(expected) = &state.profile_body {
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), *expected);
    } else {
        assert!(body.is_empty());
    }
    state.events.lock().unwrap().push("profile".into());
    Json(state.profile)
}

struct Server {
    url: String,
    state: ProviderState,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(profile: Value, post_profile: bool, profile_body: Option<Value>) -> Self {
        let state = ProviderState {
            profile,
            profile_body,
            events: Default::default(),
            token_requests: Default::default(),
        };
        let router = Router::new()
            .route("/token", post(token))
            .route(
                "/profile",
                if post_profile {
                    post(self::profile)
                } else {
                    get(self::profile)
                },
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, state, task }
    }
}

struct Mapper(ProviderState, Value, Value);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile, &self.2);
        self.0.events.lock().unwrap().push("map".into());
        Ok(OAuthProfile {
            name: Some(serde_json::from_value(self.1["name"].clone())?),
            image: Some(serde_json::from_value(self.1["image"].clone())?),
            email_verified: self.1["emailVerified"].as_bool(),
            ..Default::default()
        })
    }
}

async fn auth(id: &str, provider: OAuthProvider) -> BetterAuth<BundledSchema> {
    let config = AuthConfig::new("ordinary-social-http-test-secret-more-than-32-characters")
        .base_url("http://app.example.test");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database))
        .plugin(OAuthPlugin::new().add_provider(id, provider))
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn social_code_exchange_and_profile_mapping_persist_through_sqlite() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/social-http-providers-1.7.6.json")).unwrap();
    let redirects: Value =
        serde_json::from_str(include_str!("fixtures/social-redirect-uri-1.7.6.json")).unwrap();
    for redirect in redirects["cases"].as_array().unwrap() {
        let providers = [
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
        ]
        .into_iter()
        .map(|id| (id, None));
        let cloudflare = fixture["providers"]["cloudflare"]["tokenAuthCases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| ("cloudflare", Some(case)));
        for (id, authentication) in providers.chain(cloudflare) {
            let case = &fixture["providers"][id];
            let profile = if id == "kick" {
                json!({"data": [case["profile"]]})
            } else if id == "linear" {
                json!({"data": {"viewer": case["profile"]}})
            } else if id == "cloudflare" {
                json!({"success": true, "result": case["profile"]})
            } else {
                case["profile"].clone()
            };
            let server = Server::start(
                profile,
                matches!(id, "dropbox" | "linear"),
                case.get("profileBody").cloned(),
            )
            .await;
            let mut provider = match id {
                "gitlab" => OAuthProvider::gitlab("social-http-client", "ordinary-client-secret"),
                "spotify" => OAuthProvider::spotify("social-http-client", "ordinary-client-secret"),
                "vercel" => OAuthProvider::vercel("social-http-client", "ordinary-client-secret"),
                "huggingface" => {
                    OAuthProvider::huggingface("social-http-client", "ordinary-client-secret")
                }
                "figma" => OAuthProvider::figma("social-http-client", "ordinary-client-secret"),
                "dropbox" => OAuthProvider::dropbox("social-http-client", "ordinary-client-secret"),
                "kick" => OAuthProvider::kick("social-http-client", "ordinary-client-secret"),
                "linkedin" => {
                    OAuthProvider::linkedin("social-http-client", "ordinary-client-secret")
                }
                "slack" => OAuthProvider::slack("social-http-client", "ordinary-client-secret"),
                "naver" => OAuthProvider::naver("social-http-client", "ordinary-client-secret"),
                "linear" => OAuthProvider::linear("social-http-client", "ordinary-client-secret"),
                "cloudflare" => {
                    OAuthProvider::cloudflare("social-http-client", "ordinary-client-secret")
                }
                _ => {
                    assert_eq!(id, "polar");
                    OAuthProvider::polar("social-http-client", "ordinary-client-secret")
                }
            };
            if let Some(authentication) = authentication {
                provider.client_secret = authentication["options"]["clientSecret"]
                    .as_str()
                    .unwrap_or_default()
                    .into();
                provider.token_endpoint_auth = authentication["options"]["tokenEndpointAuthMethod"]
                    .as_str()
                    .map(|method| {
                        [
                            ("client_secret_basic", TokenEndpointAuth::ClientSecretBasic),
                            ("client_secret_post", TokenEndpointAuth::ClientSecretPost),
                            ("none", TokenEndpointAuth::None),
                        ]
                        .into_iter()
                        .find(|(name, _)| *name == method)
                        .unwrap()
                        .1
                    });
            }
            provider.redirect_uri = redirect
                .get("configured")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let expected_redirect = provider
                .redirect_uri
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("http://app.example.test/api/auth/callback/{id}"));
            provider.token_url = format!("{}/token", server.url);
            provider.user_info_url = Some(format!("{}/profile", server.url));
            provider.map_profile_to_user = Some(Arc::new(Mapper(
                server.state.clone(),
                case["mapperPatch"].clone(),
                case["profile"].clone(),
            )));
            let auth = auth(id, provider).await;
            let mut sign_in = json!({"provider":id,"callbackURL":"http://app.example.test/welcome","disableRedirect":true});
            if matches!(id, "cloudflare" | "linkedin" | "slack" | "naver" | "linear") {
                sign_in["loginHint"] = json!("owner@example.test");
                sign_in["additionalParams"] = json!({"request_marker":"request-value"});
            }
            let start = auth
                .call_endpoint(
                    HttpMethod::Post,
                    "/sign-in/social",
                    EndpointInput {
                        body: Some(sign_in),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(start.status, 200);
            let body: Value = serde_json::from_slice(&start.body).unwrap();
            let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
            let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
            if matches!(id, "linkedin" | "slack" | "naver" | "linear") {
                assert!(!query.contains_key("code_challenge_method"));
                assert!(!query.contains_key("code_challenge"));
                if matches!(id, "linkedin" | "linear") {
                    assert_eq!(query["login_hint"], "owner@example.test");
                } else {
                    assert!(!query.contains_key("login_hint"));
                }
                assert_eq!(query["request_marker"], "request-value");
            } else {
                assert_eq!(query["code_challenge_method"], "S256");
            }
            assert_eq!(query["redirect_uri"], expected_redirect);
            if id == "cloudflare" {
                assert!(!query.contains_key("login_hint"));
                assert!(!query.contains_key("request_marker"));
            }
            let cookies = start
                .headers
                .get_all("set-cookie")
                .map(|cookie| cookie.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            assert!(!cookies.is_empty());
            let mut callback_query = json!({"code":"ordinary-code","state":query["state"]});
            if matches!(id, "cloudflare" | "linkedin" | "slack" | "naver" | "linear") {
                callback_query["device_id"] = json!("ordinary-device");
            }
            let callback = auth
                .call_endpoint(
                    HttpMethod::Get,
                    &format!("/callback/{id}"),
                    EndpointInput {
                        headers: Some(HashMap::from([("cookie".into(), cookies)])),
                        query: Some(callback_query),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(callback.status, 302);
            assert_eq!(
                callback.headers.get("location").map(String::as_str),
                Some("http://app.example.test/welcome")
            );
            assert!(
                callback
                    .headers
                    .get_all("set-cookie")
                    .any(|cookie| cookie.starts_with("better-auth.session_token="))
            );
            let user = auth
                .context()
                .database
                .get_user_by_email(case["defaultUser"]["email"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
            let value = serde_json::to_value(&user).unwrap();
            for field in ["name", "email", "image", "emailVerified"] {
                assert_eq!(value[field], case["mappedUser"][field], "{id}: {field}");
            }
            let accounts = auth
                .context()
                .database
                .get_user_accounts(&user.id.display_string().unwrap())
                .await
                .unwrap();
            assert_eq!(accounts.len(), 1);
            let account = serde_json::to_value(&accounts[0]).unwrap();
            let profile_fields = if id == "naver" {
                &case["profile"]["response"]
            } else {
                &case["profile"]
            };
            let subject_value = &profile_fields[case["subjectField"].as_str().unwrap()];
            let subject = subject_value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| subject_value.to_string());
            assert_eq!(account["accountId"], subject);
            assert_eq!(account["providerId"], id);
            assert_eq!(account["accessToken"], "ordinary-access");
            assert_eq!(account["refreshToken"], "ordinary-refresh");
            assert_eq!(account["scope"], "ordinary-scope");
            assert_eq!(
                *server.state.events.lock().unwrap(),
                ["token", "profile", "map"]
            );
            if id == "vercel" {
                let expired_at = chrono::Utc::now() - chrono::Duration::seconds(30);
                let _ = auth
                    .context()
                    .database
                    .update_account_optional(
                        account["id"].as_str().unwrap(),
                        UpdateAccount {
                            access_token_expires_at: SchemaValue::Typed(Some(expired_at)),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap()
                    .unwrap();
                let session_cookie = callback
                    .headers
                    .get_all("set-cookie")
                    .map(|cookie| cookie.split(';').next().unwrap())
                    .collect::<Vec<_>>()
                    .join("; ");
                let input = || EndpointInput {
                    headers: Some(HashMap::from([("cookie".into(), session_cookie.clone())])),
                    body: Some(json!({"accountId": account["id"]})),
                    ..Default::default()
                };
                let access = auth
                    .call_endpoint(HttpMethod::Post, "/get-access-token", input())
                    .await
                    .unwrap();
                assert_eq!(access.status, 200);
                let access: Value = serde_json::from_slice(&access.body).unwrap();
                assert_eq!(access["accessToken"], "ordinary-access");
                let refresh = auth
                    .call_endpoint(HttpMethod::Post, "/refresh-token", input())
                    .await
                    .unwrap_err()
                    .to_auth_response();
                assert_eq!(refresh.status, 400);
                let refresh: Value = serde_json::from_slice(&refresh.body).unwrap();
                assert_eq!(
                    refresh,
                    json!({
                        "code": "TOKEN_REFRESH_NOT_SUPPORTED",
                        "message": "Provider vercel does not support token refreshing."
                    })
                );
                let stored = auth
                    .context()
                    .database
                    .get_user_accounts(&user.id.display_string().unwrap())
                    .await
                    .unwrap();
                let stored = serde_json::to_value(&stored[0]).unwrap();
                assert_eq!(stored["accessToken"], account["accessToken"]);
                assert_eq!(stored["refreshToken"], account["refreshToken"]);
                assert_eq!(stored["scope"], account["scope"]);
                assert_eq!(
                    *server.state.events.lock().unwrap(),
                    ["token", "profile", "map"]
                );
            }
            let requests = server.state.token_requests.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            let form = &requests[0].form;
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["code"], "ordinary-code");
            if let Some(authentication) = authentication {
                let expected = &authentication["requests"][0];
                assert_eq!(
                    requests[0]
                        .headers
                        .get("authorization")
                        .map(|value| value.to_str().unwrap()),
                    expected["authorization"].as_str()
                );
                assert_eq!(
                    requests[0].headers["content-type"],
                    expected["contentType"].as_str().unwrap()
                );
                let mut expected_form: HashMap<String, String> =
                    serde_json::from_value(expected["body"].clone()).unwrap();
                let _ = expected_form.insert("redirect_uri".into(), expected_redirect.clone());
                let _ = expected_form.insert("code_verifier".into(), form["code_verifier"].clone());
                assert_eq!(*form, expected_form);
            } else if id == "figma" {
                assert_eq!(
                    requests[0].headers["authorization"],
                    case["tokenContract"]["authorization"].as_str().unwrap()
                );
                assert!(!form.contains_key("client_id"));
                assert!(!form.contains_key("client_secret"));
                assert_eq!(form.len(), 4);
            } else {
                assert_eq!(form["client_id"], "social-http-client");
                assert_eq!(form["client_secret"], "ordinary-client-secret");
                if matches!(id, "dropbox" | "kick") {
                    assert!(requests[0].headers.get("authorization").is_none());
                    assert_eq!(form.len(), 6);
                } else if matches!(id, "linkedin" | "slack" | "naver" | "linear") {
                    assert!(requests[0].headers.get("authorization").is_none());
                    assert_eq!(form.len(), 5);
                    assert!(!form.contains_key("device_id"));
                }
            }
            if matches!(id, "linkedin" | "slack" | "naver" | "linear") {
                assert!(!form.contains_key("code_verifier"));
            } else {
                assert!(!form["code_verifier"].is_empty());
            }
            assert_eq!(form["redirect_uri"], expected_redirect);
            if matches!(
                id,
                "figma"
                    | "dropbox"
                    | "kick"
                    | "linkedin"
                    | "slack"
                    | "naver"
                    | "linear"
                    | "cloudflare"
            ) {
                let cookies = callback
                    .headers
                    .get_all("set-cookie")
                    .map(|cookie| cookie.split(';').next().unwrap())
                    .collect::<Vec<_>>()
                    .join("; ");
                let refresh = auth
                    .call_endpoint(
                        HttpMethod::Post,
                        "/refresh-token",
                        EndpointInput {
                            body: Some(json!({"accountId":account["id"]})),
                            headers: Some(HashMap::from([("cookie".into(), cookies)])),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(refresh.status, 200);
                let body: Value = serde_json::from_slice(&refresh.body).unwrap();
                assert_eq!(body["accessToken"], "refreshed-access");
                assert_eq!(body["scope"], "ordinary-scope");
                let accounts = auth
                    .context()
                    .database
                    .get_user_accounts(&user.id.display_string().unwrap())
                    .await
                    .unwrap();
                let updated = serde_json::to_value(&accounts[0]).unwrap();
                assert_eq!(updated["accessToken"], "refreshed-access");
                assert_eq!(updated["refreshToken"], "rotated-refresh");
                assert_eq!(updated["scope"], "ordinary-scope");
                let requests = server.state.token_requests.lock().unwrap().clone();
                assert_eq!(requests.len(), 2);
                let mut expected_form = HashMap::from([
                    ("grant_type".into(), "refresh_token".into()),
                    ("refresh_token".into(), "ordinary-refresh".into()),
                ]);
                if let Some(authentication) = authentication {
                    let expected = &authentication["requests"][1];
                    assert_eq!(
                        requests[1]
                            .headers
                            .get("authorization")
                            .map(|value| value.to_str().unwrap()),
                        expected["authorization"].as_str()
                    );
                    assert_eq!(
                        requests[1].headers["content-type"],
                        expected["contentType"].as_str().unwrap()
                    );
                    expected_form = serde_json::from_value(expected["body"].clone()).unwrap();
                } else if id == "figma" {
                    assert_eq!(
                        requests[1].headers["authorization"],
                        case["tokenContract"]["authorization"].as_str().unwrap()
                    );
                } else {
                    assert!(requests[1].headers.get("authorization").is_none());
                    expected_form.extend([
                        ("client_id".into(), "social-http-client".into()),
                        ("client_secret".into(), "ordinary-client-secret".into()),
                    ]);
                }
                assert_eq!(requests[1].form, expected_form);
                assert_eq!(
                    *server.state.events.lock().unwrap(),
                    ["token", "profile", "map", "token"]
                );
            }
        }
    }
}
