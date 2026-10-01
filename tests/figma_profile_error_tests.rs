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
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use better_auth::plugins::oauth::{
    OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider, OAuthProxyPlugin, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthResult, HttpMethod};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const BASE_URL: &str = "http://figma-errors.example.test";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Http503,
    ApiFailure,
    MissingViewer,
    Mapper,
    Custom,
    ApiError,
}

#[derive(Clone)]
struct ProviderState {
    fixture: Value,
    token_contract: Value,
    provider_id: &'static str,
    failure: Arc<Mutex<Option<Failure>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

async fn token(State(state): State<ProviderState>, headers: HeaderMap) -> Json<Value> {
    if state.provider_id == "figma" {
        assert_eq!(
            headers["authorization"],
            state.token_contract["authorization"].as_str().unwrap()
        );
    }
    state.events.lock().unwrap().push("token");
    Json(state.token_contract["response"].clone())
}

async fn profile(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["authorization"], "Bearer figma-access-token");
    if state.provider_id == "linear" {
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            state.fixture["profileBody"]
        );
    } else {
        assert!(body.is_empty());
    }
    state.events.lock().unwrap().push("profile");
    let failure = *state.failure.lock().unwrap();
    if failure == Some(Failure::Http503) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"temporarily_unavailable"})),
        )
    } else if failure == Some(Failure::ApiFailure) {
        (
            StatusCode::OK,
            Json(json!({"resultcode":"99","message":"Temporarily unavailable"})),
        )
    } else if failure == Some(Failure::MissingViewer) {
        (StatusCode::OK, Json(json!({"data": {}})))
    } else if state.provider_id == "linear" {
        (
            StatusCode::OK,
            Json(json!({"data": {"viewer": state.fixture["profile"]}})),
        )
    } else {
        (StatusCode::OK, Json(state.fixture["profile"].clone()))
    }
}

struct Mapper(ProviderState);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile, &self.0.fixture["profile"]);
        self.0.events.lock().unwrap().push("map");
        if *self.0.failure.lock().unwrap() == Some(Failure::Mapper) {
            return Err(AuthError::Internal("Ordinary profile mapper failed".into()));
        }
        Ok(OAuthProfile::default())
    }
}

struct CustomProfile(ProviderState);

#[async_trait]
impl OAuthUserInfoHandler for CustomProfile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0.events.lock().unwrap().push("custom");
        if *self.0.failure.lock().unwrap() == Some(Failure::Custom) {
            return Err(better_auth_core::AuthError::internal(
                "Ordinary custom userinfo failed",
            ));
        }
        if *self.0.failure.lock().unwrap() == Some(Failure::ApiError) {
            return Err(AuthResponse::json(
                429,
                &json!({
                    "code": "PROFILE_BUSY", "message": "Profile service is busy", "retryAfter": 17,
                }),
            )?
            .with_header("retry-after", "17")
            .with_header("x-profile-error", "application")
            .into());
        }
        let user = &self.0.fixture["defaultUser"];
        let profile = self.0.fixture["profile"].clone();
        let subject_profile = if self.0.provider_id == "naver" {
            &profile["response"]
        } else {
            &profile
        };
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: subject_profile[self.0.fixture["subjectField"].as_str().unwrap()]
                    .as_str()
                    .unwrap()
                    .into(),
                email: Some(user["email"].as_str().unwrap().into()).into(),
                name: user["name"].as_str().map(str::to_owned),
                image: user
                    .get("image")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .unwrap(),
                email_verified: user["emailVerified"].as_bool().unwrap(),
                additional_fields: Default::default(),
            },
            data: profile,
        }))
    }
}

struct Fixture {
    auth: BetterAuth<BundledSchema>,
    database: DatabaseConnection,
    state: ProviderState,
    proxy: bool,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(provider_id: &'static str, custom: bool, proxy: bool) -> Self {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/social-http-providers-1.7.6.json"))
                .unwrap();
        let state = ProviderState {
            fixture: fixture["providers"][provider_id].clone(),
            token_contract: fixture["providers"]["figma"]["tokenContract"].clone(),
            provider_id,
            failure: Default::default(),
            events: Default::default(),
        };
        let router = Router::new()
            .route("/token", post(token))
            .route(
                "/profile",
                if provider_id == "linear" {
                    post(profile)
                } else {
                    get(profile)
                },
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let constructor = match provider_id {
            "figma" => OAuthProvider::figma,
            "slack" => OAuthProvider::slack,
            "naver" => OAuthProvider::naver,
            "linear" => OAuthProvider::linear,
            _ => {
                assert_eq!(provider_id, "polar");
                OAuthProvider::polar
            }
        };
        let mut provider = constructor(
            fixture["clientId"].as_str().unwrap(),
            fixture["clientSecret"].as_str().unwrap(),
        );
        provider.token_url = format!("{server_url}/token");
        provider.user_info_url = Some(format!("{server_url}/profile"));
        provider.map_profile_to_user = Some(Arc::new(Mapper(state.clone())));
        if custom {
            provider.get_user_info = Some(Arc::new(CustomProfile(state.clone())));
        }
        let config = AuthConfig::new("figma-public-error-test-secret-more-than-32-characters")
            .base_url(BASE_URL);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        let builder =
            AuthBuilder::<BundledSchema>::new(config.clone())
                .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()));
        let builder = if proxy {
            builder.plugin(
                OAuthProxyPlugin::new()
                    .current_url("http://preview.example.test".into())
                    .production_url(BASE_URL.into()),
            )
        } else {
            builder
        };
        let auth = builder
            .plugin(OAuthPlugin::new().add_provider(provider_id, provider))
            .build()
            .await
            .unwrap();
        Self {
            auth,
            database,
            state,
            proxy,
            server,
        }
    }

    async fn login(&self) -> AuthResponse {
        let mut sign_in = request(HttpMethod::Post, "/api/auth/sign-in/social");
        sign_in.headers = HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("origin".into(), BASE_URL.into()),
        ]);
        sign_in.body = Some(
            serde_json::to_vec(&json!({
                "provider":self.state.provider_id, "callbackURL":format!("{BASE_URL}/welcome"),
                "disableRedirect":true,
            }))
            .unwrap(),
        );
        let start = self.auth.handle_request(sign_in).await.unwrap();
        assert_eq!(start.status, 200);
        let body: Value = serde_json::from_slice(&start.body).unwrap();
        let authorization = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        if matches!(self.state.provider_id, "slack" | "naver" | "linear") {
            assert!(!query.contains_key("code_challenge_method"));
            assert!(!query.contains_key("code_challenge"));
        } else {
            assert_eq!(query["code_challenge_method"], "S256");
        }
        assert!(!query["state"].is_empty());
        if self.proxy {
            assert!(
                query["state"].len() > 100,
                "proxy must wrap ordinary OAuth state"
            );
        }
        let cookie = cookies(&start);
        assert!(!cookie.is_empty());
        let mut callback = request(
            HttpMethod::Get,
            &format!("/api/auth/callback/{}", self.state.provider_id),
        );
        callback.headers = HashMap::from([("cookie".into(), cookie)]);
        callback.query = Some(json!({"code":"ordinary-code", "state":query["state"]}));
        self.auth.handle_request(callback).await.unwrap()
    }

    async fn row_counts(&self) -> [i64; 3] {
        let row = self.database.query_one_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM accounts) AS accounts, (SELECT COUNT(*) FROM sessions) AS sessions".to_owned(),
        )).await.unwrap().unwrap();
        ["users", "accounts", "sessions"].map(|table| row.try_get("", table).unwrap())
    }
}

fn request(method: HttpMethod, path: &str) -> AuthRequest {
    AuthRequest::new(method, path).with_url(url::Url::parse(&format!("{BASE_URL}{path}")).unwrap())
}

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn callback_profile_failures_redirect_without_persisting_rows() {
    for failure in [Failure::Http503, Failure::Mapper] {
        let fixture = Fixture::new("figma", false, false).await;
        *fixture.state.failure.lock().unwrap() = Some(failure);
        let response = fixture.login().await;
        assert_eq!(response.status, 302, "{failure:?}");
        assert_eq!(
            response.headers.get("location").unwrap(),
            &format!("{BASE_URL}/api/auth/error?error=unable_to_get_user_info"),
            "{failure:?}"
        );
        assert_eq!(fixture.row_counts().await, [0, 0, 0], "{failure:?}");
        let expected: &[&str] = match failure {
            Failure::Http503 | Failure::ApiFailure | Failure::MissingViewer => {
                &["token", "profile"]
            }
            Failure::Mapper => &["token", "profile", "map"],
            Failure::Custom | Failure::ApiError => &["token", "custom"],
        };
        assert_eq!(fixture.state.events.lock().unwrap().as_slice(), expected);
    }
}

#[tokio::test]
async fn account_info_profile_failures_return_401_and_preserve_rows() {
    for failure in [Failure::Http503, Failure::Mapper] {
        let fixture = Fixture::new("figma", false, false).await;
        let login = fixture.login().await;
        assert_eq!(login.status, 302);
        assert_eq!(
            login.headers.get("location").unwrap(),
            &format!("{BASE_URL}/welcome")
        );
        assert_eq!(fixture.row_counts().await, [1, 1, 1]);
        assert_eq!(
            *fixture.state.events.lock().unwrap(),
            ["token", "profile", "map"]
        );
        let row = fixture
            .database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM accounts".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        let account_id: String = row.try_get("", "id").unwrap();
        fixture.state.events.lock().unwrap().clear();
        *fixture.state.failure.lock().unwrap() = Some(failure);
        let mut account_info = request(HttpMethod::Get, "/api/auth/account-info");
        account_info.headers = HashMap::from([("cookie".into(), cookies(&login))]);
        account_info.query = Some(json!({"accountId":account_id}));
        let response = fixture.auth.handle_request(account_info).await.unwrap();
        assert_eq!(response.status, 401, "{failure:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!({
                "code":"FAILED_TO_GET_USER_INFO", "message":"Failed to get user info",
            }),
            "{failure:?}"
        );
        assert_eq!(fixture.row_counts().await, [1, 1, 1], "{failure:?}");
        let expected: &[&str] = match failure {
            Failure::Http503 | Failure::ApiFailure | Failure::MissingViewer => &["profile"],
            Failure::Mapper => &["profile", "map"],
            Failure::Custom | Failure::ApiError => &["custom"],
        };
        assert_eq!(fixture.state.events.lock().unwrap().as_slice(), expected);
    }
}

#[tokio::test]
async fn social_callback_and_proxy_preserve_original_callback_errors() {
    for provider_id in ["figma", "polar", "slack", "naver", "linear"] {
        for proxy in [false, true] {
            for failure in [Failure::Http503, Failure::Mapper, Failure::Custom]
                .into_iter()
                .chain((provider_id == "naver").then_some(Failure::ApiFailure))
                .chain((provider_id == "linear").then_some(Failure::MissingViewer))
            {
                let fixture = Fixture::new(provider_id, failure == Failure::Custom, proxy).await;
                *fixture.state.failure.lock().unwrap() = Some(failure);
                let response = fixture.login().await;
                let missing = matches!(
                    failure,
                    Failure::Http503 | Failure::ApiFailure | Failure::MissingViewer
                ) || (provider_id == "figma" && failure == Failure::Mapper);
                if missing {
                    assert_eq!(
                        response.status, 302,
                        "{provider_id} {failure:?} proxy={proxy}"
                    );
                    assert_eq!(
                        response.headers.get("location").unwrap(),
                        &format!("{BASE_URL}/api/auth/error?error=unable_to_get_user_info")
                    );
                } else {
                    assert_eq!(
                        response.status, 500,
                        "{provider_id} {failure:?} proxy={proxy}"
                    );
                    assert!(response.body.is_empty());
                    assert!(response.headers.get("location").is_none());
                }
                assert_eq!(fixture.row_counts().await, [0, 0, 0]);
                let expected: &[&str] = match failure {
                    Failure::Http503 | Failure::ApiFailure | Failure::MissingViewer => {
                        &["token", "profile"]
                    }
                    Failure::Mapper => &["token", "profile", "map"],
                    Failure::Custom | Failure::ApiError => &["token", "custom"],
                };
                assert_eq!(fixture.state.events.lock().unwrap().as_slice(), expected);
            }
        }
    }
}

#[tokio::test]
async fn social_account_info_distinguishes_missing_profile_from_original_callback_errors() {
    for (provider_id, failure) in [
        ("polar", Failure::Http503),
        ("polar", Failure::Mapper),
        ("polar", Failure::Custom),
        ("figma", Failure::Custom),
        ("slack", Failure::Http503),
        ("slack", Failure::Mapper),
        ("slack", Failure::Custom),
        ("naver", Failure::Http503),
        ("naver", Failure::ApiFailure),
        ("naver", Failure::Mapper),
        ("naver", Failure::Custom),
        ("linear", Failure::Http503),
        ("linear", Failure::MissingViewer),
        ("linear", Failure::Mapper),
        ("linear", Failure::Custom),
    ] {
        let fixture = Fixture::new(provider_id, failure == Failure::Custom, false).await;
        let login = fixture.login().await;
        assert_eq!(login.status, 302);
        assert_eq!(fixture.row_counts().await, [1, 1, 1]);
        let row = fixture
            .database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM accounts".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        let account_id: String = row.try_get("", "id").unwrap();
        fixture.state.events.lock().unwrap().clear();
        *fixture.state.failure.lock().unwrap() = Some(failure);
        let mut account_info = request(HttpMethod::Get, "/api/auth/account-info");
        account_info.headers = HashMap::from([("cookie".into(), cookies(&login))]);
        account_info.query = Some(json!({"accountId":account_id}));
        let response = fixture.auth.handle_request(account_info).await.unwrap();
        if matches!(
            failure,
            Failure::Http503 | Failure::ApiFailure | Failure::MissingViewer
        ) {
            assert_eq!(response.status, 401);
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap(),
                json!({"code":"FAILED_TO_GET_USER_INFO","message":"Failed to get user info"})
            );
        } else {
            assert_eq!(response.status, 500);
            assert!(response.body.is_empty());
        }
        assert_eq!(fixture.row_counts().await, [1, 1, 1]);
        let expected: &[&str] = match failure {
            Failure::Http503 | Failure::ApiFailure | Failure::MissingViewer => &["profile"],
            Failure::Mapper => &["profile", "map"],
            Failure::Custom | Failure::ApiError => &["custom"],
        };
        assert_eq!(fixture.state.events.lock().unwrap().as_slice(), expected);
    }
}

#[tokio::test]
async fn userinfo_api_errors_preserve_status_body_and_headers_on_social_endpoints() {
    for provider_id in ["figma", "polar", "slack", "naver", "linear"] {
        for endpoint in ["callback", "proxy", "account-info"] {
            let fixture = Fixture::new(provider_id, true, endpoint == "proxy").await;
            let response = if endpoint == "account-info" {
                let login = fixture.login().await;
                assert_eq!(login.status, 302);
                assert_eq!(fixture.row_counts().await, [1, 1, 1]);
                let row = fixture
                    .database
                    .query_one_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        "SELECT id FROM accounts".to_owned(),
                    ))
                    .await
                    .unwrap()
                    .unwrap();
                let account_id: String = row.try_get("", "id").unwrap();
                fixture.state.events.lock().unwrap().clear();
                *fixture.state.failure.lock().unwrap() = Some(Failure::ApiError);
                let mut request = request(HttpMethod::Get, "/api/auth/account-info");
                request.headers = HashMap::from([("cookie".into(), cookies(&login))]);
                request.query = Some(json!({"accountId": account_id}));
                fixture.auth.handle_request(request).await.unwrap()
            } else {
                *fixture.state.failure.lock().unwrap() = Some(Failure::ApiError);
                fixture.login().await
            };
            assert_eq!(response.status, 429, "{provider_id} {endpoint}");
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap(),
                json!({
                    "code": "PROFILE_BUSY", "message": "Profile service is busy", "retryAfter": 17,
                })
            );
            assert_eq!(
                response.headers.get("retry-after").map(String::as_str),
                Some("17")
            );
            assert_eq!(
                response.headers.get("x-profile-error").map(String::as_str),
                Some("application")
            );
            assert!(response.headers.get("location").is_none());
            assert_eq!(
                fixture.row_counts().await,
                if endpoint == "account-info" {
                    [1, 1, 1]
                } else {
                    [0, 0, 0]
                }
            );
            let expected: &[&str] = if endpoint == "account-info" {
                &["custom"]
            } else {
                &["token", "custom"]
            };
            assert_eq!(fixture.state.events.lock().unwrap().as_slice(), expected);
        }
    }
}
