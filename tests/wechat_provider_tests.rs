#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Integration fixtures fail immediately on invalid setup or changed protocol fields."
)]

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{OriginalUri, Query, State},
    http::HeaderMap,
    routing::get,
};
use better_auth::plugins::oauth::{OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider};
use better_auth::{AuthBuilder, AuthConfig, server_api::EndpointInput};
use better_auth_core::{AuthResponse, AuthResult, HttpMethod};
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

fn named<'a>(cases: &'a Value, name: &str) -> &'a Value {
    cases
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

#[derive(Clone)]
struct ProviderState {
    fixture: Arc<Value>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

async fn provider_response(
    State(state): State<ProviderState>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: String,
) -> Json<Value> {
    let (event, sample, response) = match uri.path() {
        "/sns/oauth2/access_token" => {
            let sample = named(&state.fixture["grants"], "code");
            ("code", sample, &sample["rawResponse"])
        }
        "/sns/oauth2/refresh_token" => {
            let sample = named(&state.fixture["grants"], "refresh");
            ("refresh", sample, &sample["rawResponse"])
        }
        _ => {
            assert_eq!(uri.path(), "/sns/userinfo");
            let sample = named(&state.fixture["profileCases"], "mapped email");
            ("profile", sample, &sample["profile"])
        }
    };
    let expected = &sample["requests"][0];
    let expected_url = url::Url::parse(expected["url"].as_str().unwrap()).unwrap();
    let expected_query: HashMap<String, String> = expected_url.query_pairs().into_owned().collect();
    assert_eq!(query, expected_query, "{event}");
    assert_eq!(body, expected["body"].as_str().unwrap(), "{event}");
    assert_eq!(
        headers
            .get("authorization")
            .map(|header| header.to_str().unwrap()),
        expected["authorization"].as_str(),
        "{event}"
    );
    state.events.lock().unwrap().push(event);
    Json(response.clone())
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
    async fn start(fixture: Value) -> Self {
        let state = ProviderState {
            fixture: Arc::new(fixture),
            events: Default::default(),
        };
        let router = Router::new()
            .route("/sns/oauth2/access_token", get(provider_response))
            .route("/sns/oauth2/refresh_token", get(provider_response))
            .route("/sns/userinfo", get(provider_response))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, state, task }
    }
}

struct Mapper(ProviderState);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        let sample = named(&self.0.fixture["profileCases"], "mapped email");
        assert_eq!(profile, &sample["mapperProfile"]);
        self.0.events.lock().unwrap().push("mapper");
        Ok(OAuthProfile {
            email: Some(serde_json::from_value(
                sample["mapperPatch"]["email"].clone(),
            )?),
            name: Some(serde_json::from_value(
                sample["mapperPatch"]["name"].clone(),
            )?),
            ..Default::default()
        })
    }
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
async fn wechat_login_saved_account_info_and_refresh_use_normal_sqlite_lifecycle() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/wechat-1.7.6.json")).unwrap();
    let server = Server::start(fixture).await;
    let fixture = &server.state.fixture;
    let sample = named(&fixture["profileCases"], "mapped email");
    let code = named(&fixture["grants"], "code");
    let refresh = named(&fixture["grants"], "refresh");
    let mut provider = OAuthProvider::wechat_with_endpoints(
        fixture["metadata"]["clientId"].as_str().unwrap(),
        fixture["metadata"]["clientSecret"].as_str().unwrap(),
        &format!("{}/authorize", server.url),
        &format!("{}/sns/oauth2/access_token", server.url),
        &format!("{}/sns/oauth2/refresh_token", server.url),
        &format!("{}/sns/userinfo", server.url),
    );
    provider.map_profile_to_user = Some(Arc::new(Mapper(server.state.clone())));
    let config = AuthConfig::new("ordinary-wechat-sqlite-test-secret-more-than-32-characters")
        .base_url("http://app.example.test");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database))
        .plugin(OAuthPlugin::new().add_provider("wechat", provider))
        .build()
        .await
        .unwrap();
    let start = auth
        .call_endpoint(
            HttpMethod::Post,
            "/sign-in/social",
            EndpointInput {
                body: Some(json!({
                    "provider":"wechat",
                    "callbackURL":"http://app.example.test/welcome",
                    "disableRedirect":true,
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(start.status, 200);
    let start_body: Value = serde_json::from_slice(&start.body).unwrap();
    let url = url::Url::parse(start_body["url"].as_str().unwrap()).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let callback = auth
        .call_endpoint(
            HttpMethod::Get,
            "/callback/wechat",
            EndpointInput {
                query: Some(json!({"code":code["input"]["code"],"state":query["state"]})),
                headers: Some(HashMap::from([("cookie".into(), cookies(&start))])),
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
    let email = sample["result"]["user"]["email"].as_str().unwrap();
    let user = auth
        .context()
        .database
        .get_user_by_email(email)
        .await
        .unwrap()
        .unwrap();
    let stored_user = serde_json::to_value(&user).unwrap();
    for field in ["name", "email", "image", "emailVerified"] {
        assert_eq!(
            stored_user[field], sample["result"]["user"][field],
            "{field}"
        );
    }
    let user_id = user.id.display_string().unwrap();
    let accounts = auth
        .context()
        .database
        .get_user_accounts(&user_id)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    let account = serde_json::to_value(&accounts[0]).unwrap();
    assert_eq!(account["providerId"], "wechat");
    assert_eq!(account["accountId"], sample["profile"]["unionid"]);
    assert_eq!(account["accessToken"], code["response"]["accessToken"]);
    assert_eq!(account["refreshToken"], code["response"]["refreshToken"]);
    let scopes: Vec<String> = serde_json::from_value(code["response"]["scopes"].clone()).unwrap();
    assert_eq!(account["scope"], scopes.join(","));
    assert_eq!(
        *server.state.events.lock().unwrap(),
        ["code", "profile", "mapper"]
    );

    let session_cookie = cookies(&callback);
    let info = auth
        .call_endpoint(
            HttpMethod::Get,
            "/account-info",
            EndpointInput {
                query: Some(json!({"accountId":account["id"]})),
                headers: Some(HashMap::from([("cookie".into(), session_cookie.clone())])),
                ..Default::default()
            },
        )
        .await
        .unwrap_err()
        .to_auth_response();
    assert_eq!(info.status, 401);
    assert_eq!(
        serde_json::from_slice::<Value>(&info.body).unwrap(),
        json!({"code":"FAILED_TO_GET_USER_INFO","message":"Failed to get user info"})
    );
    assert_eq!(
        *server.state.events.lock().unwrap(),
        ["code", "profile", "mapper"]
    );
    assert_eq!(
        serde_json::to_value(
            auth.context()
                .database
                .get_user_accounts(&user_id)
                .await
                .unwrap()
        )
        .unwrap(),
        json!([account])
    );
    assert_eq!(
        serde_json::to_value(
            auth.context()
                .database
                .get_user_by_email(email)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        stored_user
    );

    let response = auth
        .call_endpoint(
            HttpMethod::Post,
            "/refresh-token",
            EndpointInput {
                body: Some(json!({"accountId":account["id"]})),
                headers: Some(HashMap::from([("cookie".into(), session_cookie)])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let response: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response["accessToken"], refresh["response"]["accessToken"]);
    assert_eq!(
        response["refreshToken"],
        refresh["response"]["refreshToken"]
    );
    assert_eq!(response["scope"], account["scope"]);
    let accounts = auth
        .context()
        .database
        .get_user_accounts(&user_id)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    let updated = serde_json::to_value(&accounts[0]).unwrap();
    for field in ["id", "userId", "accountId", "providerId", "scope"] {
        assert_eq!(updated[field], account[field], "{field}");
    }
    assert_eq!(updated["accessToken"], refresh["response"]["accessToken"]);
    assert_eq!(updated["refreshToken"], refresh["response"]["refreshToken"]);
    assert_eq!(
        *server.state.events.lock().unwrap(),
        ["code", "profile", "mapper", "refresh"]
    );
}
