#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Local integration fixtures fail immediately on invalid setup or changed protocol fields."
)]

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use better_auth::plugins::oauth::{
    OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth::{AuthBuilder, AuthConfig, server_api::EndpointInput};
use better_auth_core::{AuthError, AuthResponse, AuthResult, HttpMethod};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

#[derive(Clone)]
struct ProviderState {
    fixture: Arc<Value>,
    requests: Arc<Mutex<Vec<Value>>>,
    profile_status: Arc<AtomicU16>,
    mapper_error: Arc<AtomicBool>,
}

async fn provider_response(
    State(state): State<ProviderState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    state.requests.lock().unwrap().push(json!({"path":uri.to_string(),"body":body,"authorization":headers.get("authorization").map(|h|h.to_str().unwrap()),"accept":headers.get("accept").map(|h|h.to_str().unwrap()),"contentType":headers.get("content-type").map(|h|h.to_str().unwrap())}));
    if uri.path() == "/v1/oauth2/token" {
        let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        let key = if form["grant_type"] == "refresh_token" {
            "refreshResponse"
        } else {
            "codeResponse"
        };
        (StatusCode::OK, Json(state.fixture[key].clone()))
    } else {
        (
            StatusCode::from_u16(state.profile_status.load(Ordering::SeqCst)).unwrap(),
            Json(state.fixture["profile"].clone()),
        )
    }
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
    async fn start() -> Self {
        let state = ProviderState {
            fixture: Arc::new(
                serde_json::from_str(include_str!("fixtures/paypal-1.7.6.json")).unwrap(),
            ),
            requests: Default::default(),
            profile_status: Arc::new(AtomicU16::new(200)),
            mapper_error: Default::default(),
        };
        let router = Router::new()
            .route("/v1/oauth2/token", post(provider_response))
            .route("/v1/identity/oauth2/userinfo", get(provider_response))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, state, task }
    }
    fn provider(&self) -> OAuthProvider {
        let mut provider = OAuthProvider::paypal(
            self.state.fixture["metadata"]["clientId"].as_str().unwrap(),
            self.state.fixture["metadata"]["clientSecret"]
                .as_str()
                .unwrap(),
        );
        provider.token_url = format!("{}/v1/oauth2/token", self.url);
        provider.user_info_url = Some(format!("{}/v1/identity/oauth2/userinfo", self.url));
        provider.map_profile_to_user = Some(Arc::new(Mapper(self.state.clone())));
        provider
    }
}
struct Mapper(ProviderState);
#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile, &self.0.fixture["profile"]);
        if self.0.mapper_error.load(Ordering::SeqCst) {
            return Err(AuthError::internal("ordinary PayPal mapper failure"));
        }
        Ok(OAuthProfile::default())
    }
}
struct CustomError;
#[async_trait]
impl OAuthUserInfoHandler for CustomError {
    async fn get_user_info(
        &self,
        _request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        Err(AuthError::Upstream {
            status: 418,
            code: "ORDINARY_APPLICATION_ERROR",
            message: "Ordinary PayPal custom handler failure",
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
async fn paypal_code_account_info_and_refresh_use_the_complete_sqlite_dispatcher() {
    let server = Server::start().await;
    let config = AuthConfig::new("ordinary-paypal-sqlite-secret-at-least-32-characters")
        .base_url("http://app.example.test");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(
            config.clone(),
            database.clone(),
        ))
        .plugin(OAuthPlugin::new().add_provider("paypal", server.provider()))
        .build()
        .await
        .unwrap();
    let start=auth.call_endpoint(HttpMethod::Post,"/sign-in/social",EndpointInput {body:Some(json!({"provider":"paypal","callbackURL":"http://app.example.test/welcome","disableRedirect":true})),..Default::default()}).await.unwrap();
    assert_eq!(start.status, 200);
    let state_cookie = cookies(&start);
    assert!(!state_cookie.is_empty());
    let body: Value = serde_json::from_slice(&start.body.bytes().unwrap()).unwrap();
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(!query["code_challenge"].is_empty());
    assert!(!query.contains_key("scope"));
    let callback = auth
        .call_endpoint(
            HttpMethod::Get,
            "/callback/paypal",
            EndpointInput {
                query: Some(json!({"code":"ordinary-code","state":query["state"]})),
                headers: Some(HashMap::from([("cookie".into(), state_cookie)])),
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
    let session_cookie = cookies(&callback);
    let fixture = &server.state.fixture;
    let profile = &fixture["profile"];
    let expected = &fixture["profileCases"][0]["result"];
    let user = auth
        .context()
        .database
        .get_user_by_email(profile["email"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    let user_id = user.id.display_string().unwrap();
    let stored = serde_json::to_value(user).unwrap();
    for field in ["name", "email", "image", "emailVerified"] {
        assert_eq!(stored[field], expected["user"][field]);
    }
    let accounts = auth
        .context()
        .database
        .get_user_accounts(&user_id)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    let account = serde_json::to_value(&accounts[0]).unwrap();
    assert_eq!(account["providerId"], "paypal");
    assert_eq!(account["accountId"], profile["user_id"]);
    assert_eq!(
        account["accessToken"],
        fixture["codeResponse"]["access_token"]
    );
    assert_eq!(
        account["refreshToken"],
        fixture["codeResponse"]["refresh_token"]
    );
    let info_input = || EndpointInput {
        query: Some(json!({"accountId":account["id"]})),
        headers: Some(HashMap::from([("cookie".into(), session_cookie.clone())])),
        ..Default::default()
    };
    let info = auth
        .call_endpoint(HttpMethod::Get, "/account-info", info_input())
        .await
        .unwrap();
    assert_eq!(info.status, 200);
    let info: Value = serde_json::from_slice(&info.body.bytes().unwrap()).unwrap();
    assert_eq!(info["user"], expected["user"]);
    assert_eq!(info["data"], expected["data"]);
    let refresh = auth
        .call_endpoint(
            HttpMethod::Post,
            "/refresh-token",
            EndpointInput {
                body: Some(json!({"accountId":account["id"]})),
                headers: Some(HashMap::from([("cookie".into(), session_cookie.clone())])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(refresh.status, 200);
    let refreshed: Value = serde_json::from_slice(&refresh.body.bytes().unwrap()).unwrap();
    let updated = auth
        .context()
        .database
        .get_user_accounts(&user_id)
        .await
        .unwrap();
    assert_eq!(updated.len(), 1);
    let updated = serde_json::to_value(&updated[0]).unwrap();
    for (field, wire) in [
        ("accessToken", "access_token"),
        ("refreshToken", "refresh_token"),
    ] {
        assert_eq!(refreshed[field], fixture["refreshResponse"][wire]);
        assert_eq!(updated[field], fixture["refreshResponse"][wire]);
    }
    for field in ["id", "userId", "accountId", "providerId", "scope"] {
        assert_eq!(updated[field], account[field]);
    }
    let requests = server.state.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 4);
    let grant = &fixture["grants"][0]["requests"][0];
    let form: HashMap<String, String> =
        url::form_urlencoded::parse(requests[0]["body"].as_str().unwrap().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(form.len(), 4);
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "ordinary-code");
    assert_eq!(form["redirect_uri"], query["redirect_uri"]);
    assert!(!form["code_verifier"].is_empty());
    assert_eq!(requests[0]["authorization"], grant["authorization"]);
    assert_eq!(requests[0]["contentType"], grant["contentType"]);
    for request in &requests[1..3] {
        assert_eq!(
            request["path"],
            "/v1/identity/oauth2/userinfo?schema=paypalv1.1"
        );
        assert_eq!(request["authorization"], "Bearer ordinary-access");
        assert_eq!(request["accept"], "application/json");
    }
    assert_eq!(
        requests[3]["body"],
        "grant_type=refresh_token&refresh_token=ordinary-refresh"
    );
    assert_eq!(requests[3]["authorization"], grant["authorization"]);

    for mapper_error in [false, true] {
        server
            .state
            .profile_status
            .store(if mapper_error { 200 } else { 503 }, Ordering::SeqCst);
        server
            .state
            .mapper_error
            .store(mapper_error, Ordering::SeqCst);
        let error = auth
            .call_endpoint(HttpMethod::Get, "/account-info", info_input())
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(error.status, 401);
        assert_eq!(
            serde_json::from_slice::<Value>(&error.body.bytes().unwrap()).unwrap(),
            json!({"code":"FAILED_TO_GET_USER_INFO","message":"Failed to get user info"})
        );
    }
    let mut provider = server.provider();
    provider.get_user_info = Some(Arc::new(CustomError));
    let custom = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database))
        .plugin(OAuthPlugin::new().add_provider("paypal", provider))
        .build()
        .await
        .unwrap();
    let before = server.state.requests.lock().unwrap().len();
    let error = custom
        .call_endpoint(HttpMethod::Get, "/account-info", info_input())
        .await
        .unwrap_err()
        .to_auth_response();
    assert_eq!(error.status, 418);
    assert_eq!(
        serde_json::from_slice::<Value>(&error.body.bytes().unwrap()).unwrap(),
        json!({"code":"ORDINARY_APPLICATION_ERROR","message":"Ordinary PayPal custom handler failure"})
    );
    assert_eq!(server.state.requests.lock().unwrap().len(), before);
    assert_eq!(
        serde_json::to_value(
            custom
                .context()
                .database
                .get_user_accounts(&user_id)
                .await
                .unwrap()
        )
        .unwrap(),
        json!([updated])
    );
}
