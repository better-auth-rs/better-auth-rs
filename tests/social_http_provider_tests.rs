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
use better_auth::plugins::oauth::{OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{AuthResult, HttpMethod};
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
    events: Arc<Mutex<Vec<String>>>,
    token_forms: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

async fn token(State(state): State<ProviderState>, body: String) -> Json<Value> {
    state.events.lock().unwrap().push("token".into());
    let form = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    state.token_forms.lock().unwrap().push(form);
    Json(
        json!({"access_token":"ordinary-access","refresh_token":"ordinary-refresh","expires_in":3600,"scope":"ordinary-scope","token_type":"Bearer"}),
    )
}

async fn profile(State(state): State<ProviderState>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(headers["authorization"], "Bearer ordinary-access");
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
    async fn start(profile: Value) -> Self {
        let state = ProviderState {
            profile,
            events: Default::default(),
            token_forms: Default::default(),
        };
        let router = Router::new()
            .route("/token", post(token))
            .route("/profile", get(self::profile))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, state, task }
    }
}

struct Mapper(ProviderState, Value);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile, &self.0.profile);
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
    for id in ["gitlab", "spotify", "huggingface", "polar"] {
        let case = &fixture["providers"][id];
        let server = Server::start(case["profile"].clone()).await;
        let mut provider = match id {
            "gitlab" => OAuthProvider::gitlab("social-http-client", "ordinary-client-secret"),
            "spotify" => OAuthProvider::spotify("social-http-client", "ordinary-client-secret"),
            "huggingface" => {
                OAuthProvider::huggingface("social-http-client", "ordinary-client-secret")
            }
            _ => {
                assert_eq!(id, "polar");
                OAuthProvider::polar("social-http-client", "ordinary-client-secret")
            }
        };
        provider.token_url = format!("{}/token", server.url);
        provider.user_info_url = Some(format!("{}/profile", server.url));
        provider.map_profile_to_user = Some(Arc::new(Mapper(
            server.state.clone(),
            case["mapperPatch"].clone(),
        )));
        let auth = auth(id, provider).await;
        let start = auth.call_endpoint(HttpMethod::Post, "/sign-in/social", EndpointInput {
            body: Some(json!({"provider":id,"callbackURL":"http://app.example.test/welcome","disableRedirect":true})),
            ..Default::default()
        }).await.unwrap();
        assert_eq!(start.status, 200);
        let body: Value = serde_json::from_slice(&start.body).unwrap();
        let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["code_challenge_method"], "S256");
        let cookies = start
            .headers
            .get_all("set-cookie")
            .map(|cookie| cookie.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(!cookies.is_empty());
        let callback = auth
            .call_endpoint(
                HttpMethod::Get,
                &format!("/callback/{id}"),
                EndpointInput {
                    headers: Some(HashMap::from([("cookie".into(), cookies)])),
                    query: Some(json!({"code":"ordinary-code","state":query["state"]})),
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
            .get_user_by_email(case["profile"]["email"].as_str().unwrap())
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
        let subject_value = &case["profile"][case["subjectField"].as_str().unwrap()];
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
        let forms = server.state.token_forms.lock().unwrap();
        assert_eq!(forms.len(), 1);
        let form = &forms[0];
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "ordinary-code");
        assert_eq!(form["client_id"], "social-http-client");
        assert_eq!(form["client_secret"], "ordinary-client-secret");
        assert!(!form["code_verifier"].is_empty());
        assert_eq!(
            form["redirect_uri"],
            format!("http://app.example.test/api/auth/callback/{id}")
        );
    }
}
