#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Integration fixtures fail immediately on invalid setup, changed protocol fields, or premature callback completion."
)]

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::plugins::oauth::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthPlugin, OAuthProfile, OAuthProfileMapper,
    OAuthProvider, OAuthUserInfoRequest,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, AuthResult, HttpMethod, SchemaValue};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{Database, DatabaseConnection, EntityTrait},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities::{account, session, user},
    },
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, oneshot};

const BASE_URL: &str = "http://oauth-profile-presence.example.test";
const MAPPED_EMAIL: &str = "mapped@example.test";
const DISCORD_IMAGE: &str = "https://cdn.discordapp.com/avatars/123456789/portrait.png";

#[derive(Clone)]
struct ProviderState {
    id: &'static str,
    profile: Arc<Mutex<Value>>,
    email: Arc<Mutex<Option<SchemaValue<Option<String>>>>>,
    verified: Arc<Mutex<Option<SchemaValue<Option<bool>>>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
    started: Arc<Notify>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

async fn token(State(state): State<ProviderState>) -> Json<Value> {
    state.events.lock().unwrap().push("token");
    Json(
        json!({"access_token":"ordinary-profile-presence-token", "token_type":"Bearer", "expires_in":3600}),
    )
}

async fn profile(State(state): State<ProviderState>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(
        headers["authorization"],
        "Bearer ordinary-profile-presence-token"
    );
    state.events.lock().unwrap().push("profile");
    Json(state.profile.lock().unwrap().clone())
}

struct Mapper(ProviderState);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        let mut expected = self.0.profile.lock().unwrap().clone();
        if self.0.id == "discord" {
            expected["image_url"] = json!(DISCORD_IMAGE);
        }
        assert_eq!(profile, &expected);
        self.0.events.lock().unwrap().push("map:start");
        let release = self.0.release.lock().unwrap().take();
        self.0.started.notify_one();
        if let Some(release) = release {
            release.await.unwrap();
        }
        self.0.events.lock().unwrap().push("map:end");
        Ok(OAuthProfile {
            email: self.0.email.lock().unwrap().clone(),
            email_verified: self.0.verified.lock().unwrap().clone(),
            ..Default::default()
        })
    }
}

struct GenericProfile(ProviderState);

#[async_trait]
impl GenericOAuthUserInfoHandler for GenericProfile {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        self.0.events.lock().unwrap().push("custom");
        Ok(Some(self.0.profile.lock().unwrap().clone()))
    }
}

struct Fixture {
    auth: BetterAuth<BundledSchema>,
    database: DatabaseConnection,
    state: ProviderState,
    data: Value,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(id: &'static str) -> Self {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/social-http-providers-1.7.6.json"))
                .unwrap();
        let data = if id == "discord" {
            json!({
                "profile":{"id":"123456789", "email":"owner@example.test", "username":"Owner", "avatar":"portrait", "verified":true},
                "defaultUser":{"name":"Owner", "email":"owner@example.test", "image":DISCORD_IMAGE, "emailVerified":true}
            })
        } else if id == "generic" {
            json!({
                "profile":{"id":"ordinary-generic-account","email":"owner@example.test","name":"Owner","emailVerified":true},
                "defaultUser":{"email":"owner@example.test","name":"Owner","emailVerified":true}
            })
        } else {
            fixture["providers"][id].clone()
        };
        let state = ProviderState {
            id,
            profile: Arc::new(Mutex::new(data["profile"].clone())),
            email: Default::default(),
            verified: Default::default(),
            events: Default::default(),
            started: Default::default(),
            release: Default::default(),
        };
        let router = Router::new()
            .route("/token", post(token))
            .route("/profile", get(profile))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client_id = fixture["clientId"].as_str().unwrap();
        let client_secret = fixture["clientSecret"].as_str().unwrap();
        let mut provider = match id {
            "huggingface" => OAuthProvider::huggingface(client_id, client_secret),
            "vercel" => OAuthProvider::vercel(client_id, client_secret),
            "reddit" => OAuthProvider::reddit(client_id, client_secret),
            "generic" => OAuthProvider::custom(
                client_id,
                client_secret,
                "https://provider.example.test/authorize",
                "https://provider.example.test/token",
            ),
            _ => {
                assert_eq!(id, "discord");
                OAuthProvider::discord(client_id, client_secret)
            }
        };
        provider.token_url = format!("{server_url}/token");
        provider.user_info_url = Some(format!("{server_url}/profile"));
        provider.map_profile_to_user = Some(Arc::new(Mapper(state.clone())));
        let plugin = if id == "generic" {
            OAuthPlugin::new().add_generic_provider(
                id,
                GenericOAuthConfig {
                    client_id: client_id.into(),
                    client_secret: Some(client_secret.into()),
                    authorization_url: Some(provider.auth_url),
                    token_url: Some(provider.token_url),
                    get_user_info: Some(Arc::new(GenericProfile(state.clone()))),
                    map_profile_to_user: provider.map_profile_to_user,
                    ..Default::default()
                },
            )
        } else {
            OAuthPlugin::new().add_provider(id, provider)
        };
        let config = AuthConfig::new("oauth-profile-presence-test-secret-more-than-32-characters")
            .base_url(BASE_URL);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        let auth = AuthBuilder::<BundledSchema>::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()))
            .plugin(plugin)
            .build()
            .await
            .unwrap();
        Self {
            auth,
            database,
            state,
            data,
            server,
        }
    }

    async fn login(&self) -> AuthResponse {
        let mut start = request(HttpMethod::Post, "/api/auth/sign-in/social");
        start.headers = HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("origin".into(), BASE_URL.into()),
        ]);
        start.body = Some(serde_json::to_vec(&json!({
            "provider":self.state.id, "callbackURL":format!("{BASE_URL}/welcome"), "disableRedirect":true
        })).unwrap());
        let start = self.auth.handle_request(start).await.unwrap();
        assert_eq!(start.status, 200);
        let body: Value = serde_json::from_slice(&start.body).unwrap();
        let authorization = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        assert!(!query["state"].is_empty());
        let cookie = cookies(&start);
        assert!(!cookie.is_empty());
        let mut callback = request(
            HttpMethod::Get,
            &format!("/api/auth/callback/{}", self.state.id),
        );
        callback.headers = HashMap::from([("cookie".into(), cookie)]);
        callback.query = Some(json!({"code":"ordinary-code", "state":query["state"]}));
        let response = self.auth.handle_request(callback).await.unwrap();
        self.state.events.lock().unwrap().push("returned");
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers.get("location").unwrap(),
            &format!("{BASE_URL}/welcome")
        );
        assert!(!cookies(&response).is_empty());
        response
    }

    async fn rows(&self) -> (Vec<user::Model>, Vec<account::Model>, Vec<session::Model>) {
        (
            user::Entity::find().all(&self.database).await.unwrap(),
            account::Entity::find().all(&self.database).await.unwrap(),
            session::Entity::find().all(&self.database).await.unwrap(),
        )
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
async fn missing_email_waits_for_async_mapper_before_callback_persists_sqlite_user() {
    for id in ["huggingface", "vercel", "discord"] {
        let fixture = Fixture::new(id).await;
        let _ = fixture
            .state
            .profile
            .lock()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("email");
        *fixture.state.email.lock().unwrap() = Some(Some(MAPPED_EMAIL.to_owned()).into());
        let (release, receiver) = oneshot::channel();
        *fixture.state.release.lock().unwrap() = Some(receiver);
        let login = fixture.login();
        tokio::pin!(login);
        tokio::select! {
            _ = &mut login => panic!("{id} callback finished before the mapper was released"),
            () = fixture.state.started.notified() => {}
        }
        assert_eq!(
            *fixture.state.events.lock().unwrap(),
            ["token", "profile", "map:start"]
        );
        assert_eq!(fixture.rows().await, (vec![], vec![], vec![]));
        release.send(()).unwrap();
        let _ = login.await;
        let (users, accounts, sessions) = fixture.rows().await;
        assert_eq!((users.len(), accounts.len(), sessions.len()), (1, 1, 1));
        assert_eq!(users[0].email.as_deref(), Some(MAPPED_EMAIL));
        assert_eq!(accounts[0].provider_id, id);
        assert_eq!(
            *fixture.state.events.lock().unwrap(),
            ["token", "profile", "map:start", "map:end", "returned"]
        );
    }
}

#[tokio::test]
async fn account_info_email_presence_matches_pinned_oracle_without_changing_sqlite_rows() {
    for raw_email in ["omitted", "null", "string"] {
        for mapping in ["unchanged", "null", "undefined", "string"] {
            let fixture = Fixture::new("huggingface").await;
            let login = fixture.login().await;
            let before = fixture.rows().await;
            assert_eq!((before.0.len(), before.1.len(), before.2.len()), (1, 1, 1));
            let account = &before.1[0];
            let mut raw_profile = fixture.data["profile"].clone();
            match raw_email {
                "omitted" => {
                    let _ = raw_profile.as_object_mut().unwrap().remove("email");
                }
                "null" => raw_profile["email"] = Value::Null,
                _ => {}
            }
            *fixture.state.profile.lock().unwrap() = raw_profile.clone();
            *fixture.state.email.lock().unwrap() = match mapping {
                "null" => Some(SchemaValue::Typed(None)),
                "undefined" => Some(SchemaValue::Undefined),
                "string" => Some(Some(MAPPED_EMAIL.to_owned()).into()),
                _ => None,
            };
            fixture.state.events.lock().unwrap().clear();
            let mut input = request(HttpMethod::Get, "/api/auth/account-info");
            input.headers = HashMap::from([("cookie".into(), cookies(&login))]);
            input.query = Some(json!({"accountId":account.id}));
            let response = fixture.auth.handle_request(input).await.unwrap();
            assert_eq!(response.status, 200, "{raw_email}/{mapping}");
            let mut expected_user = fixture.data["defaultUser"].clone();
            let expected_email = match mapping {
                "null" => Some(Value::Null),
                "undefined" => None,
                "string" => Some(json!(MAPPED_EMAIL)),
                _ => raw_profile.get("email").cloned(),
            };
            if let Some(email) = expected_email {
                expected_user["email"] = email;
            } else {
                let _ = expected_user.as_object_mut().unwrap().remove("email");
            }
            let actual: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(
                actual,
                json!({
                    "user":expected_user, "data":raw_profile,
                    "account":{"id":account.id, "providerId":account.provider_id, "accountId":account.account_id}
                }),
                "{raw_email}/{mapping}"
            );
            assert_eq!(
                *fixture.state.events.lock().unwrap(),
                ["profile", "map:start", "map:end"]
            );
            assert_eq!(fixture.rows().await, before, "{raw_email}/{mapping}");
        }
    }
}

#[tokio::test]
async fn account_info_verification_presence_matches_pinned_oracle_without_changing_sqlite_rows() {
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/email-verified-presence-1.7.6.json")).unwrap();
    for id in ["discord", "huggingface", "reddit", "generic"] {
        let fixture = Fixture::new(id).await;
        let login = fixture.login().await;
        let before = fixture.rows().await;
        let account = &before.1[0];
        for case in golden["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["provider"] == id)
        {
            let field = golden["profiles"][id]["field"].as_str().unwrap();
            let mut raw = golden["profiles"][id]["profile"].clone();
            if case["raw"] == "omitted" {
                let _ = raw.as_object_mut().unwrap().remove(field);
            } else {
                raw[field] = serde_json::from_str(case["raw"].as_str().unwrap()).unwrap();
            }
            *fixture.state.profile.lock().unwrap() = raw.clone();
            *fixture.state.verified.lock().unwrap() = match case["mapping"].as_str().unwrap() {
                "unchanged" => None,
                "undefined" => Some(SchemaValue::Undefined),
                value => Some(serde_json::from_str(value).unwrap()),
            };
            fixture.state.events.lock().unwrap().clear();
            let mut input = request(HttpMethod::Get, "/api/auth/account-info");
            input.headers = HashMap::from([("cookie".into(), cookies(&login))]);
            input.query = Some(json!({"accountId":account.id}));
            let response = fixture.auth.handle_request(input).await.unwrap();
            assert_eq!(response.status, 200, "{case}");
            let actual: Value = serde_json::from_slice(&response.body).unwrap();
            let mut expected_user = fixture.data["defaultUser"].clone();
            let _ = expected_user
                .as_object_mut()
                .unwrap()
                .remove("emailVerified");
            expected_user
                .as_object_mut()
                .unwrap()
                .extend(case["expected"]["user"].as_object().unwrap().clone());
            if id == "discord" {
                raw["image_url"] = json!(DISCORD_IMAGE);
            }
            assert_eq!(
                actual,
                json!({
                    "user":expected_user, "data":raw,
                    "account":{"id":account.id,"providerId":account.provider_id,"accountId":account.account_id}
                }),
                "{case}"
            );
            assert_eq!(
                *fixture.state.events.lock().unwrap(),
                [
                    if id == "generic" { "custom" } else { "profile" },
                    "map:start",
                    "map:end"
                ]
            );
            assert_eq!(fixture.rows().await, before, "{case}");
        }
    }
}
