#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests fail fast on fixture setup and inspect exact OAuth response fields"
)]

use async_trait::async_trait;
use better_auth::plugins::{ApiKeyPlugin, OAuthPlugin, OAuthProxyPlugin, oauth::OAuthProvider};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSession, BeforeRequestAction, CreateUser, HttpMethod,
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use serde_json::{Value, json};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct LaterPolicy;

#[async_trait]
impl AuthPlugin<TestSchema> for LaterPolicy {
    fn name(&self) -> &'static str {
        "later-policy"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if req.headers.contains_key("x-deny-oauth") {
            let body: Value = req.body_as_json()?;
            assert!(
                body["callbackURL"]
                    .as_str()
                    .expect("callback URL")
                    .contains("/oauth-proxy?")
            );
            return Err(AuthError::forbidden("OAuth disabled by application policy"));
        }
        Ok(None)
    }
}

async fn auth() -> BetterAuth<TestSchema> {
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://preview.example")
        .disable_origin_check(true);
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("connect SQLite");
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .expect("run migrations");
    AuthBuilder::<TestSchema>::new(config.clone())
        .store(SeaOrmStore::<TestSchema>::new(config, database))
        .plugin(
            OAuthProxyPlugin::new()
                .current_url("http://preview.example".into())
                .production_url("http://production.example".into()),
        )
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build(),
        )
        .plugin(LaterPolicy)
        .plugin(
            OAuthPlugin::new().add_provider("google", OAuthProvider::google("client", "secret")),
        )
        .build()
        .await
        .expect("build authentication")
}

fn request(path: &str, body: Value) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    request.body = Some(serde_json::to_vec(&body).expect("serialize request"));
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    request
}

#[tokio::test]
async fn proxy_before_api_key_preserves_real_session_emulation() {
    let auth = auth().await;
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("owner@example.com"))
        .await
        .expect("create user");
    let session = auth
        .session_manager()
        .create_session(&user, None, None)
        .await
        .expect("create real session");
    let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
        session.token(),
        auth.config(),
    );
    let mut create = request("/api-key/create", json!({"name":"OAuth linking"}));
    let _ = create.headers.insert(
        "cookie".into(),
        cookie.split(';').next().expect("session cookie").into(),
    );
    let created = auth
        .handle_request(create)
        .await
        .expect("create API key request");
    assert_eq!(created.status, 200);
    let created: Value = serde_json::from_slice(&created.body).expect("API key body");
    let mut link = request(
        "/link-social",
        json!({"provider":"google","callbackURL":"http://preview.example/done"}),
    );
    let _ = link.headers.insert(
        "x-api-key".into(),
        created["key"].as_str().expect("API key").into(),
    );
    let response = auth
        .handle_request(link)
        .await
        .expect("link-social request");
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).expect("OAuth response");
    let url =
        reqwest::Url::parse(body["url"].as_str().expect("authorization URL")).expect("parse URL");
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        params.get("redirect_uri").map(|value| value.as_ref()),
        Some("http://production.example/api/auth/callback/google")
    );
    assert!(params.get("state").expect("wrapped state").len() > 64);
}

#[tokio::test]
async fn proxy_keeps_later_application_policy_and_rewritten_body() {
    let auth = auth().await;
    let mut req = request(
        "/sign-in/social",
        json!({"provider":"google","callbackURL":"http://preview.example/done"}),
    );
    let _ = req.headers.insert("x-deny-oauth".into(), "true".into());
    let response = auth.handle_request(req).await.expect("sign-in request");
    assert_eq!(response.status, 403);
    let body: Value = serde_json::from_slice(&response.body).expect("error body");
    assert_eq!(body["message"], "OAuth disabled by application policy");
    assert!(!response.headers.contains_key("set-cookie"));
}
