#![cfg(feature = "axum")]
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests fail fast on fixture setup and inspect exact OAuth response fields"
)]

use axum::{
    Router,
    body::Body,
    http::{Request, uri::Scheme},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::plugins::{OAuthPlugin, OAuthProxyPlugin, oauth::OAuthProvider};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthRequest, HttpMethod};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn auth() -> Arc<BetterAuth<TestSchema>> {
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("https://production.example")
        .trusted_origin("http://preview.example")
        .trusted_origin("https://preview.example");
    let database = Database::connect("sqlite::memory:").await.expect("SQLite");
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .expect("migrations");
    Arc::new(
        AuthBuilder::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(config, database))
            .plugin(OAuthProxyPlugin::new().production_url("https://production.example".into()))
            .plugin(
                OAuthPlugin::new()
                    .add_provider("google", OAuthProvider::google("client", "secret")),
            )
            .build()
            .await
            .expect("authentication"),
    )
}

fn assert_proxy(body: &[u8], proxied: bool) {
    let body: Value = serde_json::from_slice(body).expect("authorization body");
    let url = reqwest::Url::parse(body["url"].as_str().expect("authorization URL")).expect("URL");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .expect("provider callback")
            .1,
        "https://production.example/api/auth/callback/google"
    );
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .expect("OAuth state")
        .1;
    assert_eq!(
        state.len() > 100,
        proxied,
        "state must be wrapped only for proxy requests"
    );
}

// Upstream: oauth-proxy/utils.ts reads request.url; server-only calls have no request URL.
#[tokio::test]
async fn direct_requests_preserve_url_across_normalization_without_trusting_headers() {
    let auth = auth().await;
    for (url, host, proxied) in [
        (
            Some("https://production.example/api/auth/sign-in/social?source=transport"),
            "attacker.example",
            false,
        ),
        (
            Some("http://production.example/api/auth/sign-in/social"),
            "production.example",
            true,
        ),
        (None, "production.example", true),
    ] {
        let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-in/social");
        if let Some(url) = url {
            request = request.with_url(reqwest::Url::parse(url).expect("transport URL"));
        }
        request.body = Some(
            serde_json::to_vec(
                &json!({"provider":"google", "callbackURL":"/return", "disableRedirect":true}),
            )
            .expect("body"),
        );
        let _ = request.headers.insert("host".into(), host.into());
        let _ = request
            .headers
            .insert("x-forwarded-proto".into(), "https".into());
        let _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        request
            .set_server_context(
                "oauthProxyRedirectBase",
                "https://attacker.example/api/auth".into(),
            )
            .expect("caller context");
        let response = auth.handle_request(request).await.expect("authorization");
        assert_eq!(response.status, 200);
        assert_proxy(&response.body, proxied);
    }
}

// Rust transport contract: server extensions override the URI scheme; forwarded headers cannot set either.
#[tokio::test]
async fn axum_preserves_uri_authority_and_explicit_transport_scheme() {
    let auth = auth().await;
    let router = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth);
    for (uri, host, scheme, proxied) in [
        ("/api/auth/sign-in/social", "production.example", None, true),
        (
            "/api/auth/sign-in/social",
            "production.example",
            Some(Scheme::HTTPS),
            false,
        ),
        (
            "https://production.example/api/auth/sign-in/social",
            "attacker.example",
            None,
            false,
        ),
        (
            "https://production.example/api/auth/sign-in/social",
            "production.example",
            Some(Scheme::HTTP),
            true,
        ),
        (
            "https://preview.example/api/auth/sign-in/social",
            "production.example",
            None,
            true,
        ),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", host)
            .header("content-type", "application/json")
            .header("forwarded", "proto=https;host=production.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "production.example")
            .body(Body::from(
                json!({"provider":"google", "callbackURL":"/return", "disableRedirect":true})
                    .to_string(),
            ))
            .expect("request");
        if let Some(scheme) = scheme {
            let _ = request.extensions_mut().insert(scheme);
        }
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("authorization");
        assert_eq!(response.status(), 200, "URI {uri}, Host {host}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        assert_proxy(&body, proxied);
    }
}
