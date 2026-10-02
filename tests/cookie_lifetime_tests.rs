#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Contract fixtures assert captured ordinary cookie values"
)]

use better_auth::plugins::{TestUtilsPlugin, test_utils::TestAuthOptions};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::store::{EphemeralStore, StatelessSchema};
use better_auth_core::{AuthRequest, CookieAttributes, CookieOverride, CreateUser, HttpMethod};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

#[tokio::test]
async fn browser_cookie_lifetime_and_http_rounding_match_pinned_fixture() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/cookie-lifetime-1.7.6.json")).unwrap();
    for (name, fixture) in fixtures.as_object().unwrap() {
        let input = &fixture["input"];
        let mut config =
            AuthConfig::new("ordinary-cookie-lifetime-fixture-secret-more-than-32-characters")
                .base_url("https://cookie-lifetime.test");
        config.session.expires_in = input["sessionExpiresIn"]
            .as_f64()
            .map(|seconds| Duration::milliseconds((seconds * 1000.0) as i64));
        config.advanced.use_secure_cookies = Some(false);
        config.advanced.default_cookie_attributes.max_age = input["defaultMaxAge"].as_f64();
        let _ = config.advanced.cookies.get_or_insert_default().insert(
            "session_token".into(),
            CookieOverride {
                name: None,
                attributes: CookieAttributes {
                    max_age: input["cookieMaxAge"].as_f64(),
                    ..Default::default()
                },
            },
        );
        let resolved = config.auth_cookie(
            "session_token",
            CookieAttributes {
                max_age: Some(config.session.expires_in().as_seconds_f64()),
                ..Default::default()
            },
        );
        assert_eq!(
            resolved.attributes.max_age,
            fixture["resolvedMaxAge"].as_f64(),
            "{name}"
        );
        let auth = BetterAuth::<StatelessSchema>::new(config.clone())
            .store(EphemeralStore::new(Arc::new(config)))
            .plugin(TestUtilsPlugin::default())
            .build()
            .await
            .unwrap();
        let helper = auth.test().unwrap();
        let user = helper
            .save_user(
                helper
                    .create_user(CreateUser::new().with_email("ordinary@cookie-lifetime.test"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let before = Utc::now().timestamp() as f64;
        let cookies = helper
            .get_cookies(
                TestAuthOptions {
                    user_id: user.id.typed().unwrap().clone(),
                    session: Default::default(),
                },
                None,
            )
            .await
            .unwrap();
        let after = Utc::now().timestamp() as f64;
        let mut browser = serde_json::to_value(&cookies[0]).unwrap();
        let _ = browser.as_object_mut().unwrap().remove("value");
        if let Some(age) = fixture["browser"]["expires"].as_f64() {
            let expires = browser["expires"].as_f64().unwrap();
            let base = expires.floor() - age.floor();
            assert!(
                before <= base && base <= after,
                "{name}: expiry uses the current whole-second clock"
            );
            browser["expires"] = match browser["expires"].as_i64() {
                Some(expires) => json!(expires - base as i64),
                None => json!(expires - base),
            };
        }
        assert_eq!(browser, fixture["browser"], "{name}");
        let headers = better_auth_core::utils::cookie_utils::create_chunked_cookies(
            &AuthRequest::new(HttpMethod::Get, "/"),
            &resolved,
            "ordinary",
        )
        .unwrap();
        let max_age = headers[0]
            .split("; ")
            .find_map(|part| part.strip_prefix("Max-Age="));
        assert_eq!(max_age, fixture["httpMaxAge"].as_str(), "{name}");
    }
}
