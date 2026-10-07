#![cfg(feature = "seaorm2")]
use better_auth::plugins::{AnonymousPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::{AuthConfig, BetterAuth};
use serde_json::{Value, json};

// Configuration changes must hide persisted plugin fields without deleting the user.
#[tokio::test]
async fn disabled_plugins_hide_stored_user_fields() {
    let config = AuthConfig::new("user-fields-test-secret-at-least-32-characters")
        .base_url("http://localhost:3000");
    let database = better_auth::seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    let enabled = BetterAuth::<Schema>::new(config.clone())
        .store(better_auth::seaorm::SeaOrmStore::new(
            config.clone(),
            database.clone(),
        ))
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(AnonymousPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .unwrap();
    let response = enabled
        .handle_request(AuthRequest::new(HttpMethod::Post, "/sign-in/anonymous"))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let original: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert_eq!(original["user"]["isAnonymous"], true);
    let cookie = response
        .headers
        .get_all("set-cookie")
        .next()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let disabled = BetterAuth::<Schema>::new(config.clone())
        .store(better_auth::seaorm::SeaOrmStore::new(config, database))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .unwrap();
    let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
    let _ = request.headers.insert("cookie".into(), cookie.into());
    let response = disabled.handle_request(request).await.unwrap();
    let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert_eq!(body["user"]["id"], original["user"]["id"]);
    for field in [
        "isAnonymous",
        "phoneNumber",
        "phoneNumberVerified",
        "role",
        "banned",
        "username",
        "twoFactorEnabled",
    ] {
        assert_eq!(body["user"].get(field), None, "{field}: {}", json!(body));
    }
}
