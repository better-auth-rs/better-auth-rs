use better_auth::{AuthConfig, BetterAuth};
use better_auth::adapters::{MemoryDatabaseAdapter, MemoryCacheAdapter, MemoryMailerAdapter};
use better_auth::plugins::{OAuthPlugin, EmailVerificationPlugin};
use better_auth::types::{AuthRequest, HttpMethod, CreateUser, CreateVerification};
use chrono::{Duration, Utc};
use serde::{Serialize, Deserialize};
use serde_json::json;

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(6)
}

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    email: String,
    #[serde(rename = "email_verified")]
    email_verified: bool,
    name: String,
    iss: String,
    aud: String,
    exp: usize,
    iat: usize,
}

#[tokio::test]
async fn test_oauth_id_token_validation_hs256() {
    let provider = better_auth::plugins::oauth::OAuthProviderConfig {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        auth_url: "https://example.com/auth".to_string(),
        token_url: "https://example.com/token".to_string(),
        user_info_url: "https://example.com/userinfo".to_string(),
        scopes: vec!["email".to_string()],
    };

    let jwt_config = better_auth::plugins::oauth::OAuthJwtConfig {
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("client".to_string()),
        algorithm: Some("HS256".to_string()),
        public_keys: None,
        shared_secret: Some("jwt-secret".to_string()),
    };

    let oauth = OAuthPlugin::new()
        .add_provider("test", provider)
        .add_jwt_config("test", jwt_config);

    let auth = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(oauth)
        .build()
        .await
        .expect("Failed to build auth instance");

    let now = Utc::now().timestamp() as usize;
    let claims = TestClaims {
        sub: "provider-user-1".to_string(),
        email: "oauth@example.com".to_string(),
        email_verified: true,
        name: "OAuth User".to_string(),
        iss: "https://issuer.example".to_string(),
        aud: "client".to_string(),
        exp: now + 3600,
        iat: now,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret("jwt-secret".as_bytes()),
    ).expect("Failed to encode token");

    let body = json!({
        "provider": "test",
        "idToken": token
    });

    let mut req = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    req.body = Some(body.to_string().into_bytes());
    req.headers.insert("content-type".to_string(), "application/json".to_string());

    let response = auth.handle_request(req).await.expect("Request failed");
    assert_eq!(response.status, 200);

    let response_json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response_json["user"]["email"], "oauth@example.com");
}

#[tokio::test]
async fn test_oauth_id_token_invalid_signature() {
    let provider = better_auth::plugins::oauth::OAuthProviderConfig {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        auth_url: "https://example.com/auth".to_string(),
        token_url: "https://example.com/token".to_string(),
        user_info_url: "https://example.com/userinfo".to_string(),
        scopes: vec!["email".to_string()],
    };

    let jwt_config = better_auth::plugins::oauth::OAuthJwtConfig {
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("client".to_string()),
        algorithm: Some("HS256".to_string()),
        public_keys: None,
        shared_secret: Some("jwt-secret".to_string()),
    };

    let oauth = OAuthPlugin::new()
        .add_provider("test", provider)
        .add_jwt_config("test", jwt_config);

    let auth = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(oauth)
        .build()
        .await
        .expect("Failed to build auth instance");

    let now = Utc::now().timestamp() as usize;
    let claims = TestClaims {
        sub: "provider-user-2".to_string(),
        email: "oauth2@example.com".to_string(),
        email_verified: true,
        name: "OAuth User".to_string(),
        iss: "https://issuer.example".to_string(),
        aud: "client".to_string(),
        exp: now + 3600,
        iat: now,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret("wrong-secret".as_bytes()),
    ).expect("Failed to encode token");

    let body = json!({
        "provider": "test",
        "idToken": token
    });

    let mut req = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    req.body = Some(body.to_string().into_bytes());
    req.headers.insert("content-type".to_string(), "application/json".to_string());

    let response = auth.handle_request(req).await.expect("Request failed");
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn test_email_verification_expired_token() {
    let plugin = EmailVerificationPlugin::new();

    let database = MemoryDatabaseAdapter::new();
    let auth = BetterAuth::new(test_config())
        .database(database)
        .plugin(plugin)
        .build()
        .await
        .expect("Failed to build auth instance");

    let create_user = CreateUser::new()
        .with_email("expired@example.com")
        .with_name("Expired User");

    let user = auth.database().create_user(create_user).await.unwrap();

    let create_verification = CreateVerification {
        identifier: user.email.clone().unwrap(),
        value: "expired-token".to_string(),
        expires_at: Utc::now() - Duration::hours(1),
    };

    auth.database().create_verification(create_verification).await.unwrap();

    let mut req = AuthRequest::new(HttpMethod::Get, "/verify-email");
    req.query.insert("token".to_string(), "expired-token".to_string());

    let response = auth.handle_request(req).await.expect("Request failed");
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn test_email_verification_resend_throttle_and_mailer() {
    let mailer = MemoryMailerAdapter::new();
    let cache = MemoryCacheAdapter::new();

    let plugin = EmailVerificationPlugin::new().resend_cooldown_seconds(60);

    let auth = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .cache(cache)
        .mailer(mailer.clone())
        .plugin(plugin)
        .build()
        .await
        .expect("Failed to build auth instance");

    let create_user = CreateUser::new()
        .with_email("verify@example.com")
        .with_name("Verify User");

    let user = auth.database().create_user(create_user).await.unwrap();
    let email = user.email.clone().unwrap();

    let body = json!({ "email": email });
    let mut req1 = AuthRequest::new(HttpMethod::Post, "/send-verification-email");
    req1.body = Some(body.to_string().into_bytes());
    req1.headers.insert("content-type".to_string(), "application/json".to_string());

    let response1 = auth.handle_request(req1).await.expect("Request failed");
    assert_eq!(response1.status, 200);
    assert_eq!(mailer.sent_messages().len(), 1);

    let mut req2 = AuthRequest::new(HttpMethod::Post, "/send-verification-email");
    req2.body = Some(body.to_string().into_bytes());
    req2.headers.insert("content-type".to_string(), "application/json".to_string());

    let response2 = auth.handle_request(req2).await.expect("Request failed");
    assert_eq!(response2.status, 429);
}
