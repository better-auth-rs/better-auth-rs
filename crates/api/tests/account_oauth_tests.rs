//! Integration tests for Account and OAuth advanced options:
//!
//! 1. Token encryption: encrypted tokens stored in DB, decrypted via get-access-token
//! 2. allow_unlinking_all: unlink-account respects the config flag
//! 3. account_linking.enabled=false: callback rejects linking for existing emails
//! 4. handle_link_social: confirm token handling in the link flow
#![allow(
    unused_results,
    reason = "oauth integration tests intentionally discard setup return values from inserts and config mutation helpers"
)]

use std::sync::{Arc, Once};

use async_trait::async_trait;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::store::AuthStore;
use better_auth_core::{
    AccountConfig, AccountLinkingConfig, AuthConfig, AuthContext, AuthPlugin, AuthRequest,
    CreateAccount, CreateUser, CreateVerification, HttpMethod, SessionManager,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema as TestSchema;
use better_auth_seaorm::{Database, SeaOrmStore};

use better_auth_api::AccountManagementPlugin;
use better_auth_api::OAuthPlugin;
use better_auth_api::plugins::oauth::encryption::{decrypt_token, encrypt_token, maybe_encrypt};
use better_auth_api::plugins::oauth::{
    OAuthConfig, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;

use serde_json::json;

const TEST_SECRET: &str = "test-secret-key-that-is-at-least-32-characters-long";
static LOCAL_PROXY_BYPASS: Once = Once::new();

fn ensure_local_proxy_bypass() {
    LOCAL_PROXY_BYPASS.call_once(|| {
        // SAFETY: Tests in this binary all need the same localhost bypass values.
        // We set them once before issuing any local OAuth mock-server requests.
        unsafe { std::env::set_var("NO_PROXY", "localhost,127.0.0.1") };
        // SAFETY: Tests in this binary all need the same localhost bypass values.
        // We set them once before issuing any local OAuth mock-server requests.
        unsafe { std::env::set_var("no_proxy", "localhost,127.0.0.1") };
    });
}

fn test_config() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
}

fn test_config_with_encryption() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            ..Default::default()
        })
}

fn test_config_with_encryption_skip_state_cookie_check() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            skip_state_cookie_check: true,
            ..Default::default()
        })
}

fn test_config_linking_disabled() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            account_linking: AccountLinkingConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        })
}

fn test_config_allow_unlinking_all() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            account_linking: AccountLinkingConfig {
                allow_unlinking_all: true,
                ..Default::default()
            },
            ..Default::default()
        })
}

fn test_config_with_account_cookie() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        })
}

/// Helper: create a user + OAuth account + session, returning (user_id, session_token).
async fn setup_user_with_account(
    db: &Arc<dyn AuthStore<TestSchema>>,
    config: &Arc<AuthConfig>,
    email: &str,
    provider: &str,
    access_token: Option<String>,
    refresh_token: Option<String>,
) -> (String, String) {
    let user = db
        .create_user(
            CreateUser::new()
                .with_email(email)
                .with_name("Test User")
                .with_email_verified(true),
        )
        .await
        .unwrap();

    let user_id = user.id().to_string();

    db.create_account(CreateAccount {
        user_id: user_id.clone(),
        account_id: format!("{}-account-id", provider),
        provider_id: provider.to_string(),
        access_token,
        refresh_token,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: Some("email profile".to_string()),
        password: None,
    })
    .await
    .unwrap();

    // Create a session for the user
    let session_manager = SessionManager::new(config.clone(), db.clone());
    let session = session_manager
        .create_session(&user, None, None)
        .await
        .unwrap();
    let token = session.token().to_string();

    (user_id, token)
}

async fn create_test_database() -> Arc<dyn AuthStore<TestSchema>> {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    Arc::new(SeaOrmStore::<TestSchema>::new(
        Arc::new(test_config()),
        database,
    ))
}

#[derive(Debug, Clone)]
struct RotatingRefreshHandler {
    sequence: Arc<std::sync::Mutex<Vec<(String, OAuthTokenSet)>>>,
}

#[async_trait]
impl OAuthRefreshTokenHandler for RotatingRefreshHandler {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String> {
        let mut sequence = self.sequence.lock().unwrap();
        let (expected, response) = sequence.remove(0);
        if refresh_token != expected {
            return Err(format!(
                "unexpected refresh token: expected {expected}, got {refresh_token}"
            ));
        }
        Ok(response)
    }
}

#[derive(Serialize)]
struct TestAccountCookieClaims<'a> {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "providerId")]
    provider_id: &'a str,
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "accessToken", skip_serializing_if = "Option::is_none")]
    access_token: Option<&'a str>,
    #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    #[serde(rename = "idToken", skip_serializing_if = "Option::is_none")]
    id_token: Option<&'a str>,
    #[serde(
        rename = "accessTokenExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    access_token_expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(
        rename = "refreshTokenExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    refresh_token_expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    exp: usize,
    iat: usize,
}

fn encode_account_cookie(
    account: &impl AuthAccount,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    access_token_expires_at: Option<chrono::DateTime<Utc>>,
) -> String {
    let now = Utc::now();
    encode(
        &Header::default(),
        &TestAccountCookieClaims {
            id: Some(account.id().to_string()),
            provider_id: account.provider_id(),
            account_id: account.account_id(),
            access_token,
            refresh_token,
            id_token: account.id_token(),
            access_token_expires_at,
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope(),
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
        },
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .unwrap()
}

fn set_session_and_account_cookies(
    req: &mut AuthRequest,
    session_token: &str,
    account_cookie: &str,
) {
    req.headers.insert(
        "cookie".to_string(),
        format!(
            "better-auth.session_token={}; better-auth.account_data={}",
            session_token, account_cookie
        ),
    );
}

/// Start a mock HTTP server that responds to OAuth token + userinfo requests.
/// `email` is the email returned from the userinfo endpoint.
async fn start_mock_oauth_server(email: &str) -> String {
    ensure_local_proxy_bypass();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock_url = format!("http://localhost:{}", addr.port());
    let email = email.to_string();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let email = email.clone();
                tokio::spawn(async move {
                    handle_mock_connection(stream, &email).await;
                });
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    mock_url
}

async fn handle_mock_connection(stream: tokio::net::TcpStream, email: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = stream;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);

    let (status, body) = if request.contains("POST") && request.contains("/token") {
        let body = json!({
            "access_token": "mock-access-token",
            "refresh_token": "mock-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "email"
        });
        ("200 OK", body.to_string())
    } else if request.contains("GET") && request.contains("/userinfo") {
        let body = json!({
            "sub": "mock-user-id-123",
            "email": email,
            "name": "Mock OAuth User",
            "email_verified": true
        });
        ("200 OK", body.to_string())
    } else {
        ("404 Not Found", json!({"error": "not found"}).to_string())
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn make_test_provider(mock_url: &str) -> OAuthProvider {
    OAuthProvider {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        auth_url: format!("{}/auth", mock_url),
        token_url: format!("{}/token", mock_url),
        user_info_url: Some(format!("{}/userinfo", mock_url)),
        scopes: vec!["email".to_string()],
        authorization_params: Vec::new(),
        map_user_info: Some(|v| {
            Ok(OAuthUserInfo {
                id: v["sub"].as_str().unwrap_or("mock-user-id-123").to_string(),
                email: v["email"]
                    .as_str()
                    .unwrap_or("unknown@example.com")
                    .to_string(),
                name: v["name"].as_str().map(String::from),
                image: None,
                email_verified: true,
            })
        }),
        get_user_info: None,
        refresh_access_token: None,
        verify_id_token: None,
        disable_implicit_sign_up: false,
        disable_sign_up: false,
        override_user_info_on_sign_in: false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Token encryption — encrypted tokens in DB, decrypted via get-access-token
// ─────────────────────────────────────────────────────────────────────────────

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_encrypt_oauth_tokens_stored_encrypted_in_db() {
    let config = Arc::new(test_config_with_encryption());
    let db = create_test_database().await;

    let plaintext_access = "ya29.real-access-token-value";
    let plaintext_refresh = "1//real-refresh-token-value";

    // Encrypt before storing (simulating what handle_callback does)
    let encrypted_access =
        maybe_encrypt(Some(plaintext_access.to_string()), true, TEST_SECRET).unwrap();
    let encrypted_refresh =
        maybe_encrypt(Some(plaintext_refresh.to_string()), true, TEST_SECRET).unwrap();

    // Verify the encrypted values are different from plaintext
    assert_ne!(encrypted_access.as_deref(), Some(plaintext_access));
    assert_ne!(encrypted_refresh.as_deref(), Some(plaintext_refresh));

    // Store encrypted tokens in DB (simulating what the callback handler would do)
    let (user_id, session_token) = setup_user_with_account(
        &db,
        &config,
        "encrypt@example.com",
        "google",
        encrypted_access.clone(),
        encrypted_refresh.clone(),
    )
    .await;

    // Verify tokens in DB are encrypted (not plaintext)
    let accounts = db.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);
    let stored_access = accounts[0].access_token().unwrap();
    let stored_refresh = accounts[0].refresh_token().unwrap();
    assert_ne!(stored_access, plaintext_access);
    assert_ne!(stored_refresh, plaintext_refresh);

    // Verify the stored encrypted values can be decrypted back to original plaintext
    let decrypted_access = decrypt_token(stored_access, TEST_SECRET).unwrap();
    let decrypted_refresh = decrypt_token(stored_refresh, TEST_SECRET).unwrap();
    assert_eq!(decrypted_access, plaintext_access);
    assert_eq!(decrypted_refresh, plaintext_refresh);

    // Now test via the get-access-token handler which should decrypt transparently
    let ctx = AuthContext::new(config.clone(), db.clone());

    let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session_token),
    );

    let mut oauth_config = OAuthConfig::default();
    let provider = make_test_provider("http://localhost:65535");
    oauth_config.providers.insert(
        "google".to_string(),
        OAuthProvider {
            client_id: provider.client_id,
            client_secret: provider.client_secret,
            auth_url: provider.auth_url,
            token_url: provider.token_url,
            user_info_url: provider.user_info_url,
            scopes: provider.scopes,
            authorization_params: provider.authorization_params,
            map_user_info: provider.map_user_info,
            get_user_info: provider.get_user_info,
            refresh_access_token: provider.refresh_access_token,
            verify_id_token: provider.verify_id_token,
            disable_implicit_sign_up: provider.disable_implicit_sign_up,
            disable_sign_up: provider.disable_sign_up,
            override_user_info_on_sign_in: provider.override_user_info_on_sign_in,
        },
    );
    let oauth_plugin = OAuthPlugin::with_config(oauth_config);
    let result = oauth_plugin.on_request(&req, &ctx).await;

    match result {
        Ok(Some(resp)) => {
            assert_eq!(resp.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            // The access token returned should be the DECRYPTED plaintext
            assert_eq!(body["accessToken"], plaintext_access);
        }
        Ok(None) => panic!("Expected response from get-access-token but got None"),
        Err(e) => panic!("get-access-token handler error: {:?}", e),
    }
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let secret = TEST_SECRET;
    let tokens = vec![
        "ya29.a0AfH6SMBx-some-access-token",
        "1//0eXXXXXXXXXXXXX-refresh-token",
        "eyJhbGciOiJSUzI1NiJ9.id-token-body",
    ];

    for plaintext in tokens {
        let encrypted = encrypt_token(plaintext, secret).unwrap();
        assert_ne!(
            encrypted, plaintext,
            "encrypted should differ from plaintext"
        );

        let decrypted = decrypt_token(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext, "roundtrip should yield original");
    }
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_encryption_disabled_stores_plaintext() {
    let config = Arc::new(test_config()); // encryption OFF by default
    let db = create_test_database().await;

    let plaintext_access = "ya29.plaintext-access-token";

    let (user_id, _) = setup_user_with_account(
        &db,
        &config,
        "plain@example.com",
        "github",
        Some(plaintext_access.to_string()),
        None,
    )
    .await;

    // Tokens should be stored as-is when encryption is disabled
    let accounts = db.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts[0].access_token(), Some(plaintext_access));
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_get_access_token_rejects_plaintext_when_encryption_is_enabled() {
    let config = Arc::new(test_config_with_encryption());
    let db = create_test_database().await;

    let (_, session_token) = setup_user_with_account(
        &db,
        &config,
        "plaintext-access@example.com",
        "google",
        Some("plain-access-token".to_string()),
        Some("plain-refresh-token".to_string()),
    )
    .await;

    let ctx = AuthContext::new(config.clone(), db.clone());
    let mut oauth_config = OAuthConfig::default();
    oauth_config.providers.insert(
        "google".to_string(),
        make_test_provider("http://localhost:65535"),
    );
    let oauth_plugin = OAuthPlugin::with_config(oauth_config);

    let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session_token),
    );

    let result = oauth_plugin.on_request(&req, &ctx).await;
    assert!(result.is_err(), "plaintext tokens must not be accepted");
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_refresh_token_rejects_plaintext_when_encryption_is_enabled() {
    let config = Arc::new(test_config_with_encryption());
    let db = create_test_database().await;

    let (_, session_token) = setup_user_with_account(
        &db,
        &config,
        "plaintext-refresh@example.com",
        "google",
        Some("plain-access-token".to_string()),
        Some("plain-refresh-token".to_string()),
    )
    .await;

    let ctx = AuthContext::new(config.clone(), db.clone());
    let mut oauth_config = OAuthConfig::default();
    oauth_config.providers.insert(
        "google".to_string(),
        make_test_provider("http://localhost:65535"),
    );
    let oauth_plugin = OAuthPlugin::with_config(oauth_config);

    let mut req = AuthRequest::new(HttpMethod::Post, "/refresh-token");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session_token),
    );

    let result = oauth_plugin.on_request(&req, &ctx).await;
    assert!(
        result.is_err(),
        "plaintext refresh tokens must not be accepted"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/account.ts :: getAccessToken/refreshToken cookie-backed token refresh behavior; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_refresh_token_persists_rotated_tokens_for_cookie_matched_account() {
    let config = Arc::new(test_config_with_account_cookie());
    let db = create_test_database().await;

    let (user_id, session_token) = setup_user_with_account(
        &db,
        &config,
        "rotate-refresh@example.com",
        "google",
        Some("old-access-token".to_string()),
        Some("old-refresh-token".to_string()),
    )
    .await;
    let account = db.get_user_accounts(&user_id).await.unwrap().remove(0);
    let account_cookie = encode_account_cookie(
        &account,
        Some("old-access-token"),
        Some("old-refresh-token"),
        Some(Utc::now() + Duration::minutes(30)),
    );

    let ctx = AuthContext::new(config.clone(), db.clone());
    let mut oauth_config = OAuthConfig::default();
    let mut provider = make_test_provider("http://localhost:65535");
    provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
        sequence: Arc::new(std::sync::Mutex::new(vec![(
            "old-refresh-token".to_string(),
            OAuthTokenSet {
                access_token: Some("rotated-access-token".to_string()),
                refresh_token: Some("rotated-refresh-token".to_string()),
                access_token_expires_at: Some(Utc::now() + Duration::minutes(30)),
                refresh_token_expires_at: Some(Utc::now() + Duration::hours(24)),
                scopes: vec!["email".to_string()],
                ..Default::default()
            },
        )])),
    }));
    oauth_config
        .providers
        .insert("google".to_string(), provider);
    let oauth_plugin = OAuthPlugin::with_config(oauth_config);

    let mut req = AuthRequest::new(HttpMethod::Post, "/refresh-token");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    set_session_and_account_cookies(&mut req, &session_token, &account_cookie);

    let result = oauth_plugin.on_request(&req, &ctx).await;
    let resp = match result {
        Ok(Some(resp)) => resp,
        other => panic!("refresh-token should succeed, got {other:?}"),
    };

    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["refreshToken"], "rotated-refresh-token");

    let updated_account = db
        .get_user_accounts(&user_id)
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.id() == account.id())
        .unwrap();
    assert_eq!(
        updated_account.refresh_token(),
        Some("rotated-refresh-token"),
        "refresh-token should persist rotated refresh tokens back to the DB"
    );
    assert!(
        resp.headers
            .get_all("Set-Cookie")
            .any(|value| value.starts_with("better-auth.account_data=")),
        "refresh-token should refresh the account_data cookie when it is the source of truth"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/account.ts :: getAccessToken/refreshToken cookie-backed token refresh behavior; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_get_access_token_refresh_persists_rotated_tokens_for_cookie_matched_account() {
    let config = Arc::new(test_config_with_account_cookie());
    let db = create_test_database().await;

    let (user_id, session_token) = setup_user_with_account(
        &db,
        &config,
        "rotate-access@example.com",
        "google",
        Some("expired-access-token".to_string()),
        Some("old-refresh-token".to_string()),
    )
    .await;
    let account = db.get_user_accounts(&user_id).await.unwrap().remove(0);
    let account_cookie = encode_account_cookie(
        &account,
        Some("expired-access-token"),
        Some("old-refresh-token"),
        Some(Utc::now() - Duration::seconds(10)),
    );

    let ctx = AuthContext::new(config.clone(), db.clone());
    let mut oauth_config = OAuthConfig::default();
    let mut provider = make_test_provider("http://localhost:65535");
    provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
        sequence: Arc::new(std::sync::Mutex::new(vec![(
            "old-refresh-token".to_string(),
            OAuthTokenSet {
                access_token: Some("rotated-access-token".to_string()),
                refresh_token: Some("rotated-refresh-token".to_string()),
                access_token_expires_at: Some(Utc::now() + Duration::minutes(30)),
                refresh_token_expires_at: Some(Utc::now() + Duration::hours(24)),
                scopes: vec!["email".to_string()],
                ..Default::default()
            },
        )])),
    }));
    oauth_config
        .providers
        .insert("google".to_string(), provider);
    let oauth_plugin = OAuthPlugin::with_config(oauth_config);

    let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    set_session_and_account_cookies(&mut req, &session_token, &account_cookie);

    let result = oauth_plugin.on_request(&req, &ctx).await;
    let resp = match result {
        Ok(Some(resp)) => resp,
        other => panic!("get-access-token should succeed, got {other:?}"),
    };

    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["accessToken"], "rotated-access-token");

    let updated_account = db
        .get_user_accounts(&user_id)
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.id() == account.id())
        .unwrap();
    assert_eq!(
        updated_account.refresh_token(),
        Some("rotated-refresh-token"),
        "get-access-token refresh path should persist rotated refresh tokens back to the DB"
    );
    assert!(
        resp.headers
            .get_all("Set-Cookie")
            .any(|value| value.starts_with("better-auth.account_data=")),
        "get-access-token refresh path should refresh the account_data cookie when it is the source of truth"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: allow_unlinking_all — unlink handler respects config
// ─────────────────────────────────────────────────────────────────────────────

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_unlink_last_account_blocked_by_default() {
    let config = Arc::new(test_config()); // allow_unlinking_all = false by default
    let db = create_test_database().await;

    let (_, session_token) = setup_user_with_account(
        &db,
        &config,
        "unlink@example.com",
        "google",
        Some("access-token".to_string()),
        None,
    )
    .await;

    let ctx = AuthContext::new(config.clone(), db.clone());
    let plugin = AccountManagementPlugin::new();

    let mut req = AuthRequest::new(HttpMethod::Post, "/unlink-account");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session_token),
    );

    let result = plugin.on_request(&req, &ctx).await;

    // Should fail — cannot unlink the last account when allow_unlinking_all is false
    match result {
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("Cannot unlink") || msg.contains("last account"),
                "Expected 'cannot unlink last account' error, got: {}",
                msg
            );
        }
        Ok(Some(resp)) => {
            // It might return an error response instead of Err
            assert_ne!(
                resp.status, 200,
                "Should not succeed unlinking the last account"
            );
        }
        Ok(None) => panic!("Expected a response"),
    }
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_unlink_last_account_allowed_when_configured() {
    let config = Arc::new(test_config_allow_unlinking_all());
    let db = create_test_database().await;

    let (_, session_token) = setup_user_with_account(
        &db,
        &config,
        "unlink-ok@example.com",
        "google",
        Some("access-token".to_string()),
        None,
    )
    .await;

    let ctx = AuthContext::new(config.clone(), db.clone());
    let plugin = AccountManagementPlugin::new();

    let mut req = AuthRequest::new(HttpMethod::Post, "/unlink-account");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session_token),
    );

    let result = plugin.on_request(&req, &ctx).await;

    // Should succeed — allow_unlinking_all is true
    match result {
        Ok(Some(resp)) => {
            assert_eq!(resp.status, 200, "Unlinking should succeed");
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(body["status"], true);
        }
        Err(e) => panic!(
            "Unlinking should succeed with allow_unlinking_all=true, got error: {:?}",
            e
        ),
        Ok(None) => panic!("Expected a response"),
    }
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_unlink_non_last_account_always_allowed() {
    // Even with allow_unlinking_all=false, unlinking one of multiple accounts should work
    let config = Arc::new(test_config());
    let db = create_test_database().await;

    let user = db
        .create_user(
            CreateUser::new()
                .with_email("multi@example.com")
                .with_name("Multi User")
                .with_email_verified(true),
        )
        .await
        .unwrap();

    let user_id = user.id().to_string();

    // Create two accounts
    db.create_account(CreateAccount {
        user_id: user_id.clone(),
        account_id: "google-id".to_string(),
        provider_id: "google".to_string(),
        access_token: Some("google-token".to_string()),
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
    })
    .await
    .unwrap();

    db.create_account(CreateAccount {
        user_id: user_id.clone(),
        account_id: "github-id".to_string(),
        provider_id: "github".to_string(),
        access_token: Some("github-token".to_string()),
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
    })
    .await
    .unwrap();

    let session_manager = SessionManager::new(config.clone(), db.clone());
    let session = session_manager
        .create_session(&user, None, None)
        .await
        .unwrap();

    let ctx = AuthContext::new(config.clone(), db.clone());
    let plugin = AccountManagementPlugin::new();

    let mut req = AuthRequest::new(HttpMethod::Post, "/unlink-account");
    req.body = Some(json!({"providerId": "google"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session.token()),
    );

    let result = plugin.on_request(&req, &ctx).await;

    match result {
        Ok(Some(resp)) => {
            assert_eq!(resp.status, 200);
        }
        Err(e) => panic!("Unlinking one of two accounts should succeed: {:?}", e),
        Ok(None) => panic!("Expected a response"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: account_linking.enabled=false — callback rejects linking for existing emails
// ─────────────────────────────────────────────────────────────────────────────

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_account_linking_disabled_rejects_new_provider() {
    let mock_url = start_mock_oauth_server("existing@example.com").await;

    let config = Arc::new(test_config_linking_disabled());
    let db = create_test_database().await;

    // Create an existing user with a different provider
    let user = db
        .create_user(
            CreateUser::new()
                .with_email("existing@example.com")
                .with_name("Existing User")
                .with_email_verified(true),
        )
        .await
        .unwrap();

    db.create_account(CreateAccount {
        user_id: user.id().to_string(),
        account_id: "old-github-id".to_string(),
        provider_id: "github".to_string(),
        access_token: Some("old-token".to_string()),
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
    })
    .await
    .unwrap();

    // Create OAuth config with a "test" provider pointing to our mock server
    let mut oauth_config = OAuthConfig::default();
    oauth_config
        .providers
        .insert("test".to_string(), make_test_provider(&mock_url));

    // Set up the OAuth state in the verification table
    let state = "test-state-linking-disabled";
    let payload = json!({
        "callbackURL": format!("{}/callback/test", mock_url),
        "codeVerifier": "test-verifier",
        "expiresAt": (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp_millis(),
    });

    db.create_verification(CreateVerification {
        identifier: format!("oauth:{}", state),
        value: payload.to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    })
    .await
    .unwrap();

    let ctx = AuthContext::new(config.clone(), db.clone());

    // Simulate a callback request
    let mut req = AuthRequest::new(
        HttpMethod::Get,
        &format!("/callback/test?code=test-code&state={}", state),
    );
    req.query
        .insert("code".to_string(), "test-code".to_string());
    req.query.insert("state".to_string(), state.to_string());

    let oauth_plugin = OAuthPlugin::with_config(oauth_config);
    let result = oauth_plugin.on_request(&req, &ctx).await;

    // Should fail because account_linking.enabled is false and a user with
    // "existing@example.com" already exists with a different provider
    match result {
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("Account linking is disabled") || msg.contains("linking is disabled"),
                "Expected account linking disabled error, got: {}",
                msg
            );
        }
        Ok(Some(resp)) => {
            assert_ne!(
                resp.status,
                200,
                "Should not succeed when linking is disabled. Body: {}",
                String::from_utf8_lossy(&resp.body),
            );
        }
        Ok(None) => panic!("Expected a response from callback"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: handle_link_social + callback token encryption for new users
// ─────────────────────────────────────────────────────────────────────────────

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_link_social_returns_redirect_url_with_state() {
    let config = Arc::new(test_config_with_encryption());
    let db = create_test_database().await;

    let (_, session_token) = setup_user_with_account(
        &db,
        &config,
        "link@example.com",
        "existing-provider",
        Some("existing-token".to_string()),
        None,
    )
    .await;

    let mut oauth_config = OAuthConfig::default();
    oauth_config.providers.insert(
        "github".to_string(),
        OAuthProvider {
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: Some("https://api.github.com/user".to_string()),
            scopes: vec!["user:email".to_string()],
            authorization_params: Vec::new(),
            map_user_info: Some(|_| unreachable!()),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        },
    );

    let ctx = AuthContext::new(config.clone(), db.clone());
    let oauth_plugin = OAuthPlugin::with_config(oauth_config);

    let mut req = AuthRequest::new(HttpMethod::Post, "/link-social");
    req.body = Some(json!({"provider": "github"}).to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.session_token={}", session_token),
    );

    let result = oauth_plugin.on_request(&req, &ctx).await;

    match result {
        Ok(Some(resp)) => {
            assert_eq!(resp.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            assert!(
                body["url"].as_str().is_some(),
                "Response should contain URL"
            );
            assert_eq!(body["redirect"], true);
            let url = body["url"].as_str().unwrap();
            assert!(url.contains("state="), "URL should contain state param");
            assert!(
                url.contains("code_challenge="),
                "URL should contain PKCE challenge"
            );
        }
        Err(e) => panic!("link-social should succeed: {:?}", e),
        Ok(None) => panic!("Expected a response"),
    }
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
#[tokio::test]
async fn test_callback_with_encryption_encrypts_tokens_for_new_user() {
    let mock_url = start_mock_oauth_server("newuser@example.com").await;

    let config = Arc::new(test_config_with_encryption_skip_state_cookie_check());
    let db = create_test_database().await;

    let mut oauth_config = OAuthConfig::default();
    oauth_config
        .providers
        .insert("test".to_string(), make_test_provider(&mock_url));

    // Set up the OAuth state for a brand-new user (no link_user_id)
    let state = "encrypt-new-user-state";
    let payload = json!({
        "callbackURL": format!("{}/callback/test", mock_url),
        "codeVerifier": "test-verifier",
        "expiresAt": (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp_millis(),
    });

    db.create_verification(CreateVerification {
        identifier: format!("oauth:{}", state),
        value: payload.to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    })
    .await
    .unwrap();

    let ctx = AuthContext::new(config.clone(), db.clone());

    let mut req = AuthRequest::new(
        HttpMethod::Get,
        &format!("/callback/test?code=test-code&state={}", state),
    );
    req.query
        .insert("code".to_string(), "test-code".to_string());
    req.query.insert("state".to_string(), state.to_string());

    let oauth_plugin = OAuthPlugin::with_config(oauth_config);
    let result = oauth_plugin.on_request(&req, &ctx).await;
    let expected_location = format!("{}/callback/test", mock_url);

    match result {
        Ok(Some(resp)) => {
            assert_eq!(resp.status, 302);
            assert_eq!(
                resp.headers.get("Location").map(String::as_str),
                Some(expected_location.as_str()),
            );

            // Verify the user was created and tokens are stored encrypted
            let user = db
                .get_user_by_email("newuser@example.com")
                .await
                .unwrap()
                .expect("User should have been created");

            let accounts = db.get_user_accounts(&user.id()).await.unwrap();
            assert_eq!(accounts.len(), 1);

            let stored_access = accounts[0].access_token().unwrap();
            // The mock server returns "mock-access-token".
            // With encryption on, the stored value should NOT be the plaintext.
            assert_ne!(
                stored_access, "mock-access-token",
                "Access token should be encrypted in DB"
            );

            // Verify it can be decrypted back to the original mock value
            let decrypted = decrypt_token(stored_access, TEST_SECRET).unwrap();
            assert_eq!(decrypted, "mock-access-token");

            // Also verify refresh token is encrypted
            if let Some(stored_refresh) = accounts[0].refresh_token() {
                assert_ne!(
                    stored_refresh, "mock-refresh-token",
                    "Refresh token should be encrypted in DB"
                );
                let decrypted_refresh = decrypt_token(stored_refresh, TEST_SECRET).unwrap();
                assert_eq!(decrypted_refresh, "mock-refresh-token");
            }
        }
        Err(e) => panic!("Callback should succeed for new user: {:?}", e),
        Ok(None) => panic!("Expected a response"),
    }
}
