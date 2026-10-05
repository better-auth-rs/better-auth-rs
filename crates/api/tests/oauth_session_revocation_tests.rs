use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use better_auth_api::plugins::oauth::encryption::encrypt_token_set;
use better_auth_api::plugins::oauth::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthAccountSubject, OAuthProvider,
    OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_api::{OAuthPlugin, SessionManagementPlugin};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::session::SessionRead;
use better_auth_core::store::AuthStore;
use better_auth_core::utils::cookie_utils::sign_cookie_value;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResult,
    CookieCacheConfig, CreateAccount, CreateUser, HttpMethod, UpdateAccount,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema as TestSchema;
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

struct Fixture {
    ctx: AuthContext<TestSchema>,
    user_id: String,
    account_id: String,
    token: String,
}

impl Fixture {
    fn cookie(&self) -> String {
        format!(
            "{}={}",
            self.ctx
                .config
                .auth_cookie("session_token", Default::default())
                .name,
            sign_cookie_value(&self.token, &self.ctx.config.secret)
        )
    }
}

async fn fixture(config: Arc<AuthConfig>) -> Fixture {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let store: Arc<dyn AuthStore<TestSchema>> =
        Arc::new(SeaOrmStore::<TestSchema>::new(config.clone(), database));
    let ctx = AuthContext::new(config, store.clone());
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("operator@example.com")
                .with_name("Fixture")
                .with_email_verified(true),
        )
        .await
        .unwrap();
    let account = store
        .create_account(CreateAccount {
            user_id: (user.id().typed().unwrap().to_string()).into(),
            account_id: ("provider-subject".to_string()).into(),
            provider_id: ("provider".to_string()).into(),
            access_token: (Some("provider-access".to_string())).into(),
            refresh_token: (Some("provider-refresh".to_string())).into(),
            access_token_expires_at: (Some(Utc::now() + Duration::hours(1))).into(),
            refresh_token_expires_at: Default::default(),
            id_token: Default::default(),
            scope: (Some("openid,email".to_string())).into(),
            password: Default::default(),
            ..Default::default()
        })
        .await
        .unwrap();
    let session = ctx
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    Fixture {
        ctx,
        user_id: user.id().typed().unwrap().to_string(),
        account_id: account.id.typed().unwrap().to_string(),
        token: session.token().to_string(),
    }
}

#[derive(Default)]
struct ProviderCalls {
    refresh: AtomicUsize,
    user_info: AtomicUsize,
}

#[async_trait]
impl OAuthRefreshTokenHandler for ProviderCalls {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String> {
        assert_eq!(refresh_token, "provider-refresh");
        let _ = self.refresh.fetch_add(1, Ordering::SeqCst);
        Ok(OAuthTokenSet {
            access_token: Some("refreshed-access".to_string()),
            access_token_expires_at: Some(Utc::now() + Duration::hours(1)),
            ..Default::default()
        })
    }
}

#[async_trait]
impl OAuthUserInfoHandler for ProviderCalls {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        assert_eq!(request.access_token.as_deref(), Some("refreshed-access"));
        let _ = self.user_info.fetch_add(1, Ordering::SeqCst);
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id: "provider-subject".to_string(),
                email: Some("operator@example.com".to_string()).into(),
                name: Some("Operator".to_string()).into(),
                image: None,
                email_verified: Some(true).into(),
            },
            data: json!({ "sub": "provider-subject", "email": "operator@example.com" }),
        }))
    }
}

fn request(path: &str, account_id: &str, cookie: &str) -> AuthRequest {
    let method = if matches!(path, "/account-info" | "/get-session") {
        HttpMethod::Get
    } else {
        HttpMethod::Post
    };
    let mut request = AuthRequest::new(method, path);
    let _ = request
        .headers
        .insert("cookie".to_string(), cookie.to_string());
    if path == "/account-info" {
        let _ = request
            .query
            .get_or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .insert(
                "accountId".to_string(),
                serde_json::Value::from(account_id.to_string()),
            );
    } else {
        let _ = request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
        request.body = Some(serde_json::to_vec(&json!({ "accountId": account_id })).unwrap());
    }
    request
}

// Upstream account routes bypass cookie caches before reading or refreshing provider credentials.
#[tokio::test]
async fn revoked_session_cache_cannot_read_or_refresh_provider_credentials() {
    let config = Arc::new(
        AuthConfig::new("oauth-revocation-secret-at-least-32-characters").session_cookie_cache(
            CookieCacheConfig {
                enabled: Some(true),
                ..Default::default()
            },
        ),
    );
    let fixture = fixture(config).await;
    let ctx = &fixture.ctx;
    let manager = ctx.session_manager();
    let cache_request = request("/get-session", &fixture.account_id, &fixture.cookie());
    let _ = manager
        .resolve(&cache_request, SessionRead::Cached)
        .await
        .unwrap();
    let cache_headers = cache_request.take_response_headers().unwrap();
    let cache = cache_headers
        .get_all("Set-Cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cache.contains("better-auth.session_data="));
    let cookie = format!("{}; {cache}", fixture.cookie());

    let calls = Arc::new(ProviderCalls::default());
    let mut provider = OAuthProvider::google("client", "secret");
    provider.refresh_access_token = Some(calls.clone());
    provider.get_user_info = Some(calls.clone());
    let plugin = OAuthPlugin::new().add_provider("provider", provider);
    let paths = ["/get-access-token", "/refresh-token", "/account-info"];
    for path in paths {
        let response = plugin
            .on_request(&request(path, &fixture.account_id, &cookie), ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200, "{path}");
    }
    assert_eq!(calls.refresh.load(Ordering::SeqCst), 1);
    assert_eq!(calls.user_info.load(Ordering::SeqCst), 1);

    manager.delete_session(&fixture.token).await.unwrap();
    let cached = request("/get-session", &fixture.account_id, &cookie);
    assert!(
        ctx.require_session(&cached).await.is_ok(),
        "the cached session must remain valid for this regression"
    );
    for path in paths {
        let error = plugin
            .on_request(&request(path, &fixture.account_id, &cookie), ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(error, AuthError::Unauthenticated),
            "{path}: {error}"
        );
    }
    assert_eq!(calls.refresh.load(Ordering::SeqCst), 1);
    assert_eq!(calls.user_info.load(Ordering::SeqCst), 1);
    assert_eq!(
        ctx.database
            .get_user_accounts(&fixture.user_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[derive(Default)]
struct ProfileOnly {
    subject_calls: AtomicUsize,
}

#[async_trait]
impl GenericOAuthUserInfoHandler for ProfileOnly {
    async fn get_user_info(&self, _tokens: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        Ok(Some(
            json!({ "name": "Updated operator", "email": "operator@example.com", "emailVerified": true }),
        ))
    }
}

#[async_trait]
impl OAuthAccountSubject for ProfileOnly {
    async fn resolve_subject(
        &self,
        _tokens: &OAuthUserInfoRequest,
        _profile: &Value,
    ) -> AuthResult<String> {
        let _ = self.subject_calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal(
            "account-info must keep the existing account subject",
        ))
    }
}

#[tokio::test]
async fn account_info_does_not_resolve_a_new_subject_for_an_existing_account() {
    let fixture = fixture(Arc::new(AuthConfig::new(
        "oauth-profile-secret-at-least-32-characters",
    )))
    .await;
    let profile = Arc::new(ProfileOnly::default());
    let plugin = OAuthPlugin::new().add_generic_provider(
        "provider",
        GenericOAuthConfig {
            client_id: "client".to_string(),
            authorization_url: Some("https://provider.example/authorize".to_string()),
            token_url: Some("https://provider.example/token".to_string()),
            get_user_info: Some(profile.clone()),
            account_subject: Some(profile.clone()),
            ..Default::default()
        },
    );
    let response = plugin
        .on_request(
            &request("/account-info", &fixture.account_id, &fixture.cookie()),
            &fixture.ctx,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    let data: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(data["account"]["id"], fixture.account_id);
    assert_eq!(data["account"]["accountId"], "provider-subject");
    assert_eq!(data["user"]["name"], "Updated operator");
    assert!(data["data"].get("sub").is_none());
    assert!(data["data"].get("id").is_none());
    assert_eq!(profile.subject_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_token_endpoint_preserves_account_route_errors_and_stored_credentials() {
    let fixture = fixture(Arc::new(AuthConfig::new(
        "oauth-refresh-secret-at-least-32-characters",
    )))
    .await;
    let _ = fixture
        .ctx
        .database
        .update_account(
            &fixture.account_id,
            UpdateAccount {
                access_token_expires_at: (Some(Utc::now() - Duration::seconds(1))).into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let plugin = OAuthPlugin::new().add_generic_provider(
        "provider",
        GenericOAuthConfig {
            client_id: "client".to_string(),
            authorization_url: Some("https://provider.example/authorize".to_string()),
            ..Default::default()
        },
    );
    for (path, code, message) in [
        (
            "/get-access-token",
            "FAILED_TO_GET_ACCESS_TOKEN",
            "Failed to get a valid access token",
        ),
        (
            "/refresh-token",
            "FAILED_TO_REFRESH_ACCESS_TOKEN",
            "Failed to refresh access token",
        ),
    ] {
        let response = plugin
            .on_request(
                &request(path, &fixture.account_id, &fixture.cookie()),
                &fixture.ctx,
            )
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(response.status, 400, "{path}");
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!({ "code": code, "message": message })
        );
    }
    let accounts = fixture
        .ctx
        .database
        .get_user_accounts(&fixture.user_id)
        .await
        .unwrap();
    assert_eq!(
        accounts[0]
            .access_token
            .typed()
            .unwrap()
            .as_deref()
            .as_deref(),
        Some("provider-access")
    );
    assert_eq!(
        accounts[0]
            .refresh_token
            .typed()
            .unwrap()
            .as_deref()
            .as_deref(),
        Some("provider-refresh")
    );
}

#[tokio::test]
async fn sign_out_preserves_stored_id_token_and_revokes_session() {
    for non_jwt_token in [false, true] {
        let mut config = AuthConfig::new("oauth-logout-secret-at-least-32-characters");
        config.account.encrypt_oauth_tokens = Some(true);
        let mut fixture = fixture(Arc::new(config)).await;
        let raw_id_token = "header.provider-identity.signature";
        let encrypted = encrypt_token_set(
            &fixture.ctx,
            Some("provider-access".to_string()),
            Some("provider-refresh".to_string()),
            Some(raw_id_token.to_string()),
        )
        .unwrap();
        assert_eq!(encrypted.id_token.as_deref(), Some(raw_id_token));
        let stored_id_token = if non_jwt_token {
            "invalid-ciphertext".to_string()
        } else {
            encrypted.id_token.unwrap()
        };
        let _ = fixture
            .ctx
            .database
            .update_account(
                &fixture.account_id,
                UpdateAccount {
                    access_token: (encrypted.access_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    refresh_token: (encrypted.refresh_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    id_token: (Some(stored_id_token.clone())).into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let plugin = OAuthPlugin::new().add_generic_provider(
            "provider",
            GenericOAuthConfig {
                client_id: "client".to_string(),
                authorization_url: Some("https://provider.example/authorize".to_string()),
                token_url: Some("https://provider.example/token".to_string()),
                end_session_endpoint: Some("https://provider.example/logout".to_string()),
                ..Default::default()
            },
        );
        let mut init =
            AuthInitContext::new(fixture.ctx.config.clone(), fixture.ctx.database.clone());
        plugin.on_init(&mut init).await.unwrap();
        fixture.ctx.extensions = init.into_parts().extensions;
        let mut request = request("/sign-out", &fixture.account_id, &fixture.cookie());
        request.body = Some(b"{}".to_vec());
        let mut response = SessionManagementPlugin::new()
            .on_request(&request, &fixture.ctx)
            .await
            .unwrap()
            .unwrap();
        fixture
            .ctx
            .session_manager()
            .finish_response(&request, &mut response)
            .unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        assert_eq!(url.host_str(), Some("provider.example"));
        assert!(
            url.query_pairs()
                .any(|(name, value)| name == "id_token_hint" && value == stored_id_token)
        );
        assert_eq!(
            response.headers.get("Location").map(String::as_str),
            Some(url.as_str())
        );
        assert!(
            fixture
                .ctx
                .database
                .get_session(&fixture.token)
                .await
                .unwrap()
                .is_none()
        );
        let accounts = fixture
            .ctx
            .database
            .get_user_accounts(&fixture.user_id)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            accounts[0].id_token.typed().unwrap().as_deref(),
            Some(stored_id_token.as_str())
        );
    }
}
